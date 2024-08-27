/*
 * PeX
 * Linux kernel permission check checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "indcall.h"

//#include "cvfa.h"
//my aux headers
#include "color.h"
#include "stopwatch.h"
#include "utility.h"
#include <fstream>

#define TOTOAL_NUMBER_OF_STOP_WATCHES 2
#define WID_0 0
#define WID_KINIT 1
#define WID_CC 1
#define WID_PI 1

STOP_WATCH(TOTOAL_NUMBER_OF_STOP_WATCHES);

using namespace llvm;

#include "knobs.h"
#include "capstat.h"

#include "module_duplicator.h"

#include <thread>
#include <mutex>
#include <pthread.h>

char indcall::ID;
Instruction* x_dbg_ins;
std::list<int> x_dbg_idx;

std::mutex x_lock;

#define CHECK_USAGE 0
////////////////////////////////////////////////////////////////////////////////
void indcall::align_globals()
{
    StringSet objs, gobjs;
    int count = 0;

    for (auto &gv : m->globals()) {
      if (!gv.hasName())
        continue;
      auto gn = gv.getName();
      if (gv.getAlignment() > 16)
        continue;
      if (gn.contains("__param"))
        continue;
      if (gn.startswith(".compound"))
        continue;
      if (gn.startswith("llvm.") ||
          gn.startswith("_") ||
          gn.startswith(".str") ||
          gn.contains("kstack_offset") ||
          gn.startswith("kimage") ||
          gn.startswith("pcpu_base_addr") ||
          //gn.startswith("__per_cpu") ||
          //gn.startswith("__kstrtab") ||
          //gn.startswith("_note_55") ||
          //gn.startswith("__addressable") ||
          gn.startswith("TRACE")
          ) {
        continue;
      }

      gv.setAlignment(Align(16));
    }
}


/*
 * deal with struct name alias
 */
void indcall::find_in_mi2m(Type* t, ModuleSet& ms)
{
    ms.clear();
    StructType *st = dyn_cast<StructType>(t);
    if (!st)
    {
        //t->print(errs());
        //errs()<<"\n";
        return;
    }
    assert(st);
    if (!st->hasName())
    {
        if (mi2m.find(t)!=mi2m.end())
            for (auto i: *mi2m[t])
                ms.insert(i);
        return;
    }
    //match using struct name
    std::string name = t->getStructName().str();
    str_truncate_dot_number(name);
    for (auto msi: mi2m)
    {
        StructType* stype = dyn_cast<StructType>(msi.first);
        if (!stype->hasName())
            continue;
        std::string struct_name = stype->getName().str();
        str_truncate_dot_number(struct_name);
        if (struct_name!=name)
            continue;
        for (auto i: (*msi.second))
        {
            ms.insert(i);
        }
    }
}
/*
 * interesting type which contains functions pointers to deal with user request
 */
bool indcall::is_interesting_type(Type* ty)
{
    if (!ty->isStructTy())
        return false;
    if (!dyn_cast<StructType>(ty)->hasName())
        return false;
    StringRef tyn = ty->getStructName();
    for (int i=0;i<BUILTIN_INTERESTING_TYPE_WORD_LIST_SIZE;i++)
    {
        if (tyn.startswith(_builtin_interesting_type_word[i]))
            return true;
    }
    if (discovered_interesting_type.count(ty)!=0)
        return true;
    return false;
}
bool indcall::_is_used_by_static_assign_to_interesting_type(Value* v,
        std::unordered_set<Value*>& duchain)
{
    if (duchain.count(v))
        return false;
    duchain.insert(v);
    if (is_interesting_type(v->getType()))
    {
        duchain.erase(v);
        return true;
    }
    for (auto *u: v->users())
    {
        if (isa<Instruction>(u))
            continue;
        if (_is_used_by_static_assign_to_interesting_type(u, duchain))
        {
            duchain.erase(v);
            return true;
        }
    }
    duchain.erase(v);
    return false;
}

bool indcall::is_used_by_static_assign_to_interesting_type(Value* v)
{
    std::unordered_set<Value*> duchain;
    return _is_used_by_static_assign_to_interesting_type(v, duchain);
}

////////////////////////////////////////////////////////////////////////////////
/*
 * debug function
 */
void indcall::dump_as_good(InstructionList& callstk)
{
    if (!knob_dump_good_path)
        return;
    errs()<<ANSI_COLOR_MAGENTA<<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<"\n"<<ANSI_COLOR_GREEN
        <<"=GOOD PATH="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
}

void indcall::dump_as_bad(InstructionList& callstk)
{
    if (!knob_dump_bad_path)
        return;
    errs()<<ANSI_COLOR_MAGENTA<<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<"\n"<<ANSI_COLOR_RED
        <<"=BAD PATH="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
    dump_a_path(callstk);
}

void indcall::dump_as_ignored(InstructionList& callstk)
{
    if (!knob_dump_ignore_path)
        return;
    errs()<<ANSI_COLOR_MAGENTA<<"Use:";
    callstk.front()->getDebugLoc().print(errs());
    errs()<<ANSI_COLOR_RESET;
    errs()<<"\n"<<ANSI_COLOR_YELLOW
        <<"=IGNORE PATH="
        <<ANSI_COLOR_RESET<<"\n";
    dump_callstack(callstk);
}

void indcall::dump_kinit()
{
    if (!knob_indcall_kinit)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
            <<"=Kernel Init Functions="
            <<ANSI_COLOR_RESET<<"\n";
    for (auto I: kernel_init_functions)
    {
        errs()<<I->getName()<<"\n";
    }
    errs()<<"=o=\n";
}

void indcall::dump_non_kinit()
{
    if (!knob_indcall_nkinit)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
            <<"=NON-Kernel Init Functions="
            <<ANSI_COLOR_RESET<<"\n";
    for (auto I: non_kernel_init_functions)
    {
        errs()<<I->getName()<<"\n";
    }
    errs()<<"=o=\n";
}

void indcall::dump_kmi()
{
    if (!knob_indcall_kmi)
        return;
    errs()<<ANSI_COLOR(BG_BLUE, FG_WHITE)
        <<"=Kernel Module Interfaces="
        <<ANSI_COLOR_RESET<<"\n";
    for (auto msi: mi2m)
    {
        StructType * stype = dyn_cast<StructType>(msi.first);
        if (stype->hasName())
            errs()<<ANSI_COLOR_RED
                <<stype->getName()
                <<ANSI_COLOR_RESET<<"\n";
        else
            errs()<<ANSI_COLOR_RED
                <<"AnnonymouseType"
                <<ANSI_COLOR_RESET<<"\n";
        for (auto m: (*msi.second))
        {
            if (m->hasName())
                errs()<<"    "<<ANSI_COLOR_CYAN
                    <<m->getName()<<ANSI_COLOR_RESET<<"\n";
            else
                errs()<<"    "<<ANSI_COLOR_CYAN
                    <<"Annoymous"<<ANSI_COLOR_RESET<<"\n";
        }
    }
    errs()<<"=o=\n";
}

////////////////////////////////////////////////////////////////////////////////
/*
 * is this function type contains non-trivial(non-primary) type?
 */
bool indcall::is_complex_type(Type* t)
{
    if (!t->isFunctionTy())
        return false;
    if (t->isFunctionVarArg())
        return true;
    FunctionType *ft = dyn_cast<FunctionType>(t);
    //params
    int number_of_complex_type = 0;
    for (int i = 0; i<(int)ft->getNumParams(); i++)
    {
        Type* argt = ft->getParamType(i);
strip_pointer:
        if (argt->isPointerTy())
        {
            argt = argt->getPointerElementType();
            goto strip_pointer;
        }

        if (argt->isSingleValueType())
            continue;
        number_of_complex_type++;
    }
    //return type
    Type* rt = ft->getReturnType();

again://to strip pointer
    if (rt->isPointerTy())
    {
        Type* pet = rt->getPointerElementType();
        if (pet->isPointerTy())
        {
            rt = pet;
            goto again;
        }
        if (!pet->isSingleValueType())
        {
            number_of_complex_type++;
        }
    }

    return (number_of_complex_type!=0);
}

/*
 * def/use global?
 * take care of phi node using `visited'
 */
Value* indcall::get_global_def(Value* val, ValueSet& visited)
{
    if (visited.count(val)!=0)
        return NULL;
    visited.insert(val);
    if (isa<GlobalValue>(val))
        return val;
    if (Instruction* vali = dyn_cast<Instruction>(val))
    {
        for (auto &U : vali->operands())
        {
            Value* v = get_global_def(U, visited);
            if (v)
                return v;
        }
    }/*else if (Value* valv = dyn_cast<Value>(val))
    {
        //llvm_unreachable("how can this be ?");
    }*/
    return NULL;
}

Value* indcall::get_global_def(Value* val)
{
    ValueSet visited;
    return get_global_def(val, visited);
}

bool indcall::is_rw_global(Value* val)
{
    ValueSet visited;
    return get_global_def(val, visited)!=NULL;
}

/*
 * is this functions part of the kernel init sequence?
 * if function f has single user which goes to start_kernel(),
 * then this is a init function
 */
bool indcall::is_kernel_init_functions(Function* f, FunctionSet& visited)
{
    if (kernel_init_functions.count(f)!=0)
        return true;
    if (non_kernel_init_functions.count(f)!=0)
        return false;

    //init functions with initcall prefix belongs to kernel init sequence
    if (function_has_gv_initcall_use(f))
    {
        kernel_init_functions.insert(f);
        return true;
    }

    //not found in cache?
    //all path that can reach to f should start from start_kernel()
    //look backward(find who used f)
    FunctionList flist;
    for (auto *U : f->users())
        if (CallInst* cs = dyn_cast<CallInst>(U))
            flist.push_back(cs->getFunction());

    //no user?
    if (flist.size()==0)
    {
        non_kernel_init_functions.insert(f);
        return false;
    }

    visited.insert(f);
    while (flist.size())
    {
        Function* xf = flist.front();
        flist.pop_front();
        if (visited.count(xf))
            continue;
        visited.insert(xf);
        if (!is_kernel_init_functions(xf, visited))
        {
            non_kernel_init_functions.insert(f);
            return false;
        }
    }
    kernel_init_functions.insert(f);
    return true;
}

bool indcall::is_kernel_init_functions(Function* f)
{
    FunctionSet visited;
    return is_kernel_init_functions(f, visited);
}

void indcall::collect_kernel_init_functions(Module& module)
{
    //kstart is the first function in boot sequence
    Function *kstart = NULL;
    //kernel init functions
    FunctionSet kinit_funcs;
    //Step 1: find kernel entry point
    errs()<<"Finding Kernel Entry Point and all __initcall_\n";
    STOP_WATCH_START(WID_KINIT);
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
            continue;
        StringRef fname = func->getName();
        if (fname.startswith("x86_64_start_kernel"))
        {
            errs()<<ANSI_COLOR_GREEN
                <<"Found "<<func->getName()
                <<ANSI_COLOR_RESET<<"\n";
            kstart = func;
            kinit_funcs.insert(kstart);
            kernel_init_functions.insert(func);
        }else if (fname.startswith("start_kernel"))
        {
            //we should consider start_kernel as kernel init functions no
            //matter what
            kernel_init_functions.insert(func);
            kinit_funcs.insert(func);
            if (kstart==NULL)
                kstart = func;
            //everything calling start_kernel should be considered init
            //for (auto *U: func->users())
            //    if (Instruction *I = dyn_cast<Instruction>(U))
            //        kinit_funcs.insert(I->getFunction());
        }else
        {
            if (function_has_gv_initcall_use(func))
                kernel_init_functions.insert(func);
        }
    }
    //should always find kstart
    if (kstart==NULL)
    {
        errs()<<ANSI_COLOR_RED
            <<"kstart function not found, may affect precission, continue anyway\n"
            <<ANSI_COLOR_RESET;
    }
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);

    errs()<<"Initial Kernel Init Function Count:"<<kernel_init_functions.size()<<"\n";

    //Step 2: over approximate kernel init functions
    errs()<<"Over Approximate Kernel Init Functions\n";
    STOP_WATCH_START(WID_KINIT);
    FunctionSet func_visited;
    FunctionSet func_work_set;
    for (auto f: kernel_init_functions)
        func_work_set.insert(f);

    while (func_work_set.size())
    {
        Function* cfunc = *func_work_set.begin();
        func_work_set.erase(cfunc);

        if (cfunc->isDeclaration() || cfunc->isIntrinsic() || is_syscall(cfunc))
            continue;
        
        kinit_funcs.insert(cfunc);
        func_visited.insert(cfunc);
        kernel_init_functions.insert(cfunc);

        //explore call graph starting from this function
        for(Function::iterator fi = cfunc->begin(), fe = cfunc->end(); fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                CallInst* ci = dyn_cast<CallInst>(ii);
                if ((!ci) || (ci->isInlineAsm()))
                    continue;
                if (Function* nf = get_callee_function_direct(ci))
                {
                    if (nf->isDeclaration() || nf->isIntrinsic() ||
                        func_visited.count(nf) || is_syscall(nf))
                        continue;
                    func_work_set.insert(nf);
                }else
                {
#if 0
                    //indirect call?
                    FunctionSet fs = resolve_indirect_callee(ci);
                    errs()<<"Indirect Call in kernel init seq: @ ";
                    ci->getDebugLoc().print(errs());
                    errs()<<"\n";
                    for (auto callee: fs)
                    {
                        errs()<<"    "<<callee->getName()<<"\n";
                        if (!func_visited.count(callee))
                            func_work_set.insert(callee);
                    }
#endif
                }
            }
        }
    }
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);

    errs()<<"Refine Result\n";
    STOP_WATCH_START(WID_KINIT);
    /*
     * ! BUG: query use of inlined function result in in-accurate result?
     * inlined foo();
     * bar(){zoo()} zoo(){foo};
     *
     * query user{foo()} -> zoo()
     * query BasicBlocks in bar -> got call instruction in bar()?
     */
    //remove all non_kernel_init_functions from kernel_init_functions
    //purge all over approximation
    int last_count = 0;

again:
    for (auto f: kinit_funcs)
    {
        if ((f->getName()=="start_kernel") ||
            (f->getName()=="x86_64_start_kernel") ||
            function_has_gv_initcall_use(f))
            continue;
        for (auto *U: f->users())
        {
            CallInstSet cil;
            get_callsite_inst(U, cil);
            bool should_break = false;
            for (auto cs: cil)
            {
                if (kinit_funcs.count(cs->getFunction())==0)
                {
                    //means that we have a user does not belong to kernel init functions
                    //we need to remove it
                    non_kernel_init_functions.insert(f);
                    should_break = true;
                    break;
                }
            }
            if (should_break)
                break;
        }
    }
    for (auto f: non_kernel_init_functions)
    {
        kernel_init_functions.erase(f);
        kinit_funcs.erase(f);
    }

    if (last_count!=(int)non_kernel_init_functions.size())
    {
        last_count = non_kernel_init_functions.size();
        static int refine_pass = 0;
        errs()<<"refine pass "<<refine_pass<<" "<<kernel_init_functions.size()<<" left\n";
        refine_pass++;
        goto again;
    }

    errs()<<" Refine result : count="<<kernel_init_functions.size()<<"\n";
    STOP_WATCH_STOP(WID_KINIT);
    STOP_WATCH_REPORT(WID_KINIT);

    dump_kinit();
}

////////////////////////////////////////////////////////////////////////////////
/*
 * resolve indirect callee
 * method 1 suffers from accuracy issue
 * method 2 is too slow
 * method 3 use the fact that most indirect call use function pointer loaded
 *          from struct(mi2m, kernel interface)
 */
FunctionSet indcall::resolve_indirect_callee_ldcst_kmi(CallInst* ci, int&err,
        int& kmi_cnt, int& dkmi_cnt)
{
    FunctionSet fs;
    //non-gep case. loading from bitcasted struct address
    if (StructType* ldbcstty = identify_ld_bcst_struct(ci->getCalledOperand()))
    {
#if 0
        errs()<<"Found ld+bitcast sty to ptrty:";
        if (ldbcstty->isLiteral())
            errs()<<"Literal, ";
        else
            errs()<<ldbcstty->getName()<<", ";
#endif
        //dump_kmi_info(ci);
        Indices indices;
        indices.push_back(0);
        err = 2;//got type
        //match - kmi
        ModuleSet ms;
        find_in_mi2m(ldbcstty, ms);
        if (ms.size())
        {
            err = 1;//found module object
            for (auto m: ms)
                if (Value* v = get_value_from_composit(m, indices))
                {
                    Function *f = dyn_cast<Function>(v);
                    assert(f);
                    fs.insert(f);
                }
        }
        if (fs.size()!=0)
        {
            kmi_cnt++;
            goto end;
        }
        //match - dkmi
        if (dmi_type_exists(ldbcstty, dmi))
            err = 1;

        indices.clear();
        indices.push_back(0);
        indices.push_back(0);
        if (FunctionSet* _fs = dmi_exists(ldbcstty, indices, dmi))
        {
            for (auto *f:*_fs)
                fs.insert(f);
            dkmi_cnt++;
            goto end;
        }
#if 0
        errs()<<"Try rkmi\n";
#endif
    }
end:
    if (fs.size())
        err = 0;
    return fs;
}

//method 3, improved accuracy
FunctionSet indcall::resolve_indirect_callee_using_kmi(CallInst* ci, int& err)
{
    FunctionSet fs;
    Value* cv = ci->getCalledOperand();

    err = 6;
    //GEP case.
    //need to find till gep is exhausted and mi2m doesn't have a match
    InstructionSet geps = get_load_from_gep(cv, dummyCE_map);
    for(auto _gep: geps)
    {
        GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(_gep);
        Type* cvt = dyn_cast<PointerType>(gep->getPointerOperandType())
            ->getElementType();
        if (!cvt->isAggregateType())
            continue;

        Indices indices;
        x_dbg_ins = gep;
        get_gep_indicies(gep, indices);
        x_dbg_idx = indices;
        assert(indices.size()!=0);
        //should remove first element because it is an array index
        //the actual match
        indices.pop_front();
        while(1)
        {
            if (err>2)
                err = 2;//found the type, going to match module
            ModuleSet ms;
            find_in_mi2m(cvt, ms);
            if (ms.size())
            {
                if (err>1)
                    err = 1;//found matching module
                for (auto m: ms)
                {
                    Value* v = get_value_from_composit(m, indices);
                    if (v==NULL)
                    {
                        /*
                         * NOTE: some of the method may not be implemented
                         *       it is ok to ignore them
                         * for example: .release method in
                         *      struct tcp_congestion_ops
                         */
#if 0
                        errs()<<m->getName();
                        errs()<<" - can not get value from composit [ ";
                        for (auto i: indices)
                            errs()<<","<<i;
                        errs()<<"], this method may not implemented yet.\n";
#endif
                        continue;
                    }
                    Function *f = dyn_cast<Function>(v);
                    assert(f);
                    fs.insert(f);
                }
                break;
            }
            //not found in mi2m
            if (indices.size()<=1)
            {
                //no match! we are also done here, mark it as resolved anyway
                //this object may be dynamically allocated,
                //try dkmi if possible
#if 0
                errs()<<" MIDC err, try DKMI\n";
                cvt = get_load_from_type(cv, dummyCE);
                errs()<<"!!!  : ";
                cvt->print(errs());
                errs()<<"\n";
                
                errs()<<"idcs:";
                for (auto i: x_dbg_idx)
                    errs()<<","<<i;
                errs()<<"\n";
                //gep->print(errs());
                errs()<<"\n";
#endif
                break;
            }
            //no match, we can try inner element
            //deal with array of struct here
            Type* ncvt;
            if (ArrayType *aty = dyn_cast<ArrayType>(cvt))
            {
                ncvt = aty->getElementType();
                //need to remove another one index
                indices.pop_front();
            }else
            {
                int idc = indices.front();
                indices.pop_front();
                if (!cvt->isStructTy())
                {
                    cvt->print(errs());
                    llvm_unreachable("!!!1");
                }
                ncvt = cvt->getStructElementType(idc);
                //FIXME! is this correct?
                if (PointerType* pty = dyn_cast<PointerType>(ncvt))
                {
                    ncvt = pty->getElementType();
                    llvm_unreachable("can't be a pointer!");
                }

                //cvt should be aggregated type!
                if (!ncvt->isAggregateType())
                {
                    /* bad cast!!!
                     * struct sk_buff { cb[48] }
                     * XFRM_TRANS_SKB_CB(__skb) ((struct xfrm_trans_cb *)&((__skb)->cb[0]))
                     */
                    //errs()<<"Can not resolve\n";
                    //x_dbg_ins->getDebugLoc().print(errs());
                    //errs()<<"\n";
                    errs()<<ANSI_COLOR_RED<<"Bad cast from type:"<<ANSI_COLOR_RESET;
                    ncvt->print(errs());
                    errs()<<" we can not resolve this\n";
                    //dump_kmi_info(ci);
                    //llvm_unreachable("NOT POSSIBLE!");
                    err = 5;
                    break;
                }
            }
            cvt = ncvt;
        }
    }
    if (fs.size()==0) {
        if (isa<Argument>(cv)) {
            for (auto u : ci->getFunction()->users()) {
                if (auto ci = dyn_cast<CallInst>(u)) {
                    if (auto cf = dyn_cast<Function>(ci->getArgOperand(cast<Argument>(cv)->getArgNo())))
                        fs.insert(cf);
            }
        }
        }
    } 
    if (fs.size() == 0) {
        if (!isa<Instruction>(cv))
            err = 3;
        else if (load_from_global_fptr(cv))
            err = 4;
            }else
        err = 0;
    return fs;
}

/*
 * this is also kmi, but dynamic one
 */
FunctionSet indcall::resolve_indirect_callee_using_dkmi(CallInst* ci, int& err)
{
    FunctionSet fs;
    Value* cv = ci->getCalledOperand();
    InstructionSet geps = get_load_from_gep(cv, dummyCE_map);

    err = 6;
    for (auto * _gep: geps)
    {
        GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(_gep);
        Type* cvt = dyn_cast<PointerType>(gep->getPointerOperandType())
            ->getElementType();
        if (!cvt->isAggregateType())
            continue;

        Indices indices;
        //need to find till gep is exhausted and mi2m doesn't have a match
        x_dbg_ins = gep;
        get_gep_indicies(gep, indices);
        x_dbg_idx = indices;
        assert(indices.size()!=0);
        //dig till we are at struct type
        while (1)
        {
            if (isa<StructType>(cvt))
                break;
            //must be an array
            if (ArrayType *aty = dyn_cast<ArrayType>(cvt))
            {
                cvt = aty->getElementType();
                //need to remove another one index
                indices.pop_front();
            }else
            {
                //no struct inside it and all of them are array?
#if 0
                errs()<<"All array?:";
                cvt->print(errs());
                errs()<<"\n";
#endif
                break;
            }
        }
        if (!dyn_cast<StructType>(cvt))
            continue;
        if (err>2)
            err = 2;
        if (dmi_type_exists(dyn_cast<StructType>(cvt), dmi) && (err>1))
            err = 1;
        //OK. now we match through struct type and indices
        if (FunctionSet* _fs = dmi_exists(dyn_cast<StructType>(cvt), indices, dmi))
        {
            //TODO:iteratively explore basic element type if current one is not found
            if (_fs->size()==0)
            {
                //dump_kmi_info(ci);
                errs()<<"uk-idcs:";
                if(!dyn_cast<StructType>(cvt)->isLiteral())
                    errs()<<cvt->getStructName();
                errs()<<" [";
                for (auto i: x_dbg_idx)
                    errs()<<","<<i;
                errs()<<"]\n";
            }
            //merge _fs into fs
            for (auto *f:*_fs)
                fs.insert(f);
        }
    }
    if (fs.size())
        err = 0;
    return fs;
}

bool indcall::load_from_global_fptr(Value* cv)
{
    ValueList worklist;
    ValueSet visited;
    worklist.push_back(cv);
    int cnt = 0;
    while(worklist.size() && (cnt++<5))
    {
        Value* v = worklist.front();
        worklist.pop_front();
        if (visited.count(v))
            continue;
        visited.insert(v);

        if (isa<GlobalVariable>(v))
            return true;

        if (isa<Function>(v) || isa<GetElementPtrInst>(v) || isa<CallInst>(v))
            continue;

        if (LoadInst* li = dyn_cast<LoadInst>(v))
        {
            worklist.push_back(li->getPointerOperand());
            continue;
        }
        if (SelectInst* sli = dyn_cast<SelectInst>(v))
        {
            worklist.push_back(sli->getTrueValue());
            worklist.push_back(sli->getFalseValue());
            continue;
        }
        if (PHINode* phi = dyn_cast<PHINode>(v))
        {
            for (unsigned int i=0;i<phi->getNumIncomingValues();i++)
                worklist.push_back(phi->getIncomingValue(i));
            continue;
        }
        //instruction
        if (Instruction* i = dyn_cast<Instruction>(v))
            for (unsigned int j = 0;j<i->getNumOperands();j++)
                worklist.push_back(i->getOperand(j));
        //constant value
        if (ConstantExpr* cxpr = dyn_cast<ConstantExpr>(v)) {
            Instruction *ii = cxpr->getAsInstruction();
            worklist.push_back(ii);
            dummyCE.insert(ii);
        }
    }
    return false;
}

void indcall::dump_kmi_info(CallInst* ci)
{
    Value* cv = ci->getCalledOperand();
    ValueList worklist;
    ValueSet visited;
    worklist.push_back(cv);
    int cnt = 0;
    ci->print(errs());
    errs()<<"\n";
    while(worklist.size() && (cnt++<5))
    {
        Value* v = worklist.front();
        worklist.pop_front();
        if (visited.count(v))
            continue;
        visited.insert(v);
        if (isa<Function>(v))
            errs()<<v->getName();
        else
            v->print(errs());
        errs()<<"\n";
        if (LoadInst* li = dyn_cast<LoadInst>(v))
        {
            worklist.push_back(li->getPointerOperand());
            continue;
        }
        if (SelectInst* sli = dyn_cast<SelectInst>(v))
        {
            worklist.push_back(sli->getTrueValue());
            worklist.push_back(sli->getFalseValue());
            continue;
        }
        if (PHINode* phi = dyn_cast<PHINode>(v))
        {
            for (unsigned int i=0;i<phi->getNumIncomingValues();i++)
                worklist.push_back(phi->getIncomingValue(i));
            continue;
        }
        if (isa<CallInst>(v))
            continue;
        if (Instruction* i = dyn_cast<Instruction>(v))
            for (unsigned int j = 0;j<i->getNumOperands();j++)
                worklist.push_back(i->getOperand(j));
    }
}

/*
 * create mapping for
 *  indirect call site -> callee
 *  callee -> indirect call site
 */
void indcall::populate_indcall_list_through_kmi(Module& module)
{
    //indirect call is load+gep and can be found in mi2m?
    int count = 0;
    int targets = 0;
    int fpar_cnt = 0;
    int gptr_cnt = 0;
    int cast_cnt = 0;
    int container_of_cnt = 0;;
    int undefined_1 = 0;
    int undefined_2 = 0;
    int unknown = 0;
    int kmi_cnt = 0;
    int dkmi_cnt = 0;
    StringRef fname;
#if 0
    errs()<<ANSI_COLOR(BG_WHITE,FG_GREEN)
        <<"indirect callsite, match"
        <<ANSI_COLOR_RESET<<"\n";
#endif
    for (auto* idc: idcs)
    {
#if 0
        errs()<<ANSI_COLOR_YELLOW<<" * ";
        idc->getDebugLoc().print(errs());
        errs()<<ANSI_COLOR_RESET<<"";
#endif
        //is this a trace point?
        //special condition, ignore tracepoint, we are not interested in them.
        if (is_tracepoint_func(idc->getCalledOperand(), dummyCE))
        {
            count++;
            targets++;
            kmi_cnt++;
#if 0
            errs()<<" [tracepoint]\n";
#endif
            continue;
        }
        if (is_container_of(idc->getCalledOperand(), dummyCE_map))
        {
            container_of_cnt++;
#if 0
            errs()<<" [container_of]\n";
#endif
            continue;
        }

        //try kmi
        //err - 0 no error
        //    - 1 undefined fptr in module, mark as resolved
        //    - 2 undefined module, mark as resolved(ok to fail)
        //    - 3 fptr comes from function parameter
        //    - 4 fptr comes from global fptr
        //    - 5 bad cast
        //    - 6 max error code- this is the bound 
        int err = 6;
        //we resolved type and there's a matching object, but no fptr defined
        bool found_module = false;
        //we resolved type but there's no matching object
        bool udf_module = false;
        FunctionSet fs = resolve_indirect_callee_ldcst_kmi(idc, err, kmi_cnt, dkmi_cnt);
        if (err<2)
            found_module = true;
        else if (err==2)
            udf_module = true;

        if (fs.size()!=0)
        {
#if 0
            errs()<<" [LDCST-KMI]\n";
#endif
            goto resolved;
        }
        fs = resolve_indirect_callee_using_kmi(idc, err);
        if (err<2)
            found_module = true;
        else if (err==2)
            udf_module = true;

        // kdfi: capability manual indcall destinations
        fname = idc->getFunction()->getName();
        if (fname == "security_capable")
            if (auto fi = m->getFunction("cap_capable"))
                fs.insert(fi);
        if (fname == "security_settime64")
            if (auto fi = m->getFunction("cap_settime"))
                fs.insert(fi);
        if (fname == "security_ptrace_access_check")
            if (auto fi = m->getFunction("cap_ptrace_access_check"))
                fs.insert(fi);
        if (fname == "security_ptrace_traceme")
            if (auto fi = m->getFunction("cap_ptrace_traceme"))
                fs.insert(fi);
        if (fname == "security_capget")
            if (auto fi = m->getFunction("cap_capget"))
                fs.insert(fi);
        if (fname == "security_capset")
            if (auto fi = m->getFunction("cap_capset"))
                fs.insert(fi);
        if (fname == "security_bprm_set_creds")
            if (auto fi = m->getFunction("cap_bprm_set_creds"))
                fs.insert(fi);
        if (fname == "security_inode_need_killpriv")
            if (auto fi = m->getFunction("cap_inode_need_killpriv"))
                fs.insert(fi);

        if (fname == "security_inode_getattr")
            if (auto fi = m->getFunction("smack_inode_getattr"))
                fs.insert(fi);
        if (fname == "security_inode_setattr")
            if (auto fi = m->getFunction("smack_inode_setattr"))
                fs.insert(fi);
        if (fname == "security_inode_getxattr")
            if (auto fi = m->getFunction("smack_inode_getxattr"))
                fs.insert(fi);
        if (fname == "security_inode_setxattr")
            if (auto fi = m->getFunction("smack_inode_setxattr"))
                fs.insert(fi);
        if (fname == "security_inode_getsecurity")
            if (auto fi = m->getFunction("smack_inode_getsecurity"))
                fs.insert(fi);
        if (fname == "security_inode_setsecurity")
            if (auto fi = m->getFunction("smack_inode_setsecurity"))
                fs.insert(fi);
        if (fname == "security_inode_listsecurity")
            if (auto fi = m->getFunction("smack_inode_listsecurity"))
                fs.insert(fi);
        if (fname == "security_mmap_addr")
            if (auto fi = m->getFunction("cap_mmap_addr"))
                fs.insert(fi);
        if (fname == "security_mmap_file")
            if (auto fi = m->getFunction("cap_mmap_file"))
                fs.insert(fi);
        if (fname == "security_task_fix_setuid")
            if (auto fi = m->getFunction("cap_task_fix_setuid"))
                fs.insert(fi);
        if (fname == "security_task_prctl")
            if (auto fi = m->getFunction("cap_task_prctl"))
                fs.insert(fi);
        if (fname == "security_task_setscheduler")
            if (auto fi = m->getFunction("cap_task_setscheduler"))
                fs.insert(fi);
        if (fname == "security_task_setioprio")
            if (auto fi = m->getFunction("cap_task_setioprio"))
                fs.insert(fi);
        if (fname == "security_task_setnice")
            if (auto fi = m->getFunction("cap_task_setnice"))
                fs.insert(fi);
        if (fname == "security_vm_enough_memory_mm")
            if (auto fi = m->getFunction("cap_vm_enough_memory"))
                fs.insert(fi);

        if (fs.size()!=0)
        {
#if 0
            errs()<<" [KMI]\n";
#endif
            kmi_cnt++;
            goto resolved;
        }
        //using a fptr not implemented yet
        switch(err)
        {
            case(6):
            case(0):
            {
                goto unresolvable;
            }
            case(1):
            case(2)://try dkmi
            {
                //try dkmi
                break;
            }
            case(3):
            {
                //function parameter, unable to be solved by kmi and dkmi, try SVF
                fpar_cnt++;
                goto unresolvable;
            }
            case(4):
            {
                gptr_cnt++;
                goto unresolvable;
            }
            case(5):
            {
                cast_cnt++;
                goto unresolvable;
            }
            default:
            llvm_unreachable("no way!");
        }
        //try dkmi
        fs = resolve_indirect_callee_using_dkmi(idc, err);
        if (err<2)
            found_module = true;
        else if (err==2)
            udf_module = true;

        if (fs.size()!=0)
        {
#if 0
            errs()<<" [DKMI]\n";
#endif
            dkmi_cnt++;
            goto resolved;
        }
        if (found_module)
        {
#if 0
                errs()<<" [UNDEFINED1-found-m]\n";
#endif
                count++;
                targets++;
                undefined_1++;
                //dump_kmi_info(idc);
                continue;
        }
        if (udf_module)
        {
#if 0
            errs()<<" [UNDEFINED2-udf-m]\n";
#endif
            count++;
            targets++;
            undefined_2++;
            //dump_kmi_info(idc);
            continue;
        }
unresolvable:
        //can not resolve
        fuidcs.insert(idc->getFunction());
        switch(err)
        {
            case (3):
            {
                //function parameter
#if 0
                errs()<<" [UPARA]\n";
#endif
                break;
            }
            case (4):
            {
                //global fptr
#if 0
                errs()<<" [GFPTR]\n";
#endif
                break;
            }
            case (5):
            {
#if 0
                errs()<<" [BAD CAST]\n";
#endif
                break;
            }
            default:
            {
#if 0
                errs()<<" [UNKNOWN]\n";
#endif
                unknown++;
                //dump the struct
                //dump_kmi_info(idc);
            }
        }
        continue;
resolved:
        count++;
        targets += fs.size();
        FunctionSet *funcs = idcs2callee[idc];
        if (funcs==NULL)
        {
            funcs = new FunctionSet;
            idcs2callee[idc] = funcs;
        }
        std::vector<Constant*> codevec;
        int f_count = 0;
        for (auto f:fs)
        {
#if 0
            errs()<<"     - "<<f->getName()<<"\n";
#endif
            funcs->insert(f);
            InstructionSet* csis = f2csi_type1[f];
            if (csis==NULL)
            {
                csis = new InstructionSet;
                f2csi_type1[f] = csis;
            }
            csis->insert(idc);

            codevec.push_back(ConstantInt::get(Type::getInt32Ty(*ctx),
                                                getFuncCode(f)));
            f_count++;
        }
        // set metadata at idc callsite
        ArrayType *codesTy = ArrayType::get(Type::getInt32Ty(*ctx), fs.size());
        Constant *codes = ConstantArray::get(codesTy, ArrayRef<Constant*>(codevec));
        MDNode *N = MDNode::get(*ctx, ValueAsMetadata::get(codes));
        idc->setMetadata("ppac_indcall", N);
    }
    errs()<<ANSI_COLOR(BG_WHITE, FG_RED)
        <<"------ KMI STATISTICS ------"
        <<ANSI_COLOR_RESET"\n";
    errs()<<"# of indirect call sites: "<< idcs.size()<<"\n";
    if (idcs.size() == 0)
        return;
    errs()<<"# resolved by KMI:"<< count<<" "<<(100*count/idcs.size())<<"%\n";
    errs()<<"#     - KMI:"<< kmi_cnt<<" "<<(100*kmi_cnt/idcs.size())<<"%\n";
    errs()<<"#     - DKMI:"<< dkmi_cnt<<" "<<(100*dkmi_cnt/idcs.size())<<"%\n";
    errs()<<"# (total target) of callee:"<<targets<<"\n";
    errs()<<"# undefined-found-m : "<<undefined_1<<" "<<(100*undefined_1/idcs.size())<<"%\n";
    errs()<<"# undefined-udf-m : "<<undefined_2<<" "<<(100*undefined_2/idcs.size())<<"%\n";
    errs()<<"# fpara(KMI can not handle, try SVF?): "
                <<fpar_cnt
                <<" "<<(100*fpar_cnt/idcs.size())
                <<"%\n";
    errs()<<"# global fptr(try SVF?): "
                <<gptr_cnt
                <<" "<<(100*gptr_cnt/idcs.size())
                <<"%\n";
    errs()<<"# cast fptr(try SVF?): "
                <<cast_cnt
                <<" "<<(100*cast_cnt/idcs.size())
                <<"%\n";
    errs()<<"# call use container_of(), high level type info stripped: "
                <<container_of_cnt
                <<" "<<(100*container_of_cnt/idcs.size())
                <<"%\n";
    errs()<<"# unknown pattern:"
                <<unknown
                <<" "<<(100*unknown/idcs.size())
                <<"%\n";
    //exit(0);
}


/*
 * method 2: cvf: Complex Value Flow Analysis
 * figure out candidate for indirect callee using value flow analysis
 */
//void indcall::populate_indcall_list_using_cvf(Module& module)
//{
//    //create svf instance
//    CVFA cvfa;
//
//    /*
//     * NOTE: shrink our analyse scope so that we can run faster
//     * remove all functions which don't have function pointer use and
//     * function pointer propagation, because we only interested in getting
//     * indirect callee here, this will help us make cvf run faster
//     */
//    FunctionSet keep;
//    FunctionSet remove;
//    //add skip functions to remove
//    //add kernel_api to remove
//    for (auto f: *skip_funcs)
//        remove.insert(module.getFunction(f));
//    for (auto f: *kernel_api)
//        remove.insert(module.getFunction(f));
//    for (auto f: trace_event_funcs)
//        remove.insert(f);
//    for (auto f: bpf_funcs)
//        remove.insert(f);
//    for (auto f: irq_funcs)
//        remove.insert(f);
//
//    FunctionList new_add;
//    //for (auto f: all_functions)
//    //    if (is_using_function_ptr(f) || is_address_taken(f))
//    //        keep.insert(f);
//    for (auto f: fuidcs)
//        keep.insert(f);
//
//    for (auto f: syscall_list)
//        keep.insert(f);
//
//    ModuleDuplicator md(module, keep, remove);
//    Module& sm = md.getResult();
//
//    //CVF: Initialize, this will take some time
//    cvfa.initialize(sm);
//
//    //do analysis(idcs=sink)
//    //find out all possible value of indirect callee
//    errs()<<ANSI_COLOR(BG_WHITE, FG_BLUE)
//        <<"SVF indirect call track:"
//        <<ANSI_COLOR_RESET<<"\n";
//    for (auto f: all_functions)
//    {
//        ConstInstructionSet css;
//        Function* df = dyn_cast<Function>(md.map_to_duplicated(f));
//        cvfa.get_callee_function_indirect(df, css);
//        if (css.size()==0)
//            continue;
//        errs()<<ANSI_COLOR(BG_CYAN, FG_WHITE)
//            <<"FUNC:"<<f->getName()
//            <<", found "<<css.size()
//            <<ANSI_COLOR_RESET<<"\n";
//        for (auto* _ci: css)
//        {
//            //indirect call sites->function
//            const CallInst* ci = dyn_cast<CallInst>(md.map_to_origin(_ci));
//            assert(ci!=NULL);
//            FunctionSet* funcs = idcs2callee[ci];
//            if (funcs==NULL)
//            {
//                funcs = new FunctionSet;
//                idcs2callee[ci] = funcs;
//            }
//            funcs->insert(f);
//            //func->indirect callsites
//            InstructionSet* csis = f2csi_type1[f];
//            if (csis==NULL)
//            {
//                csis = new InstructionSet;
//                f2csi_type1[f] = csis;
//            }
//            CallInst *non_const_ci = const_cast<CallInst*>
//                            (static_cast<const CallInst*>(ci));
//
//            csis->insert(non_const_ci);
//
//#if 1
//            errs()<<"CallSite: ";
//            ci->getDebugLoc().print(errs());
//            errs()<<"\n";
//#endif
//        }
//    }
//}

/*
 * need to populate idcs2callee before calling this function
 * should not call into this function using direct call
 */
FunctionSet indcall::resolve_indirect_callee(CallInst* ci)
{
    FunctionSet fs;
    if (ci->isInlineAsm())
        return fs;
    if (get_callee_function_direct(ci))
        llvm_unreachable("resolved into direct call!");

    auto _fs = idcs2callee.find(ci);
    if (_fs != idcs2callee.end())
    {
        for (auto* f: *(_fs->second))
            fs.insert(f);
    }

#if 0
    //FUZZY MATCHING
    //method 1: signature based matching
    //only allow precise match when collecting protected functions
        Value* cv = ci->getCalledOperand();
        Type *ft = cv->getType()->getPointerElementType();
        if (!is_complex_type(ft))
            return fs;
        if (t2fs.find(ft)==t2fs.end())
            return fs;
        FunctionSet *fl = t2fs[ft];
        for (auto* f: *fl)
            fs.insert(f);
#endif
    return fs;
}
////////////////////////////////////////////////////////////////////////////////

/*
 * track user of functions which have checks, and see whether it is tied
 * to any interesting type(struct)
 */
Value* find_struct_use(Value* f, ValueSet& visited)
{
    if (visited.count(f))
        return NULL;
    visited.insert(f);
    for (auto* u: f->users())
    {
        if (u->getType()->isStructTy())
            return u;
        if (Value*_u = find_struct_use(u, visited))
            return _u;
    }
    return NULL;
}


/*
 * this is used to identify any assignment of fptr to struct field, and we 
 * collect this in complementary of identify_kmi
 */
void indcall::identify_dynamic_kmi(Module& module)
{
    int cnt_resolved = 0;
    for (auto *f: all_functions)
    {
        Value* v = dyn_cast<Value>(f);
        Indices inds;
        ValueSet visited;
        StructType *t = find_assignment_to_struct_type(v, inds, visited, dummyCE);
        if (!t)
            continue;
        //Great! we got one! merge to know list or creat new

        cnt_resolved++;
        add_function_to_dmi(f, t, inds, dmi);
    }
    errs()<<"#dyn kmi resolved:"<<cnt_resolved<<"\n";
}

void indcall::dump_dkmi()
{
    if (!knob_indcall_dkmi)
        return;
    errs()<<ANSI_COLOR(BG_WHITE,FG_CYAN)<<"=dynamic KMI="<<ANSI_COLOR_RESET<<"\n";
    for (auto tp: dmi)
    {
        //type to metadata mapping
        StructType* t = tp.first;
        errs()<<"Type:";
        if (t->isLiteral())
            errs()<<"Literal\n";
        else
            errs()<<t->getStructName()<<"\n";
        //here comes the pairs
        IFPairs* ifps = tp.second;
        for (auto ifp: *ifps)
        {
            //indicies
            Indices* idcs = ifp->first;
            FunctionSet* fset = ifp->second;
            errs()<<"  @ [";
            for (auto i: *idcs)
            {
                errs()<<i<<",";
            }
            errs()<<"]\n";
            //function names
            for (Function* f: *fset)
            {
                errs()<<"        - ";
                errs()<<f->getName();
                errs()<<"\n";
            }
        }
    }
    errs()<<"\n";
}

/*
 * identify logical kernel module
 * kernel module usually connect its functions to a struct that can be called 
 * by upper layer
 * collect all global struct variable who have function pointer field
 */
void indcall::identify_kmi(Module& module)
{
    //Module::GlobalListType &globals = module.getGlobalList();
    //not an interesting type, no function ptr inside this struct
    TypeSet nomo;
    for(GlobalVariable &gvi: module.globals())
    {
        GlobalVariable* gi = &gvi;
        if (gi->isDeclaration())
            continue;
        assert(isa<Value>(gi));

        StringRef gvn = gi->getName();
        if (gvn.startswith("__kstrtab") || 
                gvn.startswith("__tpstrtab") || 
                gvn.startswith(".str") ||
                gvn.startswith("llvm.") ||
                gvn.startswith("__setup_str"))
            continue;

        Type* mod_interface = gi->getType();

        if (mod_interface->isPointerTy())
            mod_interface = mod_interface->getPointerElementType();
        if (!mod_interface->isAggregateType())
            continue;
        if (mod_interface->isArrayTy())
        {
            mod_interface
                = dyn_cast<ArrayType>(mod_interface)->getArrayElementType();
        }
        if (!mod_interface->isStructTy())
        {
            if (mod_interface->isFirstClassType())
                continue;
            //report any non-first class type
            errs()<<"IDKMI: aggregate type not struct?\n";
            mod_interface->print(errs());
            errs()<<"\n";
            errs()<<gi->getName()<<"\n";
            continue;
        }
        if (nomo.find(mod_interface)!=nomo.end())
            continue;
        //function pointer inside struct?
        if (!has_function_pointer_type(mod_interface))
        {
            nomo.insert(mod_interface);
            continue;
        }
        //add
        ModuleSet *ms;
        if (mi2m.find(mod_interface) != mi2m.end())
        {
            ms = mi2m[mod_interface];
        }else
        {
            ms = new ModuleSet;
            mi2m[mod_interface] = ms;
        }
        assert(ms);
        ms->insert(gi);
        //if (array_type)
        //    errs()<<"Added ArrayType:"<<gvn<<"\n";
    }
    TypeList to_remove;
    ModuleInterface2Modules to_add;
    //resolve Annoymous type into known type
    for (auto msi: mi2m)
    {
        StructType * stype = dyn_cast<StructType>(msi.first);
        if (stype->hasName())
            continue;
        StructType *rstype = NULL;
        assert(msi.second);
        for (auto m: (*msi.second))
        {
            //constant bitcast into struct
            for (auto *_u: m->users())
            {
                ConstantExpr* u = dyn_cast<ConstantExpr>(_u);
                BitCastInst* bciu = dyn_cast<BitCastInst>(_u);
                PointerType* type = NULL;
                if((u) && (u->isCast()))
                {
                    type = dyn_cast<PointerType>(u->getType());
                    goto got_bitcast;
                }
                if (bciu)
                {
                    type = dyn_cast<PointerType>(bciu->getType());
                    goto got_bitcast;
                }
                //what else???
                continue;
got_bitcast:
                //struct object casted into non pointer type?
                if (type==NULL)
                    continue;
                StructType* _stype = dyn_cast<StructType>(type->getElementType());
                if ((!_stype) || (!_stype->hasName()))
                    continue;
                rstype = _stype;
                goto out;
            }
        }
out:
        if (!rstype)
            continue;
        //resolved, merge with existing type
        if (mi2m.find(rstype)!=mi2m.end())
        {
            ModuleSet* ms = mi2m[rstype];
            for (auto m: (*msi.second))
                ms->insert(m);
        }else if (to_add.find(rstype)!=to_add.end())
        {
            ModuleSet* ms = to_add[rstype];
            for (auto m: (*msi.second))
                    ms->insert(m);
        }else
        {
            //does not exists? reuse current one!
            to_add[rstype] = msi.second;
            /*
             * this should not cause crash as we already parsed current element
             * and this should be set to NULL in order to not be deleted later
             */
            mi2m[stype] = NULL;
        }
        to_remove.push_back(stype);
    }
    for (auto r: to_remove)
    {
        delete mi2m[r];
        mi2m.erase(r);
    }
    for (auto r: to_add)
        mi2m[r.first] = r.second;
}

/*
 * populate cache
 * --------------
 * all_functions
 * t2fs(Type to FunctionSet)
 * syscall_list
 * f2csi_type0 (Function to BitCast CallSite)
 * idcs(indirect call site)
 */
void indcall::preprocess(Module& module)
{
    int func_count = 0;
    for (Module::iterator fi = module.begin(), f_end = module.end();
            fi != f_end; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (func->isDeclaration())
        {
            ExternalFuncCounter++;
            continue;
        }
        if (func->isIntrinsic())
            continue;

        FuncCounter++;

        all_functions.insert(func);

        // function map to export analysis result
        funcCode[func] = func_count;
        func_count++;

        Type* type = func->getFunctionType();
        FunctionSet *fl = t2fs[type];
        if (fl==NULL)
        {
            fl = new FunctionSet;
            t2fs[type] = fl;
        }
        fl->insert(func);
        
        if (is_syscall_prefix(func->getName()))
            syscall_list.insert(func);

        for(Function::iterator fi = func->begin(), fe = func->end();
                fi != fe; ++fi)
        {
            BasicBlock* bb = dyn_cast<BasicBlock>(fi);
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                CallInst* ci = dyn_cast<CallInst>(ii);
                if (!ci || ci->getCalledFunction() || ci->isInlineAsm())
                    continue;
                
                Value* cv = ci->getCalledOperand();
                Function *bcf = dyn_cast<Function>(cv->stripPointerCasts());
                if (bcf)
                {
                    //this is actually a direct call with function type cast
                    InstructionSet* csis = f2csi_type0[bcf];
                    if (csis==NULL)
                    {
                        csis = new InstructionSet;
                        f2csi_type0[bcf] = csis;
                    }
                    csis->insert(ci);
                    continue;
                }
                idcs.insert(ci);
            }
        }
    }
}

FunctionSet indcall::function_signature_match(CallInst* ci)
{
    FunctionSet fs;
    Value* cv = ci->getCalledOperand();
    Type *ft = cv->getType()->getPointerElementType();
    if (t2fs.find(ft)==t2fs.end())
        return fs;
    FunctionSet *fl = t2fs[ft];
    for (auto* f: *fl)
        fs.insert(f);
    return fs;
}

void indcall::export_func_code()
{
    std::ofstream ofs(knob_func_code_list, std::ofstream::out);
    for (auto m : funcCode)
    {
        ofs << m.first->getName().str();
        ofs << "\n";
               ofs << m.second
            << "\n";
    }
               ofs.close();


}

void indcall::my_debug(Module& module)
{
    int resolved = 0;
    int targets = 0;
    for (auto* idc: idcs)
    {
        FunctionSet fs = function_signature_match(idc);
        if (fs.size()!=0)
        {
            resolved++;
        }
        targets+=fs.size();
    }
    errs()<<"# fsm total idcs to resolve:"<< idcs.size()<<"\n";
    errs()<<"# fsm resolved:"<<resolved<<"\n";
    errs()<<"# fsm targets:"<<targets<<"\n";
}

int indcall::getFuncCode(Function *func)
{
    return funcCode[func];
}

/*
 * process capability protected globals and functions
 */
void indcall::process_cpgf(Module& module)
{
    errs()<<"Pre-processing...\n";
    STOP_WATCH_MON(WID_0, preprocess(module));
    errs()<<"Found "<<syscall_list.size()<<" syscalls\n";

    errs()<<"Collecting Initialization Closure.\n";
    STOP_WATCH_MON(WID_0, collect_kernel_init_functions(module));

//    statistics for function signature based approache
//    STOP_WATCH_MON(WID_0, my_debug(module));
//    exit (0);

    errs()<<"Identify Kernel Modules Interface\n";
    STOP_WATCH_MON(WID_0, identify_kmi(module));
    dump_kmi();
    errs()<<"dynamic KMI\n";
    STOP_WATCH_MON(WID_0, identify_dynamic_kmi(module));
    dump_dkmi();

    errs()<<"Populate indirect callsite using kernel module interface\n";
    STOP_WATCH_MON(WID_0, populate_indcall_list_through_kmi(module));

//    if (knob_indcall_cvf)
//    {
//        errs()<<"Resolve indirect callsite.\n";
//        STOP_WATCH_MON(WID_0, populate_indcall_list_using_cvf(module));
//    }
//    exit(0);

    delete skip_funcs;
    delete skip_vars;
    delete crit_syms;
    delete kernel_api;
    //delete gating;
}

bool indcall::runOnModule(Module &module)
{
    m = &module;
    ctx = &m->getContext();
    return indcallPass(module);
}

bool indcall::indcallPass(Module &module)
{
    errs()<<ANSI_COLOR_CYAN
        <<"--- PROCESS FUNCTIONS ---"
        <<ANSI_COLOR_RESET<<"\n";
    process_cpgf(module);
    errs()<<ANSI_COLOR_CYAN
        <<"--- DONE! ---"
        <<ANSI_COLOR_RESET<<"\n";

#if CUSTOM_STATISTICS
    dump_statistics();
#endif

    for (auto dummy : dummyCE) {
        dummy->deleteValue();
    }
    for (auto dummy : dummyCE_map) {
        dummy.first->deleteValue();
    }
    export_func_code();
    align_globals();
    return false;
}

static RegisterPass<indcall>
XXX("indcall", "indcall Pass (with getAnalysisUsage implemented)");
