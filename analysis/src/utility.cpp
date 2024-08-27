/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "utility.h"
#include "color.h"
#include "internal.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
using namespace llvm;

static InstructionList dbgstk;
static ValueList dbglst;
static CE2Inst ce2fi_new;
IntFunctionMap funcCode;
Str2Int sizes;

static bool any_user_of_av_is_v(Value* av, Value* v, ValueSet& visited)
{
    if (av==v)
        return true;
    if (visited.count(av))
        return false;
    visited.insert(av);
    for (auto* u: av->users())
    {
        if (dyn_cast<Value>(u)==v)
        {
            return true;
        }
        if (any_user_of_av_is_v(u, v, visited))
        {
            return true;
        }
    }
    return false;
}

/*
 * full def-use chain
 */
int use_parent_func_arg_deep(Value* v, Function* f)
{
    int cnt = 0;
    for (auto a = f->arg_begin(), b = f->arg_end(); a!=b; ++a)
    {
        Value* av = dyn_cast<Value>(a);
        ValueSet visited;
        if (any_user_of_av_is_v(av,v,visited))
            return cnt;
        cnt++;
    }
    return -1;
}


Instruction* GetNextInstruction(Instruction* i)
{
    //if (isa<TerminatorInst>(i))
    //    return i;
    BasicBlock::iterator BBI(i);
    return dyn_cast<Instruction>(++BBI);
}

Instruction* GetNextNonPHIInstruction(Instruction* i)
{
    //if (isa<TerminatorInst>(i))
    //    return i;
    BasicBlock::iterator BBI(i);
    while(isa<PHINode>(BBI))
        ++BBI;
    return dyn_cast<Instruction>(BBI);
}

Function* get_callee_function_direct(Instruction* i)
{
    CallInst* ci = dyn_cast<CallInst>(i);
    if (!ci)
        return nullptr;
    if (Function* f = ci->getCalledFunction())
        return f;
    Value* cv = ci->getCalledOperand();
    Function* f = dyn_cast<Function>(cv->stripPointerCasts());
    return f;
}

StringRef get_callee_function_name(Instruction* i)
{
    if (Function* f = get_callee_function_direct(i))
        return get_func_name(f->getName().str());
    return "";
}

//compare two indices
bool indices_equal(Indices* a, Indices* b)
{
    if (a->size()!=b->size())
        return false;
    auto ai = a->begin();
    auto bi = b->begin();
    while(ai!=a->end())
    {
        if (*ai!=*bi)
            return false;
        bi++;
        ai++;
    }
    return true;
}


/*
 * store dyn KMI result into DMInterface so that we can use it later
 */
void add_function_to_dmi(Function* f, StructType* t, Indices& idcs, DMInterface& dmi)
{
    IFPairs* ifps = dmi[t];
    if (ifps==NULL)
    {
        ifps = new IFPairs;
        dmi[t] = ifps;
    }
    FunctionSet* fset = NULL;
    for (auto* p: *ifps)
    {
        if (indices_equal(&idcs, p->first))
        {
            fset = p->second;
            break;
        }
    }
    if (fset==NULL)
    {
        fset = new FunctionSet;
        Indices* idc = new Indices;
        for (auto i: idcs)
            idc->push_back(i);
        IFPair* ifp = new IFPair(idc,fset);
        ifps->push_back(ifp);
    }
    fset->insert(f);
}

/*
 * this type exists in dmi?
 */
bool dmi_type_exists(StructType* t, DMInterface& dmi)
{
//first method
    auto ifps = dmi.find(t);
    std::string stname;
    //only use this for literal
    if (t->isLiteral())
    {
        if (ifps!=dmi.end())
            return true;
        return false;
    }
    //match using name
    stname = t->getStructName().str();
    str_truncate_dot_number(stname);
    for (auto& ifpsp: dmi)
    {
        StructType* cst = ifpsp.first;
        if (cst->isLiteral())
            continue;
        std::string cstn = cst->getStructName().str();
        str_truncate_dot_number(cstn);
        if (cstn==stname)
        {
            return true;
        }
    }
    return false;
}

/*
 * given StructType and indices, return FunctionSet or NULL
 */
FunctionSet* dmi_exists(StructType* t, Indices& idcs, DMInterface& dmi)
{
//first method
    auto ifps = dmi.find(t);
    std::string stname;
    IFPairs* ifpairs;
    //only use this for literal
    if (t->isLiteral())
    {
        if (ifps!=dmi.end())
        {
            ifpairs = ifps->second;
            for (auto* p: *ifpairs)
                if (indices_equal(&idcs, p->first))
                    return p->second;
        }
        goto end;
    }

    //match using name
    stname = t->getStructName().str();
    str_truncate_dot_number(stname);
    for (auto& ifpsp: dmi)
    {
        StructType* cst = ifpsp.first;
        if (cst->isLiteral())
            continue;
        std::string cstn = cst->getStructName().str();
        str_truncate_dot_number(cstn);
        if (cstn==stname)
        {
            ifpairs = ifpsp.second;
            for (auto* p: *ifpairs)
                if (indices_equal(&idcs, p->first))
                    return p->second;
        }
    }

end:
    return NULL;
}


/*
 * intra-procedural analysis
 *
 * only handle high level type info right now.
 * maybe we can extend this to global variable as well
 *
 * see if store instruction actually store the value to some field of a struct
 * return non NULL if found, and indices is stored in idcs
 *
 */
static StructType* resolve_where_is_it_stored_to(StoreInst* si, Indices& idcs, InstructionSet &dummyCE)
{
    StructType* ret = NULL;
    //po is the place where we want to store to
    Value* po = si->getPointerOperand();
    ValueList worklist;
    ValueSet visited;
    worklist.push_back(po);

    //use worklist to track what du-chain
    while (worklist.size())
    {
        //fetch an item and skip if visited
        po = worklist.front();
        worklist.pop_front();
        if (visited.count(po))
            continue;
        visited.insert(po);

        /*
         * pointer operand is global variable?
         * dont care... we can extend this to support fine grind global-aa, since
         * we already know the target
         */
        if (dyn_cast<GlobalVariable>(po))
            continue;
        if (ConstantExpr* cxpr = dyn_cast<ConstantExpr>(po))
        {
            Instruction* cxpri = cxpr->getAsInstruction();
            worklist.push_back(cxpri);
            dummyCE.insert(cxpri);
            continue;
        }
        if (Instruction* i = dyn_cast<Instruction>(po))
        {
            switch(i->getOpcode())
            {
                case(Instruction::PHI):
                {
                    PHINode* phi = dyn_cast<PHINode>(i);
                    for (unsigned int i=0;i<phi->getNumIncomingValues();i++)
                        worklist.push_back(phi->getIncomingValue(i));
                    break;
                }
                case(Instruction::Select):
                {
                    SelectInst* sli = dyn_cast<SelectInst>(i);
                    worklist.push_back(sli->getTrueValue());
                    worklist.push_back(sli->getFalseValue());
                    break;
                }
                case(BitCastInst::BitCast):
                {
                    BitCastInst *bci = dyn_cast<BitCastInst>(i);
//FIXME:sometimes struct name is purged into i8.. we don't know why,
//but we are not able to resolve those since they are translated
//to gep of byte directly without using any struct type/member/field info
//example: alloc_buffer, drivers/usb/host/ohci-dbg.c
                    worklist.push_back(bci->getOperand(0));
                    break;
                }
                case(Instruction::IntToPtr):
                {
                    IntToPtrInst* i2ptr = dyn_cast<IntToPtrInst>(i);
                    worklist.push_back(i2ptr->getOperand(0));
                    break;
                }
                case(Instruction::GetElementPtr):
                {
                    //only GEP is meaningful
                    GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(i);
                    Type* t = gep->getSourceElementType();
                    get_gep_indicies(gep, idcs);
                    assert(idcs.size()!=0);
                    ret = dyn_cast<StructType>(t);
                    goto out;
                    break;
                }
                case(Instruction::Call):
                {
                    //ignore interprocedural...
                    break;
                }
                case(Instruction::Load):
                {
                    //we are not able to handle load
                    break;
                }
                case(Instruction::Store):
                {
                    //how come we have a store???
                    dump_gdblst(dbglst);
                    llvm_unreachable("Store to Store?");
                    break;
                }
                case(Instruction::Alloca):
                {
                    //store to a stack variable
                    //maybe interesting to explore who used this.
                    break;
                }
                case(BinaryOperator::Add):
                {
                    //adjust pointer using arithmatic, seems to be weired
                    BinaryOperator *bop = dyn_cast<BinaryOperator>(i);
                    for (unsigned int i=0;i<bop->getNumOperands();i++)
                        worklist.push_back(bop->getOperand(i));
                    break;
                }
                case(Instruction::PtrToInt):
                {
                    PtrToIntInst* p2int = dyn_cast<PtrToIntInst>(i);
                    worklist.push_back(p2int->getOperand(0));
                    break;
                }
                default:
                    errs()<<"unable to handle instruction:"
                        <<ANSI_COLOR_RED;
                    i->print(errs());
                    errs()<<ANSI_COLOR_RESET<<"\n";
                    break;
            }
        }else
        {
            //we got a function parameter
        }
    }
out:
    return ret;
}

/*
 * part of dynamic KMI - a data flow analysis
 * for value v, we want to know whether it is assigned to a struct field, and 
 * we want to know indices and return the struct type
 * NULL is returned if not assigned to struct
 *
 * ! there should be a store instruction in the du-chain
 * TODO: extend this to inter-procedural analysis
 */
//known interesting
inline bool stub_fatst_is_interesting_value(Value* v)
{

    if (isa<BitCastInst>(v)||
        isa<CallInst>(v)||
        isa<ConstantExpr>(v)||
        isa<StoreInst>(v) ||
        isa<Function>(v))
        return true;
    if (SelectInst* si = dyn_cast<SelectInst>(v))
    {
        //result of select shoule be the same as v
        if (si->getType()==v->getType())
            return true;
    }
    if (PHINode *phi = dyn_cast<PHINode>(v))
    {
        if (phi->getType()==v->getType())
            return true;
    }
    //okay if this is a function parameter
    //a value that is not global and not an instruction/phi
    if ((!isa<GlobalValue>(v))
            && (!isa<Instruction>(v)))
    {
        return true;
    }

    return false;
}
//known uninteresting
inline bool stub_fatst_is_uninteresting_value(Value*v)
{
    if (isa<GlobalVariable>(v) ||
        isa<Constant>(v) ||
        isa<ICmpInst>(v) ||
        isa<PtrToIntInst>(v))
        return true;
    return false;
}

StructType* find_assignment_to_struct_type(Value* v, Indices& idcs,
                                           ValueSet& visited, InstructionSet& dummyCE)
{
    if (visited.count(v))
        return NULL;
    visited.insert(v);

    dbglst.push_back(v);

    //FIXME: it is possible to assign to global variable!
    //       but currently we are not handling them
    //skip all global variables,
    //the address is statically assigned to global variable
    if (!stub_fatst_is_interesting_value(v))
    {
#if 0
        if (!stub_fatst_is_uninteresting_value(v))
        {
            errs()<<ANSI_COLOR_RED<<"XXX:"
                <<ANSI_COLOR_RESET<<"\n";
            dump_gdblst(dbglst);
        }
#endif
        dbglst.pop_back();
        return NULL;
    }

    //* ! there should be a store instruction in the du-chain
    if (StoreInst* si = dyn_cast<StoreInst>(v))
    {
        StructType* ret = resolve_where_is_it_stored_to(si, idcs, dummyCE);
        dbglst.pop_back();
        return ret;
    }

    for (auto* u: v->users())
    {
        Value* tu = u;
        Type* t = u->getType();
        if (StructType* t_st = dyn_cast<StructType>(t))
            if ((t_st->hasName())
                && t_st->getStructName().startswith("struct.kernel_symbol"))
                    continue;
        //inter-procedural analysis
        //we are interested if it is used as a function parameter
        if (CallInst* ci = dyn_cast<CallInst>(tu))
        {
            //currently only deal with direct call...
            Function* cif = get_callee_function_direct(ci);
            if ((ci->getCalledOperand()==v) || (cif==u))
            {
                //ignore calling myself..
                continue;
            }else if (cif==NULL)
            {
                //indirect call...
#if 0
                errs()<<"fptr used in indirect call";
                ci->print(errs());errs()<<"\n";
                errs()<<"arg v=";
                v->print(errs());errs()<<"\n";
#endif
                continue;
            } else if (!cif->isVarArg())
            {
                //try to figure out which argument is u corresponds to
                int argidx = -1;
                for (unsigned int ai = 0; ai<ci->arg_size(); ai++)
                {
                    if (ci->getArgOperand(ai)==v)
                    {
                        argidx = ai;
                        break;
                    }
                }
                //argidx should not ==-1
                if (argidx==-1)
                {
                    errs()<<"Calling "<<cif->getName()<<"\n";
                    ci->print(errs());errs()<<"\n";
                    errs()<<"arg v=";
                    v->print(errs());
                    errs()<<"\n";
                }
                assert(argidx!=-1);
                //errs()<<"Into "<<cif->getName()<<"\n";
                //now are are in the callee function
                //figure out the argument
                auto targ = cif->arg_begin();
                for (int i=0;i<argidx;i++)
                    targ++;
                tu = targ;
            }else
            {
                //means that this is a vararg
                continue;
            }
        }
        //FIXME: visited?
        if (StructType* st = find_assignment_to_struct_type(tu, idcs, visited, dummyCE))
        {
            dbglst.pop_back();
            return st;
        }
    }
    dbglst.pop_back();
    return NULL;
}

InstructionSet get_user_instruction(Value* v)
{
    InstructionSet ret;
    ValueSet vset;
    ValueSet visited;
    visited.insert(v);
    for (auto* u: v->users())
    {
        vset.insert(u);
    }
    while (vset.size())
    {
        for (auto x: vset)
        {
            v = x;
            break;
        }
        visited.insert(v);
        vset.erase(v);
        //if a user is a instruction add it to ret and remove from vset
        if (Instruction *i = dyn_cast<Instruction>(v))
        {
            ret.insert(i);
            continue;
        }
        //otherwise add all user of current one
        for (auto* _u: v->users())
        {
            if (visited.count(_u)==0)
                vset.insert(_u);
        }
    }
    return ret;
}

/*
 * get CallInst
 * this can resolve call using bitcast
 *  : call %() bitcast %() @foo()
 */
static void _get_callsite_inst(Value*u, CallInstSet& cil, int depth)
{
    if (depth>2)
        return;
    Value* v = u;
    CallInst *cs;
    cs = dyn_cast<CallInst>(v);
    if (cs)
    {
        cil.insert(cs);
        return;
    }
    //otherwise...
    for (auto *u: v->users())
        _get_callsite_inst(u, cil, depth+1);
}

void get_callsite_inst(Value*u, CallInstSet& cil)
{
    _get_callsite_inst(u, cil, 0);
}

/*
 * is this type a function pointer type or 
 * this is a composite type which have function pointer type element
 */
static bool _has_function_pointer_type(Type* type, TypeSet& visited)
{
    if (visited.count(type)!=0)
        return false;
    visited.insert(type);
strip_pointer:
    if (type->isPointerTy())
    {
        type = type->getPointerElementType();
        goto strip_pointer;
    }
    if (type->isFunctionTy())
        return true;
    
    //ignore array type?
    //if (!type->isAggregateType())
    if (!type->isStructTy())
        return false;
    //for each element in this aggregate type, find out whether the element
    //type is Function pointer type, need to track down more if element is
    //aggregate type
    for (unsigned i=0; i<type->getStructNumElements(); ++i)
    {
        Type* t = type->getStructElementType(i);
        if (t->isPointerTy())
        {
            if (_has_function_pointer_type(t, visited))
                return true;
        }else if (t->isStructTy())
        {
            if (_has_function_pointer_type(t, visited))
                return true;
        }
    }
    //other composite type
    return false;
}

bool has_function_pointer_type(Type* type)
{
    TypeSet visited;
    return _has_function_pointer_type(type, visited);
}

/*
 * return global value if this is loaded from global value, otherwise return NULL
 */
GlobalValue* get_loaded_from_gv(Value* v, InstructionSet &dummyCE)
{
    GlobalValue* ret = NULL;
    IntToPtrInst* i2ptr = dyn_cast<IntToPtrInst>(v);
    LoadInst* li;
    Value* addr;
    if (!i2ptr)
        goto end;
    //next I am expectnig a load instruction
    li = dyn_cast<LoadInst>(i2ptr->getOperand(0));
    if (!li)
        goto end;
    addr = li->getPointerOperand()->stripPointerCasts();
    //could be a constant expr of gep?
    if (ConstantExpr* cxpr = dyn_cast<ConstantExpr>(addr))
    {
        GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(cxpr->getAsInstruction());
        dummyCE.insert(gep);
        if (Value* tpobj = gep->getPointerOperand())
            ret = dyn_cast<GlobalValue>(tpobj);
    }
end:
    return ret;
}

/*
 * is this a load+bitcast of struct into fptr type?
 * could be multiple load + bitcast 
 */
StructType* identify_ld_bcst_struct(Value* v)
{
#if 0
    LoadInst* li = dyn_cast<LoadInst>(v);
    if (!li)
        return NULL;
    Value* addr = li->getPointerOperand();
    if (BitCastInst* bci = dyn_cast<BitCastInst>(addr))
        addr = bci->getOperand(0);
    else
        return NULL;
    //should be pointer type
    if (PointerType* pt = dyn_cast<PointerType>(addr->getType()))
    {
        Type* et = pt->getElementType();
        if (StructType *st = dyn_cast<StructType>(et))
        {
            //resolved!, they are trying to load the first function pointer
            //from a struct type we already know!
            return st;
        }
    }
    return NULL;
#else
    int num_load = 0;
    Value* nxtv = v;
    while(1)
    {
        if (LoadInst* li = dyn_cast<LoadInst>(nxtv))
        {
            nxtv = li->getPointerOperand();
            num_load++;
            continue;
        }
        if (IntToPtrInst* itoptr = dyn_cast<IntToPtrInst>(nxtv))
        {
            nxtv = itoptr->getOperand(0);
            continue;
        }
        break;
    }
    if (num_load==0)
        return NULL;
    if (BitCastInst* bci = dyn_cast<BitCastInst>(nxtv))
    {
        nxtv = bci->getOperand(0);
    }else
        return NULL;
    //num_load = number of * in nxtv
    Type* ret = nxtv->getType();
    while(num_load)
    {
        //I am expecting a pointer type
        PointerType* pt = dyn_cast<PointerType>(ret);
        if (!pt)
        {
            errs()<<"I am expecting a pointer type! got:";
            ret->print(errs());
            errs()<<"\n";
            return NULL;
        }
        //assert(pt);
        ret = pt->getElementType();
        num_load--;
    }
    return dyn_cast<StructType>(ret);
#endif
}

/*
 * trace point function as callee?
 * similar to load+gep, we can not know callee statically, because it is not defined
 * trace point is a special case where the indirect callee is defined at runtime,
 * we simply mark it as resolved since we can find where the callee fptr is loaded
 * from
 */
bool is_tracepoint_func(Value* v, InstructionSet& dummyCE)
{
    if (StructType* st = identify_ld_bcst_struct(v))
    {
#if 0
        errs()<<"Found:";
        if (st->isLiteral())
            errs()<<"Literal\n";
        else
            errs()<<st->getStructName()<<"\n";
#endif
        //no name ...
        if (!st->hasName())
            return false;
        StringRef name = st->getStructName().str();
        if (name=="struct.tracepoint_func")
        {
            //errs()<<" ^ a tpfunc:";
            //addr->print(errs());
            LoadInst* li = dyn_cast<LoadInst>(v);
            Value* addr = li->getPointerOperand()->stripPointerCasts();

            //addr should be a phi
            PHINode * phi = dyn_cast<PHINode>(addr);
            assert(phi);
            //one of the incomming value should be a load
            for (unsigned int i=0;i<phi->getNumIncomingValues();i++)
            {
                Value* iv = phi->getIncomingValue(i);
                //should be a load from a global defined object
                if (GlobalValue* gv = get_loaded_from_gv(iv, dummyCE))
                {
                    //gv->print(errs());
                    //errs()<<(gv->getName());
                    break;
                }
            }
            //errs()<<"\n";
            return true;
        }
        return false;
    }
    //something else?
    return false;
}

/*
 * FIXME: we are currently not able to handle container_of, which is expanded
 * into gep with negative index and high level type information is stripped
 * maybe we can define a function to repalce container_of... so that high level
 * type information won't be stripped during compilation
 */
bool is_container_of(Value* v, InstFuncMap& dummyCE)
{
    if (auto gep = dyn_cast<GetElementPtrInst>(v)) {
        if (isa<ConstantInt>(gep->getOperand(1))) {
            if (cast<ConstantInt>(gep->getOperand(1))->getSExtValue() != 0)
                return true;
        }
    }

    return false;
/*
    InstructionSet geps = get_load_from_gep(cv, dummyCE);
    for (auto _gep: geps)
    {
        GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(_gep);
        //container_of has gep with negative index
        //and must have negative or non-zero index in the first element
        auto i = gep->idx_begin();
        ConstantInt* idc = dyn_cast<ConstantInt>(i);
        if (idc && (idc->getSExtValue()!=0))
        {
#if 0
            Type* pty = gep->getSourceElementType();
            if(StructType* sty = dyn_cast<StructType>(pty))
            {
                if (!sty->isLiteral())
                    errs()<<sty->getStructName()<<" ";
            }
#endif
            return true;
        }
    }
    return false;
*/
}

Type *stripPointerType(Type *type) {
    Type *elemTy = type;
    while(isa<PointerType>(elemTy))
        elemTy = elemTy->getPointerElementType();
    return elemTy;
}


/*
 * get the type where the function pointer is stored
 * could be combined with bitcast/gep/select/phi
 *
 *   addr = (may bit cast) gep(struct addr, field)
 *   ptr = load(addr)
 *   call ptr
 *
 *  may have other form like:
 *  addr1 = gep
 *  addr2 = gep
 *  ptr0 = phi/select addr1, addr2
 *  ptr1 = bitcast ptr0
 *  fptr = load(ptr1)
 *  call fptr
 *
 *  or no gep at all like
 *
 *  fptr_addr = bitcast struct addr, func type*()
 *  fptr = load fptr_addr
 *  call fptr
 *
 */
InstructionSet get_load_from_gep(Value* v, InstFuncMap& dummyCE)
{
    InstructionSet lots_of_geps;
    //handle non load instructions first
    //might be gep/phi/select/bitcast
    //collect all load instruction into loads
    InstructionSet loads;
    ValueSet visited;
    ValueList worklist;

    //first, find all interesting load
    worklist.push_back(v);
    while(worklist.size())
    {
        Value* i = worklist.front();
        worklist.pop_front();
        if (visited.count(i))
            continue;
        visited.insert(i);
        assert(i!=NULL);
        if (LoadInst* li = dyn_cast<LoadInst>(i))
        {
            loads.insert(li);
            continue;
        }
        if (BitCastInst * bci = dyn_cast<BitCastInst>(i))
        {
            worklist.push_back(bci->getOperand(0));
            continue;
        }
        if (PHINode* phi = dyn_cast<PHINode>(i))
        {
            for (int k=0; k<(int)phi->getNumIncomingValues(); k++)
                worklist.push_back(phi->getIncomingValue(k));
            continue;
        }
        if (SelectInst* sli = dyn_cast<SelectInst>(i))
        {
            worklist.push_back(sli->getTrueValue());
            worklist.push_back(sli->getFalseValue());
            continue;
        }
        if (IntToPtrInst* itptr = dyn_cast<IntToPtrInst>(i))
        {
            worklist.push_back(itptr->getOperand(0));
            continue;
        }
        if (PtrToIntInst* ptint = dyn_cast<PtrToIntInst>(i))
        {
            worklist.push_back(ptint->getOperand(0));
            continue;
        }
        //binary operand for pointer manupulation
        if (BinaryOperator *bop = dyn_cast<BinaryOperator>(i))
        {
            for (int i=0;i<(int)bop->getNumOperands();i++)
                worklist.push_back(bop->getOperand(i));
            continue;
        }
        if (ZExtInst* izext = dyn_cast<ZExtInst>(i))
        {
            worklist.push_back(izext->getOperand(0));
            continue;
        }
        if (SExtInst* isext = dyn_cast<SExtInst>(i))
        {
            worklist.push_back(isext->getOperand(0));
            continue;
        }
        if (isa<ExtractValueInst>(i)) {
            continue;
        }
        if (isa<GlobalValue>(i) || isa<ConstantExpr>(i) ||
            isa<GetElementPtrInst>(i) || isa<CallInst>(i))
            continue;
        if (!isa<Instruction>(i))
            continue;
        i->print(errs());
        errs()<<"\n";
        llvm_unreachable("no possible");
    }
    //////////////////////////
    //For each load instruction's pointer operand, we want to know whether
    //it is derived from gep or not..
    for (auto* lv: loads)
    {
        LoadInst* li = dyn_cast<LoadInst>(lv);
        Value* addr = li->getPointerOperand();

        //track def-use chain
        worklist.push_back(addr);
        visited.clear();
        while (worklist.size())
        {
            Value* i = worklist.front();
            worklist.pop_front();
            if (visited.count(i))
                continue;
            visited.insert(i);
            if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(i))
            {
                lots_of_geps.insert(gep);
                continue;
            }
            if (BitCastInst * bci = dyn_cast<BitCastInst>(i))
            {
                worklist.push_back(bci->getOperand(0));
                continue;
            }
            if (PHINode* phi = dyn_cast<PHINode>(i))
            {
                for (int k=0; k<(int)phi->getNumIncomingValues(); k++)
                    worklist.push_back(phi->getIncomingValue(k));
                continue;
            }
            if (SelectInst* sli = dyn_cast<SelectInst>(i))
            {
                worklist.push_back(sli->getTrueValue());
                worklist.push_back(sli->getFalseValue());
                continue;
            }
            if (IntToPtrInst* itptr = dyn_cast<IntToPtrInst>(i))
            {
                worklist.push_back(itptr->getOperand(0));
                continue;
            }
            if (PtrToIntInst* ptint = dyn_cast<PtrToIntInst>(i))
            {
                worklist.push_back(ptint->getOperand(0));
                continue;
            }
            //binary operand for pointer manupulation
            if (BinaryOperator *bop = dyn_cast<BinaryOperator>(i))
            {
                for (int i=0;i<(int)bop->getNumOperands();i++)
                    worklist.push_back(bop->getOperand(i));
                continue;
            }
            if (ZExtInst* izext = dyn_cast<ZExtInst>(i))
            {
                worklist.push_back(izext->getOperand(0));
                continue;
            }
            if (SExtInst* isext = dyn_cast<SExtInst>(i))
            {
                worklist.push_back(isext->getOperand(0));
                continue;
            }
            //gep in constantexpr?
            if (ConstantExpr* cxpr = dyn_cast<ConstantExpr>(i))
            {
                Instruction *ii = cxpr->getAsInstruction();
                worklist.push_back(cxpr);
                dummyCE[ii] = li->getFunction();
                continue;
            }

            if (isa<GlobalValue>(i) || isa<LoadInst>(i) ||
                isa<AllocaInst>(i) || isa<CallInst>(i))
                continue;
            if (!isa<Instruction>(i))
                continue;
            //what else?
            i->print(errs());
            errs()<<"\n";
            llvm_unreachable("what else?");
        }
    }
    return lots_of_geps;
}

//only care about case where all indices are constantint
void get_gep_indicies(GetElementPtrInst* gep, Indices& indices)
{
    if (!gep)
        return;
    //replace all non-constant with zero
    //because they are literally an array...
    //and we are only interested in the type info
    for (auto i = gep->idx_begin(); i!=gep->idx_end(); ++i)
    {
        ConstantInt* idc = dyn_cast<ConstantInt>(i);
        if (idc)
            indices.push_back(idc->getSExtValue());
        else
            indices.push_back(0);
    }
}

bool function_has_gv_initcall_use(Function* f)
{
    static FunctionSet fs_initcall;
    static FunctionSet fs_noninitcall;
    if (fs_initcall.count(f)!=0)
        return true;
    if (fs_noninitcall.count(f)!=0)
        return false;
    for (auto u: f->users())
        if (GlobalValue *gv = dyn_cast<GlobalValue>(u))
        {
            if (!gv->hasName())
                continue;
            if (gv->getName().startswith("__initcall_"))
            {
                fs_initcall.insert(f);
                return true;
            }
        }
    fs_noninitcall.insert(f);
    return false;
}

void str_truncate_dot_number(std::string& str)
{

    while (isdigit(str.back())) {
        std::size_t found = str.find_last_of('.');
        if (found == std::string::npos)
            break;
        str = str.substr(0,found);
    }
}


//bool is_skip_struct(StringRef str)
//{
//    for (int i=0;i<BUILDIN_STRUCT_TO_SKIP;i++)
//        if (str.startswith(_builtin_struct_to_skip[i]))
//            return true;
//    return false;
//}

/*
 * match a type/indices with known ones
 */
static Value* _get_value_from_composit(Value* cv, Indices& indices)
{
    //cv must be global value
    GlobalVariable* gi = dyn_cast<GlobalVariable>(cv);
    Constant* initializer = dyn_cast<Constant>(cv);
    Value* ret = NULL;
    Value* v;
    int i;
    dbglst.push_back(cv);

    if (!indices.size())
        goto end;

    i = indices.front();
    indices.pop_front();

    if (gi)
        initializer = gi->getInitializer();
    assert(initializer && "must have a initializer!");
    /*
     * no initializer? the member of struct in question does not have a
     * concreat assignment, we can return now.
     */
    if (initializer==NULL)
        goto end;
    if (initializer->isZeroValue())
        goto end;
    v = initializer->getAggregateElement(i);
    assert(v!=cv);
    if (v==NULL)
        goto end;//means that this field is not initialized

    v = v->stripPointerCasts();
    assert(v);
    if (isa<Function>(v))
    {
        ret = v;
        goto end;
    }
    if (indices.size())
        ret = _get_value_from_composit(v, indices);
end:
    dbglst.pop_back();
    return ret;
}

Value* get_value_from_composit(Value* cv, Indices& indices)
{
    Indices i = Indices(indices);
    return _get_value_from_composit(cv, i);
}

/*
 * is this function's address taken?
 * ignore all use by EXPORT_SYMBOL and perf probe trace defs.
 */
bool is_address_taken(Function* f)
{
    bool ret = false;
    for (auto& u: f->uses())
    {
        auto* user = u.getUser();
        if (CallInst* ci = dyn_cast<CallInst>(user))
        {
            //used inside inline asm?
            if (ci->isInlineAsm())
                continue;
            //used as direct call, or parameter inside llvm.*
            if (Function* _f = get_callee_function_direct(ci))
            {
                if ((_f==f) || (_f->isIntrinsic()))
                    continue;
                //used as function parameter
                ret = true;
                goto end;
            }else
            {
                //used as function parameter
                ret = true;
                goto end;
            }
            llvm_unreachable("should not reach here");
        }
        //not call instruction
        ValueList vs;
        ValueSet visited;
        vs.push_back(dyn_cast<Value>(user));
        while(vs.size())
        {
            Value* v = vs.front();
            vs.pop_front();
            if (v->hasName())
            {
               auto name = v->getName();
               if (name.startswith("__ksymtab") || 
                       name.startswith("trace_event") ||
                       name.startswith("perf_trace") ||
                       name.startswith("trace_raw") || 
                       name.startswith("llvm.") ||
                       name.startswith("event_class"))
                   continue;
               ret = true;
               goto end;
            }
            for (auto&u: v->uses())
            {
                auto* user = dyn_cast<Value>(u.getUser());
                if (!visited.count(user))
                {
                    visited.insert(user);
                    vs.push_back(user);
                }
            }
        }
    }
end:
    return ret;
}

bool is_using_function_ptr(Function* f)
{
    bool ret = false;
    for(Function::iterator fi = f->begin(), fe = f->end(); fi != fe; ++fi)
    {
        BasicBlock* bb = dyn_cast<BasicBlock>(fi);
        for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
        {
            if (CallInst *ci = dyn_cast<CallInst>(ii))
            {
                if (Function* f = get_callee_function_direct(ci))
                {
                    //should skip those...
                    if (f->isIntrinsic())
                      continue;
                    //parameters have function pointer in it?
                    for (auto &i: ci->operands())
                    {
                        //if (isa<Function>(i->stripPointerCasts()))
                        if (PointerType *pty = dyn_cast<PointerType>(i->getType()))
                        {
                            if (isa<FunctionType>(pty->getElementType()))
                            {
                                ret = true;
                                goto end;
                            }
                        }
                    }
                    //means that direct call is not using a function pointer
                    //in the parameter
                    continue;
                }else if (ci->isInlineAsm())
                {
                    //ignore inlineasm
                    //InlineAsm* iasm = dyn_cast<InlinAsm>(ci->getCalledValue());
                    continue;
                }else
                {
                    ret = true;
                    goto end;
                }
            }
            //any other use of function is considered using function pointer
            for (auto &i: ii->operands())
            {
                //if (isa<Function>(i->stripPointerCasts()))
                if (PointerType *pty = dyn_cast<PointerType>(i->getType()))
                {
                    if (isa<FunctionType>(pty->getElementType()))
                    {
                        ret = true;
                        goto end;
                    }
                }
            }
        }
    }
end:
    return ret;
}
////////////////////////////////////////////////////////////////////////////////
SimpleSet* skip_vars;
//SimpleSet* skip_funcs;
SimpleSet* crit_syms;
SimpleSet* kernel_api;

void initialize_gatlin_sets(StringRef knob_skip_func_list,
        StringRef knob_skip_var_list,
        StringRef knob_crit_symbol,
        StringRef knob_kernel_api)
{
    llvm::errs()<<"Load supplimental files...\n";
    StringList builtin_skip_functions(std::begin(_builtin_skip_functions),
            std::end(_builtin_skip_functions));
    skip_funcs = new SimpleSet(knob_skip_func_list.str(), builtin_skip_functions);
    if (!skip_funcs->use_builtin())
        llvm::errs()<<"    - Skip function list, total:"<<skip_funcs->size()<<"\n";

    StringList builtin_skip_var(std::begin(_builtin_skip_var),
            std::end(_builtin_skip_var));
    skip_vars = new SimpleSet(knob_skip_var_list.str(), builtin_skip_var);
    if (!skip_vars->use_builtin())
        llvm::errs()<<"    - Skip var list, total:"<<skip_vars->size()<<"\n";

    StringList builtin_crit_symbol;
    crit_syms = new SimpleSet(knob_crit_symbol.str(), builtin_crit_symbol);
    if (!crit_syms->use_builtin())
        llvm::errs()<<"    - Critical symbols, total:"<<crit_syms->size()<<"\n";

    StringList builtin_kapi;
    kernel_api = new SimpleSet(knob_kernel_api.str(), builtin_kapi);
    if (!kernel_api->use_builtin())
        llvm::errs()<<"    - Kernel API list, total:"<<kernel_api->size()<<"\n";
}

////////////////////////////////////////////////////////////////////////////////
SimpleSet *crit_structs = nullptr;
SimpleSet *load_list(StringRef knob_list)
{
    SimpleSet *tmp_list = nullptr;
    llvm::errs()<<"Load list...: " << knob_list << "\n";
    StringList builtin_tmp_struct;
    if (!tmp_list)
        tmp_list = new SimpleSet(knob_list.str(), builtin_tmp_struct);
    else {
        tmp_list->load(knob_list.str());
    }
    llvm::errs() << "    - total: " << tmp_list->size() << "\n";
    return tmp_list;
}
void initialize_crit_struct(StringRef knob_crit_struct_list)
{
    llvm::errs()<<"Load critical struct list...: " << knob_crit_struct_list << "\n";
    StringList builtin_crit_struct(std::begin(_builtin_crit_struct),
                                   std::end(_builtin_crit_struct));
    if (!crit_structs)
        crit_structs = new SimpleSet(knob_crit_struct_list.str(), builtin_crit_struct);
    else {
        crit_structs->load(knob_crit_struct_list.str());
    }
    llvm::errs() << "    - Critical structs, total: " << crit_structs->size() << "\n";
}

SimpleSet *link_structs;
void initialize_link_struct(StringRef knob_link_struct_list)
{
    llvm::errs()<<"Load link struct list...\n";
    StringList builtin_link_struct(std::begin(_builtin_link_struct),
                                   std::end(_builtin_link_struct));
    link_structs = new SimpleSet(knob_link_struct_list.str(), builtin_link_struct);
    llvm::errs() << "    - Link structs, total: " << link_structs->size() << "\n";
}

SimpleSet *alloc_funcs;
void initialize_alloc_func(StringRef knob_alloc_func_list)
{
    llvm::errs()<<"Load alloc functions...\n";
    StringList builtin_alloc_function(std::begin(_builtin_alloc_function),
                                   std::end(_builtin_alloc_function));
    alloc_funcs = new SimpleSet(knob_alloc_func_list.str(), builtin_alloc_function);
    llvm::errs() << "    - Alloc function list, total: " << alloc_funcs->size() << "\n";

}

SimpleSet *free_funcs;
void initialize_free_func(StringRef knob_free_func_list)
{
    llvm::errs()<<"Load free functions...\n";
    StringList builtin_free_function(std::begin(_builtin_free_function),
                                   std::end(_builtin_free_function));
    free_funcs = new SimpleSet(knob_free_func_list.str(), builtin_free_function);
    llvm::errs() << "    - Free function list, total: " << free_funcs->size() << "\n";

}

SimpleSet *skip_funcs;
SimpleSet *mte_skip_funcs;
void initialize_skip_func(StringRef knob_skip_func_list, StringRef knob_mte_skip_func_list)
{
    llvm::errs()<<"Load skip functions...\n";
    StringList builtin_skip_function(std::begin(_builtin_skip_function),
                                   std::end(_builtin_skip_function));
    skip_funcs = new SimpleSet(knob_skip_func_list.str(), builtin_skip_function);
    llvm::errs() << "    - Skip function list, total: " << skip_funcs->size() << "\n";
    //for (auto f : *skip_funcs) {
    //    errs() << "      - " << f << "\n";
    //}
    if (knob_mte_skip_func_list != "") {
        StringList empty;
        llvm::errs()<<"Load mteskip functions...\n";
        StringList builtin_mte_skip(std::begin(_builtin_skip_function), 
                std::begin(_builtin_skip_function));
        mte_skip_funcs = new SimpleSet(knob_mte_skip_func_list.str(), builtin_mte_skip);
        llvm::errs() << "    - MTE Skip function list, total: " << mte_skip_funcs->size() << "\n";
        for (auto f : *mte_skip_funcs) {
            errs() << "      - " << f << "\n";
    }

    }

}

SimpleSet *list_structs;
void initialize_list_struct(StringRef knob_list_struct_list)
{
    llvm::errs()<<"Load list struct list...\n";
    StringList builtin_list_struct(std::begin(_builtin_list_struct),
                                   std::end(_builtin_list_struct));
    list_structs = new SimpleSet(knob_list_struct_list.str(), builtin_list_struct);
    llvm::errs() << "    - List structs, total: " << list_structs->size() << "\n";
    for (auto iter = list_structs->begin(); iter != list_structs->end(); ++iter)
        llvm::errs() << "    - " << *iter << "\n";
}

SimpleSet *kernel_files;
void initialize_kernel_files(StringRef knob_kernel_file_list)
{
    llvm::errs()<<"Load kernel file list...\n";
    if (knob_kernel_file_list != "") {
        kernel_files = new SimpleSet(knob_kernel_file_list.str(), {});
    }
    llvm::errs() << "    - Kernel Files, total: " << kernel_files->size() << "\n";
    for (auto iter = kernel_files->begin(); iter != kernel_files->end(); ++iter)
        llvm::errs() << "    - " << *iter << "\n";
}



void initialize_builtin_sets()
{
    //llvm::errs()<<"Load builtins...\n";

    llvm::errs()<<"Load builtin ignore fields...\n";

//    StringList builtin_alloc_functions(std::begin(_builtin_alloc_functions),
//                                       std::end(_builtin_alloc_functions));
//   alloc_funcs = new SimpleSet(knob_alloc_func_list,builtin_alloc_functions);
//    llvm::errs() << "    - Alloc funciton list, total:" << alloc_funcs->size() << "\n";
}

void initialize_function_code(Module &m, StringRef f)
{
    llvm::errs() << "Load function codes..." << f << "\n";
    if (f == "") {
        return;
    }
    std::ifstream input(f.str());
    std::string line;

    while(std::getline(input, line)) {
        Function* func = m.getFunction(line);
        std::getline(input, line);
        std::string::size_type sz;
        int code = stoi(line, &sz);
        if (!func)
            continue;
        funcCode[code] = func;
    }
}

void initialize_struct_size(Module &m, StringRef f)
{
    llvm::errs() << "Load struct sizes..\n";
    if (f == "")
        return;
    std::ifstream input(f.str());
    std::string line;

    while(std::getline(input, line)) {
        std::string sname = line;
        std::getline(input, line);
        std::string::size_type sz;
        int size = stoi(line, &sz)/8;
        sizes[sname] = size;
    }

}
void initialize_skip_func_indcall(Module &module) {
    ValueSet visited;
    print_debug("initialize_skip_func_indcall");
    for (Module::iterator fi = module.begin(), fe = module.end();
         fi != fe; ++fi) {
        Function *func = dyn_cast<Function>(fi);
        if (is_skip_function(fi->getName().str()))
            continue;
        if (!func)
            continue;
        if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
            continue;

        for(auto &B : *fi) {
            for (auto I = B.begin(), E = B.end(); I != E; ++I) {
                if (!isa<CallInst>(&*I))
                    continue;
                if (!I->hasMetadata("ppac_indcall"))
                    continue;
                Metadata *md = I->getMetadata("ppac_indcall");
                if (!isa<MDNode>(md))
                    continue;
                MDNode *mdn = cast<MDNode>(md);
                md = mdn->getOperand(0).get();
                if (!isa<ValueAsMetadata>(md))
                    continue;

                Value *md_val = cast<ValueAsMetadata>(md)->getValue();
                if (visited.count(md_val))
                    continue;
                visited.insert(md_val);
               
                Constant *ca = cast<Constant>(md_val);
                unsigned num = cast<ArrayType>(ca->getType())->getNumElements();

                ConstantDataArray *cda = cast<ConstantDataArray>(ca);
                bool has_skip = false;
                for (int i=0; i<num; ++i) {
                    uint64_t code = cda->getElementAsInteger(i);
                    Function *ff = get_func_from_code(code);
                    if (!ff)
                        continue;
                    if (is_skip_function(ff->getName().str())) {
                        has_skip = true;
                        print_debug(ff->getName(), nullptr, "skip function used in indcall");
                    }
                }
                if (!has_skip)
                    continue;
                errs() << "[DEBUG] add to skip functions from " << *mdn << "\n";
                for (int i=0; i<num; ++i) {
                    uint64_t code = cda->getElementAsInteger(i);
                    Function *ff = get_func_from_code(code);
                    if (!ff)
                        continue;
                    if (!is_skip_function(ff->getName().str())) {
                        print_debug(ff->getName(), nullptr, "new skip function");
                        skip_funcs->insert(ff->getName().str());
                    }
                }
            }
        }
    }
}
bool get_indirect_call_dest(Instruction *ii, FunctionSet &funcs)
{
    if (!ii->hasMetadata("ppac_indcall"))
        return false;
    Metadata *md = ii->getMetadata("ppac_indcall");
    if (!isa<MDNode>(md))
        return false;
    MDNode *mdn = cast<MDNode>(md);

    md = mdn->getOperand(0).get();
    if (!isa<ValueAsMetadata>(md))
        return false;
    Value *md_val = cast<ValueAsMetadata>(md)->getValue();
    Constant *ca = cast<Constant>(md_val);
    unsigned num = cast<ArrayType>(ca->getType())->getNumElements();

    ConstantDataArray *cda = cast<ConstantDataArray>(ca);
    for (int i=0; i<num; ++i) {
        uint64_t code = cda->getElementAsInteger(i);
        Function *func = get_func_from_code(code);
        if (func && !func->isDeclaration() && !func->isIntrinsic())
            funcs.insert(func);
    }

    return true;
}
Type *get_element_type(StructType *ty, Indices *idx) {

    Type *res_ty = ty;
    auto iter = idx->begin();
    ++iter; // ignore first 0
    for (; iter != idx->end(); ++iter) {
        if (*iter < 0) {
            if (isa<ArrayType>(res_ty))
                res_ty = res_ty->getArrayElementType();
            else
                return nullptr;
        }
        else if (auto sty = dyn_cast<StructType>(res_ty)) {
            if (sty->getNumElements() <= *iter)
                return nullptr;
            res_ty = cast<StructType>(sty)->getElementType(*iter);
        } else if (auto aty = dyn_cast<ArrayType>(res_ty)){
            if (aty->getNumElements() <= *iter)
                return nullptr;
            res_ty = aty->getElementType();
        } else
            return nullptr;
    }
    return res_ty;
}
Function* get_func_from_code(int code) {
    if (funcCode.count(code) != 0)
        return funcCode[code];
    return nullptr;
}
std::string get_func_name(std::string fname)
{
    if (fname.find(".") != std::string::npos)
        return fname.substr(0, fname.find("."));
    return fname;
}
int get_struct_size(StructType *sty) {
    if (sizes.count(sty->getName().str())) {
        return sizes[sty->getName().str()];
    }
    return -1;
}
std::string get_struct_name(std::string tname)
{
    // strip '.XXX' at the last of the name
    if (tname.find_first_of(".") != tname.find_last_of("."))
        return tname.substr(0, tname.find_last_of("."));
    return tname;
}
bool is_asm(Value *v) {
  if (!isa<CallBase>(v))
    return false;
  return cast<CallBase>(v)->isInlineAsm();
}
bool is_asm_get_current(Value *v) {
    if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;

    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.compare("mrs $0, sp_el0") != 0)
        return false;
    return true;
}

// return true if v is asm load and op is the loaded value
bool is_asm_load(Value *v, int op) {
    if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;

    auto asm_op = get_asm_ldval(v);

    if (asm_op > 0 && ((op < 0) || asm_op == op))
        return true;

    return false;
}

// return true if v is asm store and op is the stored value
bool is_asm_store(Value *v, int op) {
    if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;
    auto asm_op = get_asm_stval(v);

    if (asm_op > 0 && ((op < 0) || asm_op == op))
        return true;

    return false;
}

bool is_asm_access(Value *v, int op) {
    if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;
    if (cast<User>(v)->getNumOperands() <= op)
        return false;
    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("// atomic")==0 && op==0)
        return true;
    if (str.find("// cmpxchg_case")==0 && op==0)
        return true;
    if ((is_asm_store(v) || is_asm_load(v)) &&
        (op == get_asm_addr(v)))
        return true;

    //if (str.find("\x09cas") != std::string::npos && op == 0)
    //    return true;

    return false;
}

int get_asm_addr(Value *v) {
    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("// atomic")==0)
        return 0;
    if (str.find("// cmpxchg_case")==0)
        return 0;
    if (str.compare("stlr $1, $0") == 0)
        return 0;
    if (str.compare("stlr ${1:w}, $0") == 0)
        return 0;
    if (str.compare("stlrb ${1:w}, $0") == 0)
        return 0;
    if (str.compare("ldar $0, $1") == 0)
        return 0;
    if (str.compare("ldar ${0:w}, $1") == 0)
        return 0;
    if (str.compare("ldarb ${0:w}, $1") == 0)
        return 0;
    if (str.find("prfm\x09pstl1strm") != std::string::npos)
        return 0;
    if (str.find("\x09ld") != std::string::npos)
        return 0;
    if (str.find("\x09st") != std::string::npos)
        return 0;
    return -1;
}

// get asm loaded value or stored value
int get_asm_ldval(Value *v) {
    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("// atomic")==0)
        return 1000;
    if (str.find("// cmpxchg_case")==0)
        return 1000;
    if (str.find("prfm\x09pstl1strm") != std::string::npos)
        return 1000;
    if (str.find("\x09ld") != std::string::npos)
        return 1000;
    if (str.compare("ldar $0, $1") == 0)
        return 1000;
    if (str.compare("ldar ${0:w}, $1") == 0)
        return 1000;
    if (str.compare("ldarb ${0:w}, $1") == 0)
        return 1000;
    return -1;
}

// get asm loaded value or stored value
int get_asm_stval(Value *v) {
    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("// cmpxchg_case")==0)
        return 2;
    if (str.find("prfm\x09pstl1strm") != std::string::npos)
        return 1;
    if (str.compare("stlr $1, $0") == 0)
        return 1;
    if (str.compare("stlr ${1:w}, $0") == 0)
        return 1;
    if (str.compare("stlrb ${1:w}, $0") == 0)
        return 1;
    if (str.find("\x09st") != std::string::npos)
        return 1;
    return -1;
}

bool is_same_func(Function *f1, Function *f2) {
    if (f1 == f2)
        return true;
    if (get_struct_name(f1->getName().str()) == get_struct_name(f2->getName().str()))
        return true;
    return false;
}
bool is_same_struct(StructType *s1, StructType *s2) {
    if (get_struct_name(s1->getName().str()) == get_struct_name(s2->getName().str()))
        return true;
    else if (!s1->hasName() || !s2->hasName()) {
        if (s1->isLayoutIdentical(s2))
            return true;
        else if ((s1->getNumElements() == s2->getNumElements())) {
            for (int i=0; i<s1->getNumElements(); i++) {
                if (!is_same_type(s1->getElementType(i),
                                  s2->getElementType(i)))
                    return false;
            }
            return true;
        }
    }
    return false;
}

// t1: struct type
// t2: struct pointer type
bool is_same_struct_ptr(Type *t1, Type *t2) {
    PointerType *p2 = dyn_cast<PointerType>(t2);
    if (!p2)
        return false;
    Type *e2 = p2->getElementType();
    StructType *s1 = dyn_cast<StructType>(t1);
    StructType *s2 = dyn_cast<StructType>(e2);
    if (!s1 || !s2)
        return false;
    return is_same_struct(s1, s2);
}

bool is_same_type(Type *t1, Type *t2) {
    if (t1 == t2)
        return true;
   
    if (isa<PointerType>(t1) && isa<PointerType>(t2))
        return is_same_type(t1->getPointerElementType(),
                            t2->getPointerElementType());
    if (isa<StructType>(t1) && isa<StructType>(t2)) {

        StructType *s1 = cast<StructType>(t1);
        StructType *s2 = cast<StructType>(t2);
        if (is_same_struct(s1, s2))
            return true;
    }
    else if (isa<ArrayType>(t1) && isa<ArrayType>(t2)) {
        if (is_same_type(t1->getArrayElementType(),
                         t2->getArrayElementType()))
            return true;
    }
    return false;
}

bool has_type(TypeSet* ts, Type *ty) {
    for (auto tt : *ts) {
        if (is_same_type(tt, ty))
            return true;
    }
    return false;
}

bool is_same_uselist(ValueList *ul1, ValueList *ul2) {
    if (ul1->size() != ul2->size())
        return false;

    auto iter1 = ul1->begin();
    auto iter2 = ul2->begin();
    for(; iter1 != ul1->end() && iter2 != ul2->end();
        ++iter1, ++iter2) {
        if (*iter1 != *iter2)
            return false;
    }
    return true;
}

bool is_redundant(VLSet *vls, ValueList *vl) {
    for (auto _vl : *vls) {
        auto rit = vl->rbegin();
        auto _rit = _vl->rbegin();


        for (; rit != vl->rend() && _rit != _vl->rend(); ++rit, ++_rit) {
            if (*rit != *_rit)
                break;
        }
        if (rit == vl->rend() || _rit == _vl->rend())
            return true;
    }
    return false;
}

int get_inst_count(Function* func, Instruction* ii) {
    int count = 0;
    for (auto iter = inst_begin(func); iter != inst_end(func);
         ++iter) {
        if (iter->isDebugOrPseudoInst())
            continue;
        if (isa<CallInst>(&*iter)) {
          auto fname = get_callee_function_name(&*iter);
          if (fname.startswith("llvm.dbg.value"))
            continue;
        }
        if (&*iter == ii)
            return count;
        count++;
    }
    print_error(ii, func, "no instruction!");
    exit(1);
}

int get_op_count(Function* func, Instruction* ii, unsigned opNum) {
    int count = 0;
    for (auto iter = inst_begin(func); iter != inst_end(func);
         ++iter) {

        if (&*iter == ii)
            return count;
        if (iter->getOpcode() == ii->getOpcode()
            && opNum < iter->getNumOperands() )
            count++;
    }
    print_error(ii, func, "no instruction!");
    exit(1);
}

InstructionSet *get_inst(Value *v, bool debug, Function* func) {
    InstructionSet iset;

    if (isa<Instruction>(v)) {
        iset.insert(cast<Instruction>(v));
        return new InstructionSet(iset);
    }

    ValueSet visited;
    ValueList worklist;
    worklist.push_back(v);

    if (debug) {
        errs() << "  get_inst " << *v;
        if (func)
            errs() << " (" << func->getName() << ")";
        errs() << "\n";
    }
    while(worklist.size()) {
        Value *vv = worklist.front();
        worklist.pop_front();
        if (visited.count(vv))
            continue;
        visited.insert(vv);

        if (isa<Instruction>(vv) &&
            (cast<Instruction>(vv)->getParent() != nullptr)) {
            if (func) {
                if (cast<Instruction>(vv)->getFunction() != func)
                    continue;
            }

            if (debug)
                errs() << "    - " << *vv << "\n";
            iset.insert(cast<Instruction>(vv));
            continue;
        }
        if (isa<ConstantVector>(vv)) {
            if (debug) {
                errs() << "constant vector \n\n";
                VectorType *vt = cast<ConstantVector>(vv)->getType();
                errs() << "  element type: " << *vt->getElementType() << "\n";
                errs() << "  num element: " << vt->getArrayNumElements() << "\n";
                for(auto uu : vv->users())
                    errs() << "  user  : "<< *uu << "\n";
            }
            auto uu = *vv->users().begin();

            if (auto ii = dyn_cast<Instruction>(uu)) {
                if (!ii->getParent())
                    continue;
                if (debug)
                    errs() << "    - " << *ii << "\n";
                iset.insert(ii);
                continue;
            }
        }
        for (auto uu : vv->users()) {
            worklist.push_back(uu);
        }
    }

    if (iset.empty()) {
        if (debug)
            errs() << "[ERROR] no iset!\n";
        return nullptr;
    }
    return new InstructionSet(iset);
}
void dump_func(raw_fd_ostream &out, Function *func)
{
    out << "func    : " << get_func_name(func->getName().str()) << "\n";

}
void dump_inst(raw_fd_ostream &out, Instruction *i)
{
    std::string src_ty = "i";
    src_ty = src_ty.append(std::to_string(get_inst_count(i->getFunction(),i)));
    src_ty = src_ty.append("-");
    src_ty = src_ty.append(std::to_string(i->getOpcode()));
    src_ty = src_ty.append("-");
    src_ty = src_ty.append(std::to_string(get_op_count(i->getFunction(), i)));

    out << "src  [" << src_ty << "]: ";
    out << *i << "\n";

}

// detach constantexpr & return the list of users
// NOTE: constant expr used in different instructions should be
//  detached for each.
// TODO: detach can be done on 1-level ce?
InstructionSet *detach_constant_expr(ConstantExpr *ce, Function *func,
                                     CE2FISet &ce2fimap) {
    Function2ChkInst *fimap = nullptr;
    InstructionSet *users = nullptr;
    // check if ce is already detached in this function.
    if (ce2fimap.count(ce)) {
        fimap = ce2fimap[ce];
        if (fimap) {
            for (auto m : *fimap) {
                if (m.first == func) {
                    if (m.second) {
                        users = m.second;
                        if (users->size()>0) {
                            return users;
                        }
                    }
                }
            }
        }
    }
    if (!fimap) {
        fimap = new Function2ChkInst;
        ce2fimap[ce] = fimap;
    }
    if (!users) {
        users = new InstructionSet;
        fimap->insert(std::make_pair(func, users));
    }
    InstructionSet *iset = get_inst(ce, false, func);
    if (!iset) {
        print_error(ce, func, "can't get iset from ce!");
        return nullptr;
    }
    if (iset->empty()) {
        print_error(ce, func, "can't get iset from ce!");
        return nullptr;
    }

    InstructionSet *new_set = ce2fi_new[ce];
    if (!new_set) {
        new_set = new InstructionSet;
        ce2fi_new[ce] = new_set;
    }

    bool debug = false;
    //print_debug(ce, func, "detach constant expr");
    InstructionSet expandSet;
    for (auto insert : *iset) {
        bool has_new = false;
        for (auto ni :*users) {
            if (ni->getParent() == insert->getParent()) {
                has_new = true;
                break;
            }
        }
        if (has_new)
            continue;

        // create a new constantexpr for each basic block.
        Instruction *ceI = cast<ConstantExpr>(ce)->getAsInstruction();
        IRBuilder<> builder(insert);
        builder.SetInsertPoint(&*insert->getParent()->getFirstInsertionPt());
        Value *vv = builder.Insert(ceI);
        users->insert(cast<Instruction>(vv));
        new_set->insert(cast<Instruction>(vv));
    }

    InstructionSet userset;

    for (auto insert : *iset) {
        bool direct = false;
        for (int i=0; i<insert->getNumOperands(); ++i)
            if (insert->getOperand(i) == ce)
                direct = true;
        if (direct){
            userset.insert(insert);
        }
        else {
            expandSet.insert(insert);
        }
    }
    delete iset;

    for (auto ii : userset) {
        Value *new_ce = nullptr;
        for (auto ni : *users) {
            if (ni->getParent() == ii->getParent()) {
                new_ce = ni;
                break;
            }
        }
        if (!new_ce)
            //should never happen
            continue;

        for (int i=0; i<ii->getNumOperands(); ++i)
            if (ii->getOperand(i) == ce)
                ii->setOperand(i, new_ce);
    }

    // now expand instructions in expandset
    // : should detach all constantexpr chains

    for (auto ei : expandSet) {
        Value *new_ce = nullptr;
        for (auto ni : *new_set) {
            if (ni->getParent() == ei->getParent()) {
                new_ce = ni;
                break;
            }
        }
        if (!new_ce)
            // should not happen
            continue;
        if (detach_constant_expr_recur(ce, new_ce, ei, ce2fimap))
            users->insert(ei);
    }

    if (debug)
        errs() <<"~~~~~ DEBUG ~~~~~" << *func << "\n";

    return users;
}

bool detach_constant_expr_recur(ConstantExpr *ce, Value *new_ce,
                                Instruction *base, CE2FISet &ce2fimap) {
    bool res = false;
    bool debug = false;
    //if (debug)
        //print_debug(base, base->getFunction(), "detach_recursive");
        //print_debug(new_ce);
    for (int i=0; i<base->getNumOperands(); ++i) {
        Value *op = base->getOperand(i);
        if (!isa<ConstantExpr>(op)) {
            continue;
        }
        ValueSet visited;
        visited.clear();
        if (op == ce) {
            //print_debug(op, base->getFunction(), "detach_recur set op");
            base->setOperand(i, new_ce);
            res |= true;
            //errs() << "\n~~ DEBUG ~~\n";
            //errs() << *base->getParent() << "\n";
            continue;
        }

        if (!is_use_def_recur(cast<User>(op), ce, &visited)) {
            continue;
        }
        //print_debug(op, base->getFunction(), "detach_recur set op");

        Function2ChkInst *fimap = nullptr;
        InstructionSet *users = nullptr;
        if (ce2fimap.count(cast<ConstantExpr>(op))) {
            fimap =  ce2fimap[cast<ConstantExpr>(op)];
            if (fimap) {
                for (auto m : *fimap) {
                    if (m.first == base->getFunction()) {
                        users = m.second;
                    }
                }
            }
        }
        if (!fimap) {
            fimap = new Function2ChkInst;
            ce2fimap[cast<ConstantExpr>(op)] = fimap;
        }
        if (!users) {
            users = new InstructionSet;
            fimap->insert(std::make_pair(base->getFunction(), users));
        }

        InstructionSet *new_set = ce2fi_new[cast<ConstantExpr>(op)];
        if (!new_set) {
            new_set = new InstructionSet;
            ce2fi_new[cast<ConstantExpr>(op)] = new_set;
        }

        bool has_new = false;
        for (auto ii : *new_set) {
            if (ii->getParent() == base->getParent()) {
                base->setOperand(i, ii);
                has_new |= true;
                break;
            }
        }
        if (has_new)
            continue;

        IRBuilder<> builder(cast<Instruction>(new_ce)->getNextNode());
        Value *nv =
            builder.Insert(cast<ConstantExpr>(op)->getAsInstruction());
        base->setOperand(i, nv);
        users->insert(base);
        new_set->insert(cast<Instruction>(nv));
        //errs() << "\n~~ DEBUG ~~\n";
        //errs() << *base->getParent() << "\n";

        res |= detach_constant_expr_recur(
            ce, new_ce, cast<Instruction>(nv), ce2fimap);
    }
    return res;
}
bool bb_can_reach(BasicBlock *s, BasicBlock *d, BasicBlockSet *visited) {
    if (s == d)
        return true;
    if (visited->count(d))
        return false;
    visited->insert(d);
    for (auto bb : predecessors(d)) {
        if (bb_can_reach(s, bb, visited))
            return true;
    }
    return false;
}
bool bb_can_reach(BasicBlock *s, BasicBlock *d) {
    if (s == d)
        return true;
    BasicBlock *bb;
    while(bb = d->getSinglePredecessor()) {
        if (bb == s)
            return true;
    }
    return false;
}
bool is_use_def(User *u, Value *d) {
    //errs() << "use-def \nuser:" << *u << "\ndef: " << *d << "\n";
    for (auto &op : u->operands()) {
        if (op == d)
            return true;
    }
    return false;
}
bool is_use_def_recur(User*u, Value*d, ValueSet *visited) {
    if (visited->count(u)>0)
        return false;
    visited->insert(u);
    //errs() << "is_use_def_recur: " << *u << " && " << *d << "\n";
    for (auto &op : u->operands()) {
        if (op == d)
            return true;
        if (auto ce = dyn_cast<ConstantExpr>(op)) {
            if (is_use_def_recur(ce, d, visited))
                return true;
        }
    }
    return false;
}
bool is_list_ptr(Type *ty) {
    if (!isa<PointerType>(ty))
        return false;
    if (!isa<StructType>(ty->getPointerElementType()))
        return false;
    std::string name = get_struct_name(
        cast<StructType>(ty->getPointerElementType())->getName().str());
    for (int i=0; i<BUILTIN_LIST_STRUCTURE_SIZE; i++) {
        if (_builtin_list_struct[i] == name)
            return true;
    }
    return false;
}
bool is_alloc_inst(Value *v) {
    if (isa<CastInst>(v))
        return is_alloc_inst(cast<User>(v)->getOperand(0));
    if (!isa<CallInst>(v))
        return false;
    if (is_alloc_function(get_callee_function_name(cast<Instruction>(v)).str()))
        return true;
    if (is_free_function(get_callee_function_name(cast<Instruction>(v)).str()))
        return true;
    return false;
}
bool is_alloc_inst(Value *v, ValueSet *visited) {
    if (visited->count(v))
        return false;
    visited->insert(v);
    if (isa<CastInst>(v))
        return is_alloc_inst(cast<User>(v)->getOperand(0), visited);
    if (isa<PHINode>(v)) {
        if (is_alloc_inst(cast<User>(v)->getOperand(0), visited))
            return true;
        return false;
    }
    if (!isa<CallInst>(v))
        return false;
    if (is_alloc_function(get_callee_function_name(cast<Instruction>(v)).str()))
        return true;
    if (is_free_function(get_callee_function_name(cast<Instruction>(v)).str()))
      return true;
    return false;
}


void dump_use(llvm::raw_fd_ostream &out, Value *v) {
    std::string ty;
    ty = isa<Argument>(v) ? "a" :
        isa<GlobalVariable>(v) ? "g" :
        isa<ConstantExpr>(v) ? "c" :
        isa<Instruction>(v) ? "i" :
        "?";
    if (isa<Instruction>(v)) {
        ty = ty.append(
            std::to_string(get_inst_count(cast<Instruction>(v)->getFunction(),
                                          cast<Instruction>(v))));
        ty = ty.append("-");
        ty = ty.append(
                std::to_string(cast<Instruction>(v)->getOpcode()));
        ty = ty.append("-");
        ty = ty.append(std::to_string(
                               get_op_count(cast<Instruction>(v)->getFunction(),
                                            cast<Instruction>(v))));
    }
    out << "[" << ty << "]: ";
    if (isa<GlobalVariable>(v))
        out << cast<GlobalVariable>(v)->getName() << "\n";
    else
        out << *v << "\n";
}
void dump_uselist(llvm::raw_fd_ostream &out, ValueList *ul) {
    out << "ul   [" << ul->size() << "]:\n";
        for (auto u : *ul){
            dump_use(out, u);
        }
}
void dump_indices(llvm::raw_fd_ostream &out, Indices &idx) {
    for (auto i : idx) {
        out << i << " ";
    }
    out << "\n";
}
void print_error(StringRef v, Function *func, StringRef msg) {
    errs() << "[ERROR] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    errs() << v << "\n";
}
void print_report(StringRef v, Function *func, StringRef msg) {
    errs() << "[REPORT] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    errs() << v << "\n";
}
void print_debug(StringRef v, Function *func, StringRef msg) {
    errs() << "[DEBUG] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    errs() << v << "\n";
}
void print_error(Value *v, Function *func, StringRef msg) {
    errs() << "[ERROR] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    else {
        if (auto ii = dyn_cast<Instruction>(v)) {
            if (ii->getParent()) {
                if (ii->getFunction())
                    errs() << ii->getFunction()->getName() << ": ";
            }
        }
    }
    errs() << *v << "\n";
}
void print_report(Value *v, Function *func, StringRef msg) {
    errs() << "[REPORT] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    else {
        if (auto ii = dyn_cast<Instruction>(v)) {
            if (ii->getParent()) {
                if (ii->getFunction())
                    errs() << ii->getFunction()->getName() << ": ";
            }
        }
    }
    errs() << *v << "\n";
}
void print_debug(Value *v, StringRef msg) {
    errs() << "[DEBUG] ";
    if (msg != "")
        errs() << msg << " - ";
    if (auto arg = dyn_cast<Argument>(v)) {
        errs() << arg->getParent()->getName() << ": ";
    } else if (auto ii = dyn_cast<Instruction>(v)) {
        if (ii->getParent()) {
            if (ii->getFunction())
                errs() << ii->getFunction()->getName() << ": ";
        }
    }
    if (isa<GlobalVariable>(v))
        errs() << v->getName() << "\n";
    else
        errs() << *v << "\n";
}

void print_debug(Value *v, Function *func, StringRef msg) {
    errs() << "[DEBUG] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    else {
        if (auto arg = dyn_cast<Argument>(v)) {
            errs() << arg->getParent()->getName() << ": ";
        } else if (auto ii = dyn_cast<Instruction>(v)) {
            if (ii->getParent()) {
                if (ii->getFunction())
                    errs() << ii->getFunction()->getName() << ": ";
            }
        }
    }
    if (isa<GlobalVariable>(v))
        errs() << v->getName() << "\n";
    else
        errs() << *v << "\n";
}
void print_error(Value *v, StringRef msg) {
    errs() << "[ERROR] ";
    if (msg != "")
        errs() << msg << " - ";
    if (auto arg = dyn_cast<Argument>(v)) {
        errs() << arg->getParent()->getName() << ": ";
    } else if (auto ii = dyn_cast<Instruction>(v)) {
        if (ii->getParent()) {
            if (ii->getFunction())
                errs() << ii->getFunction()->getName() << ": ";
        }
    }
    if (isa<GlobalVariable>(v))
        errs() << v->getName() << "\n";
    else
        errs() << *v << "\n";
}

void print_error(Type *v, Function *func, StringRef msg) {
    errs() << "[ERROR] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    if (isa<StructType>(v))
        errs() << v->getStructName() << "\n";
    else
        errs() << *v << "\n";
}
void print_report(Type *v, Function *func, StringRef msg) {
    errs() << "[REPORT] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    if (isa<StructType>(v))
        errs() << v->getStructName() << "\n";
    else
        errs() << *v << "\n";
}
void print_debug(Type *v, Function *func, StringRef msg) {
    errs() << "[DEBUG] ";
    if (msg != "")
        errs() << msg << " - ";
    if (func)
        errs() << func->getName() << ": ";
    if (v == nullptr)
        errs() << "nullptr\n";
    else if (isa<StructType>(v))
        errs() << v->getStructName() << "\n";
    else
        errs() << *v << "\n";
}


void dump_uselist(Function *func, ValueList &uselist, InstFuncMap &dummyCE) {
    Value *prev = nullptr;
    int count = 0;
    for (auto ui : uselist) {
        Instruction *ii;
        if (isa<ConstantExpr>(ui)) {
            ii = cast<ConstantExpr>(ui)->getAsInstruction();
            dummyCE[ii] = func;
        }
        else if (isa<Argument>(ui)){
            errs() << "arg";
            goto next;
        }
        else if (isa<GlobalVariable>(ui)) {
            errs() << "gv";
            goto next;
        }
        else
            ii = cast<Instruction>(ui);

        errs() << ii->getOpcodeName();
        if (isa<StoreInst>(ii)) {

            // prev == store destination
            if (prev == ii->getOperand(0))
                errs() << "_src";
            // prev == store source
            else
                errs() << "_dst";
        }
next:
        prev = ui;
        count++;
        if (count != uselist.size())
            errs() << " => ";
    }
    errs() << "\n";
}

void dump_list(Function *func, ValueList &list) {
    errs() << "    Function " << func->getName() << "\n";
    for (auto v : list) {
        errs() << "      " << *v << "\n";
    }
}

bool is_err_check(Value *v) {
    if (!isa<ICmpInst>(v))
        return false;

    auto icmp = cast<ICmpInst>(v);
    auto pr = icmp->getPredicate();
    if(pr != CmpInst::ICMP_UGT && pr != CmpInst::ICMP_EQ && pr != CmpInst::ICMP_SLT)
        return false;

    Value *cv = icmp->getOperand(1)->stripPointerCasts();
    if (!isa<Constant>(cv))
        return false;

    if (auto ce = dyn_cast<ConstantExpr>(cv)) {
        if (ce->getOpcode() == Instruction::IntToPtr)
            cv = ce->getOperand(0);
    }

    if (!isa<ConstantInt>(cv) && !isa<ConstantPointerNull>(cv)
        && !cast<Constant>(cv)->isZeroValue())
        return false;

    return true;
}
ICmpInst *get_err_check(Value *ii) {
    for (auto u : ii->users()) {
        if (is_err_check(u))
            return cast<ICmpInst>(u);
    }
    return nullptr;
}

bool is_err_bb(BasicBlock *prev, BasicBlock *cur) {
  auto succ = prev->getUniqueSuccessor();
  auto pred = prev->getUniquePredecessor();

  // single successor, single predecessor
  if (succ && pred)
    return is_err_bb(pred, prev);

  // multiple predecessor
  else if (!pred) {
    auto termI = prev->getTerminator();
    if (isa<BranchInst>(termI))
        if (is_err_check(termI->getOperand(0)))
            return true;
  }

  return false;
}


bool is_err_phi(Value *op, BasicBlock *dst) {
  if (!isa<Instruction>(op))
    return false;
  auto check = get_err_check(cast<Instruction>(op));
  if (!check) {
    if (auto ci = dyn_cast<CastInst>(op)) {
      auto next = ci->getOperand(0);
      if (auto ni = dyn_cast<Instruction>(next)) {
        if (ni->getParent() == ci->getParent())
          return is_err_phi(ni, dst);
        if (ci->getParent()->getSinglePredecessor())
          return is_err_phi(ni, ci->getParent());
      }
    }
  } else {
    BasicBlock *errorBB;
    BranchInst *bi = nullptr;
    for (auto u : check->users()) {
      if (isa<BranchInst>(u)) {
        bi = dyn_cast<BranchInst>(u);
        break;
      }
    }
    if (!bi)
      return false;
    if (check->getPredicate() == CmpInst::ICMP_SLT) {
      errorBB = bi->getSuccessor(1);
    } else {
      errorBB = bi->getSuccessor(0);
    }
    if (errorBB == dst)
      return true;
  }
  return false;
}



////////////////////////////////////////////////////////////////////////////////
void dump_callstack(InstructionList& callstk)
{
    errs()<<ANSI_COLOR_GREEN<<"Call Stack:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;

    for (auto* I: callstk)
    {
        errs()<<""<<cnt<<" "<<I->getFunction()->getName()<<" ";
        I->getDebugLoc().print(errs());
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

bool dump_a_path_worker(std::vector<BasicBlock*> &bbl, Function* f, BasicBlockSet& visited)
{
    BasicBlock* bb = bbl.back();
    if (bb==&f->getEntryBlock())
        return true;
    auto I = pred_begin(bb);
    auto E = pred_end(bb);
    for (;I!=E;++I)
    {
        if (visited.find(*I)!=visited.end())
            continue;
        visited.insert(*I);
        bbl.push_back(*I);
        if (dump_a_path_worker(bbl, f, visited))
            return true;
        bbl.pop_back();
    }
    return false;
}

void dump_a_path(InstructionList& callstk)
{
    errs()<<ANSI_COLOR_GREEN<<"Path: "<<ANSI_COLOR_RESET<<"\n";

    std::vector<std::vector<Instruction*>> ill;
    for (auto cI = callstk.rbegin(), E=callstk.rend(); cI!=E; ++cI)
    {
        Instruction* I = *cI;
        BasicBlockSet visited;
        std::vector<BasicBlock*> bbl;
        std::vector<Instruction*> il;
        Function* f = I->getFunction();
        //errs()<<f->getName()<<":";
        //trace back till we reach the entry point of the function
        bbl.push_back(I->getParent());
        dump_a_path_worker(bbl, f, visited);
        //print instructions from ebb till the end
        for (auto bI = bbl.rbegin(), bE = bbl.rend(); bI!=bE; ++bI)
        {
            BasicBlock* bb = *bI;
            for (BasicBlock::iterator ii = bb->begin(), ie = bb->end(); ii!=ie; ++ii)
            {
                Instruction *i = dyn_cast<Instruction>(ii);
                if (CallInst *ci = dyn_cast<CallInst>(ii))
                    if (Function* cf = ci->getCalledFunction())
                        if (cf->getName().startswith("llvm."))
                            continue;
                il.push_back(i);
                if (i==I)
                    break;
            }
        }
        ill.push_back(il);
    }
    for (unsigned int i=0;i<ill.size();i++)
    {
        auto& il = ill[i];
        Function* f = il[0]->getFunction();
        auto fname = f->getName();
        errs()<<"Function:"<<fname<<"\n";
        for (unsigned int j = 0;j<il.size();j++)
        {
            il[j]->print(errs());
            errs()<<"\n";
        }
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

void dump_dbgstk(InstructionList& dbgstk)
{
    errs()<<ANSI_COLOR_GREEN<<"Process Stack:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;

    for (auto* I: dbgstk)
    {
        errs()<<""<<cnt<<" "<<I->getFunction()->getName()<<" ";
        I->getDebugLoc().print(errs());
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

void dump_gdblst(ValueList& list)
{
    errs()<<ANSI_COLOR_GREEN<<"Process List:"<<ANSI_COLOR_RESET<<"\n";
    int cnt = 0;
    for (auto* I: list)
    {
        errs()<<"  "<<cnt<<":";
        if (Function*f = dyn_cast<Function>(I))
            errs()<<f->getName();
        else
        {
            I->print(errs());
            if (Instruction* i = dyn_cast<Instruction>(I))
            {
                errs()<<"  ";
                i->getDebugLoc().print(errs());
            }
        }
        errs()<<"\n";
        cnt++;
    }
    errs()<<ANSI_COLOR_GREEN<<"-------------"<<ANSI_COLOR_RESET<<"\n";
}

bool is_alloc(Value *v) {
    if (isa<AllocaInst>(v)) {
      return true;
    }
    if (!isa<CallInst>(v))
      return false;
    if (is_alloc_function(get_callee_function_name(cast<CallInst>(v)).str()))
        return true;
    return false;
}
bool is_builtin_container_of(Instruction *i) {
    if (!isa<CallInst>(i)) return false;
    auto fname = get_callee_function_name(i);

    if (fname.contains("builtin_container_of"))
        return true;
    return false;
}

void get_call_dest(Value *v, FunctionSet &funcs)
{
    if (!isa<CallInst>(v))
        return;
    auto ci = cast<CallInst>(v);
    if (auto f = get_callee_function_direct(ci)) {
      auto fname = f->getName();
      if (fname=="blocking_notifier_call_chain" ||
          fname=="raw_notifier_call_chain" ||
          fname=="atomic_notifier_call_chain" ||
          fname=="srcu_notifier_call_chain") {
        try_get_notifier_call(ci, &funcs);
        return;
      }
      funcs.insert(f);
      return;
    }
    auto fname = ci->getFunction()->getName();
    if (fname.startswith("security")) {
        try_get_security_hook(ci, &funcs);
        return;
    }
    if (get_indirect_call_dest(ci, funcs))
        return;
}

void collect_notifier_registers(Module *m, InstructionSet *registers) {
 for (Module::iterator fi = m->begin(), fe = m->end();
      fi != fe; ++fi) {
   Function *func = dyn_cast<Function>(fi);
   if (!func)
     continue;
   if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
     continue;
   for(auto &B : *func) {
     for (auto I = B.begin(), E = B.end(); I != E; ++I) {
       if (!isa<CallInst>(&*I))
         continue;
       auto fname = get_callee_function_name(&*I).str();
       if (fname=="blocking_notifier_call_register" ||
           fname=="raw_notifier_call_register" ||
           fname=="atomic_notifier_call_register" ||
           fname=="srcu_notifier_call_register") {
         registers->insert(&*I);
       }
     }
   }
 }
}
void try_get_notifier_call(Instruction *i, FunctionSet *_funcs) {
  static InstructionSet registers;
  static Inst2Func i2f;
  Constant *nhv = nullptr;
  StructType *nhty = nullptr;
  bool nested = true;
  ValueList nbs;
  FunctionSet *funcs;
  Module *m = i->getModule();
  if (i2f.count(i)) {
    for (auto f : *(i2f[i])) {
      _funcs->insert(f);
    }
    return;
  } else {
    funcs = new FunctionSet;
    i2f[i] = funcs;
  }

  if (registers.empty()) {
    collect_notifier_registers(m, &registers);
  }

  // find the notifier head
  auto v = cast<CallInst>(i)->getArgOperand(0)->stripPointerCasts();
  if (isa<GlobalVariable>(v)) {
    nhv = cast<Constant>(v);
  } else {
    while (true) {
      if (isa<LoadInst>(v)) {
        v = cast<User>(v)->getOperand(0);
        nested=false;
      } else {
        break;
      }
    }
    if (isa<GetElementPtrInst>(v)) {
      nhty = get_pstr_type(m, cast<User>(v)->getOperand(0)->getType());
    }
  }
  if (!nhv && !nhty)
    return;

  // find the notifier block

  // notifier head is a global variable
  if (nhv) {
      ValueSet gv = {nhv};
      for (auto i : registers) {
          auto arg = cast<CallInst>(i)->getArgOperand(0);
          if (is_global(arg, &gv)) {
              nbs.push_back(cast<CallInst>(i)->getArgOperand(1));
          }
      }
  } else { // notifier head is from a struct object
    for (auto i : registers) {
      auto v = cast<CallInst>(i)->getArgOperand(0);
      if (!nested) {
        // find load - gep
        if (isa<LoadInst>(v)) {
          v = cast<User>(v)->getOperand(0);
        } else {
          continue;
        }
      }
      if (isa<GetElementPtrInst>(v)) {
        v = cast<User>(v)->getOperand(0);
        if (auto sty = get_pstr_type(m, v->getType())) {
          if (sty == nhty) {
            nbs.push_back(cast<CallInst>(i)->getArgOperand(1));
          }
        }
      } else {
        continue;
      }
    }
  }

  while (nbs.size()) {
    auto nb = nbs.back();
    nbs.pop_back();
    if (isa<Argument>(nb)) {
      auto func = cast<Argument>(nb)->getParent();
      int argno = cast<Argument>(nb)->getArgNo();
      for (auto u : func->users()) {
        if (!isa<CallInst>(u))
          continue;
        nbs.push_back(cast<CallInst>(u)->getArgOperand(argno));
      }
    } else if (auto gv = dyn_cast<GlobalVariable>(nb)) {
      auto base = gv->getInitializer();
      if (auto cb = dyn_cast<Function>(base->getAggregateElement(unsigned(0))))
        funcs->insert(cb);
    } else if (auto gep = dyn_cast<GetElementPtrInst>(nb)) {
      ValueSet strset;
      std::set<unsigned> skipset={Instruction::Call, Instruction::Ret};
      collect_forward(gep, Instruction::Store, 1, &skipset, &strset);
      for (auto s : strset) {
        if (auto cb = dyn_cast<Function>(cast<User>(s)->getOperand(0)))
          funcs->insert(cb);
      }
    }
  }

  for (auto f : *funcs) {
    _funcs->insert(f);
  }

}
void try_get_security_hook(Instruction *i, FunctionSet* funcs) {
  static std::map<Value*, FunctionSet*> val2hooks;
  auto smack_hooks = i->getModule()->getNamedValue("smack_hooks");
  if (!smack_hooks)
      return;

  if (val2hooks.count(i)) {
    auto _funcs = val2hooks[i];
    if (!_funcs)
      return;
    *funcs = *_funcs;
    return;
  }

  FunctionSet *_funcs = nullptr;;
  Value *op = cast<CallInst>(i)->getCalledOperand();
  if (!op)
    return;
  if (!isa<LoadInst>(op))
    return;
  ValueSet visited, srcset;
  int hookid = -1;

  Value *src = cast<User>(op)->getOperand(0);
  backward_find_sty(src, &visited, &srcset);
  for (auto s : srcset) {
    if (!isa<GetElementPtrInst>(s))
      continue;
    auto sty = get_pstr_type(i->getModule(), cast<User>(s)->getOperand(0)->getType());
    if (!sty)
      continue;
    if (get_struct_name(sty->getStructName().str())
        == "struct.security_hook_list") {
      ValueSet _srcset;
      ValueSet callset;
      visited.clear();

      backward(src, &visited, &_srcset, &callset);

      for (auto s : _srcset) {
        if (auto ld = dyn_cast<LoadInst>(s)) {
          Value *gep = ld->getOperand(0);
          if (isa<ConstantExpr>(gep))
            gep = cast<ConstantExpr>(gep)->getAsInstruction();
          if (cast<User>(gep)->getNumOperands() < 3)
            continue;
          Value *ival = cast<User>(gep)->getOperand(2);
          hookid = cast<ConstantInt>(ival)->getZExtValue();
        }
      }
    }
  }
  if (hookid >= 0) {
    auto init = cast<GlobalVariable>(smack_hooks)->getInitializer();
    _funcs = new FunctionSet;
    for (unsigned i=0; i<cast<StructType>(init->getType())->getNumElements(); ++i) {
      Constant *entry = init->getAggregateElement(i);
      if (!entry)
        continue;
      if (!isa<ConstantStruct>(entry)) {
        continue;
      }

      auto head = cast<User>(entry->getAggregateElement(1));
      auto hook = cast<User>(entry->getAggregateElement(2));
      if (isa<ConstantExpr>(head)) {
        head = cast<ConstantExpr>(head)->getAsInstruction();
        head = cast<User>(head->stripPointerCasts());
      }
      int off = cast<ConstantInt>(head->getOperand(1))->getZExtValue();
      if (off != hookid*8)
        continue;
      _funcs->insert(cast<Function>(hook->getOperand(0)));
    }
  }

  val2hooks[i] = _funcs;
  if (_funcs)
    *funcs = *_funcs;
}

Type *get_type(Module *m, Type *ty) {
    Type *sty = ty;
    int ptr_cnt = 0;
    while (isa<PointerType>(sty)) {
        sty = sty->getPointerElementType();
        ptr_cnt++;
    }
    if (!isa<StructType>(sty))
        return ty;
    if (sty->getStructName().startswith("struct.anon") ||
        sty->getStructName().startswith("union.anon"))
      return ty;

    auto sname = get_struct_name(sty->getStructName().str());
    Type *resTy = nullptr;
    resTy = StructType::getTypeByName(m->getContext(), sname);
    if (!resTy)
        return ty;
    if (cast<StructType>(sty)->getNumElements() !=
        cast<StructType>(resTy)->getNumElements())
      return ty;
    for (int i=0; i<ptr_cnt; ++i) {
        resTy = resTy->getPointerTo();
    }
    return resTy;
}

StructType *get_pstr_type(Module *m, Type *ty) {
    if (isa<PointerType>(ty)) {
        if (isa<StructType>(ty->getPointerElementType())) {
            if (ty->getPointerElementType()->getStructName().startswith("struct.atomic_t"))
                return nullptr;
            return cast<StructType>(get_type(m, ty->getPointerElementType()));
        }
    }
    return nullptr;
}
bool is_list_struct(Type *ty) {
    Type *elemTy = stripPointerType(ty);
    if (!isa<StructType>(elemTy))
        return false;
    if (!list_structs->exists(get_struct_name(
                                  cast<StructType>(elemTy)->getName().str())))
        return false;
    return true;
}

void backward_find_sty(Value *_v, ValueSet *visited,
                            ValueSet *srcset, ValueSet *ldset,
                            ValueSet *callset) {
  ValueList worklist;
  if (visited->count(_v))
    return;

  worklist.push_back(_v);

  while (worklist.size()) {

  Instruction *ii = nullptr;
  Value *v = worklist.back();
  worklist.pop_back();
  if (visited->count(v))
    continue;
  visited->insert(v);

  if (auto arg = dyn_cast<Argument>(v)) {
    if (!callset)
      continue;
    for (auto c : *callset) {
      auto ci = dyn_cast<CallInst>(c);
      FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
          if (callee == arg->getParent()) {
            worklist.push_back(ci->getArgOperand(arg->getArgNo()));
            continue;
          }
        }
    }
    continue;
  } else if (isa<Instruction>(v)) {
    ii = cast<Instruction>(v);
  }
  else if (isa<ConstantExpr>(v)) {
    ii = cast<ConstantExpr>(v)->getAsInstruction();
  }

  if (!ii)
    continue;

  if (auto sty = get_pstr_type(ii->getModule(), ii->getType())) {
    if (!is_list_struct(sty)) {
      srcset->insert(v);
    }
  }

  for (auto u : ii->users()) {
    if (!isa<CastInst>(u))
      continue;
    if (auto sty = get_pstr_type(ii->getModule(), u->getType())) {
      if (!is_list_struct(sty))
        srcset->insert(u);
    }
  }

  switch(ii->getOpcode()) {
    case Instruction::Alloca: {
      srcset->clear();
      if (ldset)
        ldset->clear();
      return;
    }
    case Instruction::GetElementPtr: {
      if (auto sty = get_pstr_type(ii->getModule(), ii->getOperand(0)->getType())) {
        if (!is_list_struct(sty)) {
          srcset->insert(v);
        }
      }
      worklist.push_back(ii->getOperand(0));
      break;
    }
    case Instruction::Call:
      if (is_builtin_container_of(ii)) {
        if (get_callee_function_name(ii) == "make_kuid")
          worklist.push_back(ii->getOperand(1));
        else
          worklist.push_back(ii->getOperand(0));
      } else if (auto callee = get_callee_function_direct(ii)) {
        if (!callee->hasName() &&
            !callee->isDeclaration() && !callee->isIntrinsic())
            continue;
        if (is_alloc_function(callee->getName().str())) {
          if (ldset)
            ldset->insert(v);
        } else if (is_skip_function(callee->getName().str())) {
          break;
        } else {
        if (callee->size()==0)
            continue;
          worklist.push_back(callee->back().getTerminator());
        }
      }
      break;

    case Instruction::Select:
      worklist.push_back(ii->getOperand(1));
      worklist.push_back(ii->getOperand(2));
      break;

    case Instruction::Load:
      if (ldset)
        ldset->insert(v);
      break;

    case Instruction::PHI:
    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::Add:
    case Instruction::And:
    case Instruction::Sub:
    case Instruction::Xor:
    case Instruction::Or:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
    case Instruction::Ret:
      for (unsigned i=0; i<ii->getNumOperands(); ++i)
        worklist.push_back(ii->getOperand(i));
      break;

    default:
      break;

  } // switch
  } // while

  return;
}


void backward(Value *_v, ValueSet *visited, ValueSet *srcset,
        ValueSet *callset, ValueList *uselist, bool (*skip_func)(Value*)) {

  ValueList worklist;
  worklist.push_back(_v);

  while (worklist.size()) {
    Instruction *ii = nullptr;
    Value *v = worklist.back();
    worklist.pop_back();
    if (!v)
      continue;
    if (visited->count(v)) {
      continue;
    }
    if (skip_func) {
        if (skip_func(v))
            continue;
    }

    visited->insert(v);

    if (uselist)
      if (std::find(uselist->begin(), uselist->end(), v) != uselist->end())
        continue;

    if (isa<Instruction>(v)) {
      ii = cast<Instruction>(v);
    } else if (isa<ConstantExpr>(v)) {
      ii = cast<ConstantExpr>(v)->getAsInstruction();
    } else if (isa<GlobalVariable>(v)) {
      srcset->insert(v);
    } else if (auto arg = dyn_cast<Argument>(v)) {
      bool found_callee = false;
      if (callset) {
        for (auto c : *callset) {
          if (!isa<CallInst>(c))
            continue;
          auto ci = dyn_cast<CallInst>(c);
          if (ci->arg_size() <= arg->getArgNo())
            continue;
          FunctionSet funcs;
          get_call_dest(ci, funcs);
          for (auto callee : funcs) {
            if (callee == arg->getParent()) {
              auto next = ci->getArgOperand(arg->getArgNo());
              if (!isa<Instruction>(next))
                continue;
              worklist.push_back(next);
              found_callee = true;
            }
          }
        }
      }
      if (!found_callee) {
        srcset->insert(arg);
      }
      continue;
    }

    if (!ii)
        continue;

    if (is_alloc(ii)) {
        srcset->insert(v);
        continue;
    }

    switch(ii->getOpcode()) {
    case Instruction::Alloca:
    case Instruction::Load:
      srcset->insert(v);
      break;
    

    case Instruction::Call: {
      if (is_builtin_container_of(ii)) {
        int op = 0;
        if (get_callee_function_name(ii) == "make_kuid")
          op = 1;
        worklist.push_back(ii->getOperand(op));
        break;
      }

      FunctionSet funcs;
      get_call_dest(ii, funcs);
      for (auto callee : funcs) {
          if (!callee->hasName() &&
            !callee->isDeclaration() && !callee->isIntrinsic())
              continue;
        if (is_skip_function(callee->getName().str()))
          continue;
        if (callee->getName() == "kstrdup") {
          worklist.push_back(ii->getOperand(0));
          break;
        }
        if (callset) {
          callset->insert(ii);
        }
        if (callee->size()==0)
            continue;
        worklist.push_back(callee->back().getTerminator());
      }
      break;
    }
    case Instruction::Select:
      worklist.push_back(ii->getOperand(1));
      worklist.push_back(ii->getOperand(2));
      break;

    case Instruction::GetElementPtr: {
      worklist.push_back(ii->getOperand(0));
      break;
    }

    case Instruction::PHI: {
      auto phi = cast<PHINode>(ii);
      for (unsigned i=0; i<phi->getNumIncomingValues(); i++) {
        auto op = phi->getIncomingValue(i);
        BasicBlock *targetBB = ii->getParent();
        if (isa<Instruction>(op))
          if (cast<Instruction>(op)->getParent() != phi->getIncomingBlock(i))
            targetBB = phi->getIncomingBlock(i);
        if (is_err_phi(phi->getIncomingValue(i), targetBB))
          continue;
        worklist.push_back(phi->getIncomingValue(i));
      }
      break;
    }

    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::ZExt:
    case Instruction::Trunc:
    case Instruction::SExt:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Xor:
    case Instruction::Mul:
    case Instruction::LShr:
    case Instruction::Shl:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
    case Instruction::Ret:
      for (unsigned i=0; i<ii->getNumOperands(); ++i) {
        worklist.push_back(ii->getOperand(i));
      }
      break;

    default:
      break;
    } // switch
  } // while
}

bool is_err_ptr(Value *v) {
    errs() << "is_err_ptr?\n";
  if (!isa<CastInst>(v)) {
    errs() << "not a cast inst\n";
    return false;
  }

  if (isa<TruncInst>(v)) {
    print_debug(v, "trunc");
    return true;
  }

  // %0 = %struct.A*
  // %1 = icmp ugt %0, inttoptr (i64 -err to %struct.A)
  // br %1, label trueBB, label falseBB
  //
  // falseBB:
  // %2 = bitcast %struct.A* %0 to %struct.B* <- [v]
  auto op = cast<User>(v)->getOperand(0);
  if (isa<Instruction>(op)) {
    auto prevBB = cast<Instruction>(op)->getParent();
    auto currBB = cast<Instruction>(v)->getParent();
    if (prevBB!=currBB) {
      if (auto br = dyn_cast<BranchInst>(prevBB->getTerminator())) {
        if (br->isConditional()) {
          if (auto icmp = dyn_cast<ICmpInst>(br->getOperand(0))) {
            if (auto ce = dyn_cast<ConstantExpr>(icmp->getOperand(1))) {
              if (ce->getOpcode() == Instruction::IntToPtr)
                return true;
            }
          }
        }
      }
    }
  }
  // %0 = %struct.A*
  // %1 = bitcast %struct.A* %0 to %struct.B* <- [v]
  // %2 = icmp ugt %0, inttoptr (i64 -err to %struct.A*)
  // br %2, label trueBB, label falseBB
  for (auto u : op->users()) {
    if (auto icmp = dyn_cast<ICmpInst>(u)) {
      if (auto ce = dyn_cast<ConstantExpr>(icmp->getOperand(1))) {
        if (ce->getOpcode() == Instruction::IntToPtr)
          return true;
      }
    }
  }
  return false;
}
bool is_global(Value *v, ValueSet *gvset, std::set<unsigned> *skipset) {
    if (!isa<Constant>(v))
        return false;
    if (isa<GlobalVariable>(v)) {
        if (gvset->count(v)) {
            return true;
        }
        else {
            return false;
        }
    }
    else if (isa<ConstantExpr>(v)) {
      if (skipset)
        if (skipset->count(cast<ConstantExpr>(v)->getOpcode()))
          return false;
      if (auto u = dyn_cast<User>(v)) {
        for (int i=0; i<u->getNumOperands(); ++i) {
          if (is_global(u->getOperand(i), gvset))
            return true;
        }
      }
    }
    return false;
}


bool is_global(Value *v, ValueSet *gvset) {
  if (!isa<Constant>(v))
    return false;
  if (isa<GlobalVariable>(v)) {
    if (gvset->count(v))
      return true;
    else {
      return false;
    }
  }
  else if (isa<ConstantExpr>(v)) {
    if (auto u = dyn_cast<User>(v)) {
      for (int i=0; i<u->getNumOperands(); ++i) {
        if (is_global(u->getOperand(i), gvset))
          return true;
      }
    }
  }
  return false;
}

bool has_ops_call(Value *v) {
    InstructionSet castset, ldset;
    bool debug=false;

    if (isa<Instruction>(v))
        castset.insert(cast<Instruction>(v));
    for (auto u : v->users()) {
        if (isa<CastInst>(u) || isa<GetElementPtrInst>(u)) {
            castset.insert(cast<Instruction>(u));
            for (auto uu : u->users()) {
                if (isa<CastInst>(uu) || isa<GetElementPtrInst>(uu)) {
                    castset.insert(cast<Instruction>(uu));
                }
            }
        }
    }
    for (auto u : castset) {
        for (auto uu : u->users()) {
            if (isa<LoadInst>(uu)) {
                if (uu->getType()->isPointerTy()) {
                    if (uu->getType()->getPointerElementType()->isFunctionTy()) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

void collect_forward(Value *v, unsigned target_opcode, int target_opnum,
             std::set<unsigned> *skip_opcodes, ValueSet *results,
             UseSet *visited, std::set<StringRef> *prefixes) {
  UseSet _visited;
  UseList worklist;
  bool debug=false;

  if (!visited)
    visited = &_visited;

  for (auto &u : v->uses())
      worklist.push_back(&u);

  while(worklist.size()) {
    auto u = worklist.back();
    auto vv = u->getUser();
    auto op = u->getOperandNo();
    Instruction *i = nullptr;
    worklist.pop_back();

    if (visited->count(u))
      continue;
    visited->insert(u);

    if (debug)
      print_debug(vv, "collect");
    if (isa<Argument>(vv)) {
        for (auto &u : vv->uses())
            worklist.push_back(&u);
        continue;
    } else if (isa<ConstantExpr>(vv)) {
        i = cast<ConstantExpr>(vv)->getAsInstruction();
    } if (isa<Instruction>(vv)) {
        i = cast<Instruction>(vv);
    } else {
        continue;
    }
    if (is_err_ptr(vv))
        continue;

    if (i->getOpcode() == target_opcode) {
      if (target_opnum < 0 || op==target_opnum) {
        if (target_opcode==Instruction::Call) {
          bool found=false;
          auto fname = get_callee_function_name(i);
          if (fname != "" && prefixes) {
            for (auto p : *prefixes) { 
              if (fname.startswith(p)) {
                results->insert(vv);
                found=true;
                break;
              }
            }
            if (found)
              continue;
          }
        } else if (target_opcode==Instruction::GetElementPtr 
                    && op > 1 && target_opnum ==2) {
            results->insert(vv);
            continue;
        } else {
          results->insert(vv);
          continue;
        }
      }
    }
    if (skip_opcodes && !is_asm(i) && !is_builtin_container_of(i))
      if (skip_opcodes->count(i->getOpcode()))
        continue;
    switch(i->getOpcode()) {
    case Instruction::Call:
      if (is_asm(i)) {
        int addr_op = get_asm_addr(i);
        if (addr_op<0 || addr_op != op)
          continue;
        if (isa<IntegerType>(u->get()->getType()) &&
            u->get()->getType()->getPrimitiveSizeInBits() < 64)
          continue;
        if (target_opcode==Instruction::Load && is_asm_load(i))
          results->insert(i);
        else if (target_opcode==Instruction::Store && target_opnum==1 &&
                 is_asm_store(i))
          results->insert(i);
      } else if (is_builtin_container_of(i)) {
        if (skip_opcodes && skip_opcodes->count(Instruction::GetElementPtr)) {
            continue;
        }
        for (auto &u : vv->uses())
          worklist.push_back(&u);
      } else if (is_alloc_inst(i)) {
        continue;
      } else {
        auto fname = get_callee_function_name(i);
        if (target_opcode == Instruction::Load || (target_opcode == Instruction::Store && target_opnum==1)) {
        if (fname.startswith("llvm.memcpy") ||
            fname.startswith("llvm.memmove") ||
            fname.startswith("kmemdup") ||
            fname.startswith("kmemdup_nul"))
          results->insert(i);
        }

        FunctionSet funcs;
        get_call_dest(i, funcs);

        for (auto callee : funcs) {
          if (is_alloc_function(callee->getName().str()))
            continue;
          if (is_free_function(callee->getName().str()))
            continue;
          if (op >= callee->arg_size())
            continue;
          auto arg = callee->getArg(op);
          for (auto &u : arg->uses())
            worklist.push_back(&u);
        }
      }
      break;
    case Instruction::Select:
      if (op==1 || op==2) {
        for (auto &u : vv->uses()) {
          worklist.push_back(&u);
        }
      }
      break;
    case Instruction::PHI:
    case Instruction::GetElementPtr:
    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Xor:
    case Instruction::Mul:
    case Instruction::LShr:
    case Instruction::Shl:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
      for (auto &u : vv->uses()) {
        worklist.push_back(&u);
      }
      break;

    case Instruction::Ret:
      for (auto u : i->getFunction()->users()) {
        if (auto ci = dyn_cast<CallInst>(u)) {
          auto caller=ci->getFunction();
          if (is_alloc_function(caller->getName().str()))
            continue;
          if (is_free_function(caller->getName().str()))
            continue;

          for (auto &_u : ci->uses()) {
            worklist.push_back(&_u);
          }
        }
      }
      break;

    default:
      break;
    }
  }
}

int collect_backward(Value *v, unsigned target_opcode,
             std::set<unsigned> *skip_opcodes, ValueSet *results,
             UseSet *visited) {
  UseSet _visited;
  UseList worklist;
  bool debug=false;
  int count=0;

  if (!visited)
    visited = &_visited;

  for (auto &u : v->uses())
      worklist.push_back(&u);

  while(worklist.size()) {
    auto u = worklist.back();
    auto vv = u->get();
    worklist.pop_back();

    if (visited->count(u))
      continue;
    visited->insert(u);
    if (auto arg = dyn_cast<Argument>(vv)) {
      auto func = arg->getParent();
      for (auto u : func->users()) {
        if (auto ci = dyn_cast<CallInst>(u)) {
          if (ci->arg_size() <= arg->getArgNo())
            continue;
          worklist.push_back(&ci->getArgOperandUse(arg->getArgNo()));
        }
      }
      continue;
    }
    if (!isa<Instruction>(vv))
        continue;
    if (is_err_ptr(vv))
        continue;

    if (debug)
      print_debug(vv, "collect");

    auto i = cast<Instruction>(vv);
    if (i->getOpcode() == target_opcode) {
      results->insert(vv);
      count++;
      continue;
    }
    if (skip_opcodes && !is_asm(i))
      if (skip_opcodes->count(i->getOpcode()))
        continue;
    switch(i->getOpcode()) {
    case Instruction::Call:
      if (is_asm(i)) {
        continue;
      } else if (is_builtin_container_of(i)) {
        if (skip_opcodes && skip_opcodes->count(Instruction::GetElementPtr))
            continue;
        worklist.push_back(&i->getOperandUse(0));
      } else if (is_alloc_inst(i)) {
        continue;
      } else {
        FunctionSet funcs;
        get_call_dest(i, funcs);
        for (auto callee : funcs) {
          auto ret = callee->back().getTerminator();
          if (!ret)
            continue;
          if (isa<ReturnInst>(ret)) {
            worklist.push_back(&cast<User>(ret)->getOperandUse(0));
          }
        }
      }
      break;
    case Instruction::Select:
      worklist.push_back(&i->getOperandUse(1));
      worklist.push_back(&i->getOperandUse(2));
      break;
    case Instruction::PHI:
    case Instruction::GetElementPtr:
    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Xor:
    case Instruction::Mul:
    case Instruction::LShr:
    case Instruction::Shl:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
      for (auto &u : i->operands()) {
        worklist.push_back(&u);
      }
      break;

    default:
      break;
    }
  }
  return count;
}
