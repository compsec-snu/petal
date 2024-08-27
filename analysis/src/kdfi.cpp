#include "kdfi.h"
#include "utility.h"
#include <fstream>
using namespace llvm;
extern cl::opt<std::string> knob_full_struct_list;
extern cl::opt<std::string> knob_mte_struct_list;
extern cl::opt<std::string> knob_pac_struct_list;
extern cl::opt<std::string> knob_mode;

char kdfi::ID;

// return ty from [n x ty]*
Type *get_parr_type(Type *ty) {
  if (isa<PointerType>(ty)) {
    if (auto aty = dyn_cast<ArrayType>(ty->getPointerElementType())) {
        return aty->getElementType();
    } else if (auto vty = dyn_cast<VectorType>(ty->getPointerElementType())) {
        return vty->getElementType();
    }
  }
  return nullptr;
}

bool is_from_stack(Value* i) {
  ValueSet visited, srcset;
  bool res = false;
  backward(i, &visited, &srcset, nullptr, nullptr);

  if (!srcset.size())
    return res;

  for (auto s : srcset) {
    if (!isa<AllocaInst>(s))
      break;
    else
      res = true;
  }
  return res;
}

bool is_per_cpu_gep(Value *ii)
{
  if (!ii)
    return false;
  if (!isa<GetElementPtrInst>(ii))
    return false;
  
  auto op = cast<Instruction>(ii)->getOperand(0);
  if (!isa<GlobalVariable>(op))
    return false;
  GlobalVariable *gv = cast<GlobalVariable>(op);
  return gv->getName() == "__per_cpu_offset";
}

bool kdfi::is_i8gep(User *gep) {
  Value *src = gep->getOperand(0);
  if (src->getType() != Type::getInt8PtrTy(*ctx))
    return false;
  if (!isa<ConstantInt>(gep->getOperand(1)))
    return false;
  return true;
}

ConstantExpr *has_priv_constexpr(Value *v, unsigned opcode)
{
    ConstantExpr *res = nullptr;
    if (!isa<User>(v))
        return res;
    if (auto ce = dyn_cast<ConstantExpr>(v)) {
        if (ce->getOpcode() == opcode)
            return ce;
    }

    User *u = cast<User>(v);
    for (auto &op : u->operands()) {
        if (!isa<ConstantExpr>(op))
            continue;
        else if (cast<ConstantExpr>(op)->getOpcode() != opcode) {
            res = has_priv_constexpr(op, opcode);
            if (res)
                break;
        } else { // constexpr opcode = opcode
            res = cast<ConstantExpr>(op);
            return res;
        }
    }
    return res;
}

bool kdfi::is_list_type(Type* ty) {
  if (!isa<StructType>(ty) &&  !isa<PointerType>(ty))
    return false;
  if (isa<PointerType>(ty)) {
      if (!isa<StructType>(ty->getPointerElementType()))
          return false;
      if (!list_structs->exists(
              get_struct_name(
                  cast<StructType>(ty->getPointerElementType())->getName().str())))
          return false;
      return true;
  }
  if (!list_structs->exists(
          get_struct_name(cast<StructType>(ty)->getName().str())))
      return false;
  return true;
}

StructType *kdfi::get_list_type(Type* ty) {
  if (!isa<StructType>(ty) &&  !isa<PointerType>(ty))
    return nullptr;
  if (isa<PointerType>(ty)) {
      if (!isa<StructType>(ty->getPointerElementType()))
          return nullptr;
      if (list_structs->exists(
              get_struct_name(
                  cast<StructType>(ty->getPointerElementType())->getName().str())))
          return get_pstr_type(ty);
      return nullptr;
  }
  if (list_structs->exists(
          get_struct_name(cast<StructType>(ty)->getName().str())))
      return cast<StructType>(get_type(ty));
  return nullptr;
}


bool kdfi::is_private_type(Type *ty) {
    if (is_list_type(ty))
        return true;
    
    if (isa<IntegerType>(stripPointerType(ty)))
        return true;
    return false;
}
bool kdfi::is_pte_type(Type *ty) {
  if (!isa<StructType>(ty))
    return false;
  auto sty = cast<StructType>(ty);
  if (sty->getName()=="struct.pte_t" ||
              sty->getName()=="struct.pmd_t" ||
              sty->getName()=="struct.pud_t" ||
              sty->getName()=="struct.pgd_t" ||
              sty->getName()=="struct.alt_instr" ||
              sty->getName().startswith("struct.page"))
    return true;
  return false;
}
Type *kdfi::get_type(Type *ty) {
    Type *sty = ty;
    int ptr_cnt = 0;
    while (isa<PointerType>(sty)) {
        sty = sty->getPointerElementType();
        ptr_cnt++;
    }
    if (!isa<StructType>(sty))
        return ty;
    if (is_anon_type(sty->getStructName()))
      return ty;
    auto sname = get_struct_name(sty->getStructName().str());
    Type *resTy = nullptr;
    resTy = StructType::getTypeByName(*ctx, sname);
    if (!resTy)
        return ty;
    for (int i=0; i<ptr_cnt; ++i) {
        resTy = resTy->getPointerTo();
    }
    return resTy;
}

bool is_parr_type(Type *ty) {
    if (!ty)
        return false;
    if (!isa<PointerType>(ty))
        return false;
    if (!isa<VectorType>(ty->getPointerElementType()) && 
            !isa<ArrayType>(ty->getPointerElementType()))
        return false;
    return true;
}
bool kdfi::is_pstr_type(Type *ty)
{
    if (!ty)
        return false;
    if (!isa<PointerType>(ty))
        return false;
    Type *elemTy = ty->getPointerElementType();
    if (!isa<StructType>(elemTy))
        return false;

    if (elemTy->getStructName().startswith("union"))
        return false;
    if (elemTy->getStructName().startswith("struct.util_est"))
        return false;
    if (elemTy->getStructName().startswith("struct.atomic"))
        return false;
    if (elemTy->getStructName().startswith("struct.refcount"))
        return false;


    return true;
}

MDNode *kdfi::get_arg_md(Argument *arg) 
{
    Function *func = arg->getParent();
    if (!func->hasMetadata("kdfi"))
        return nullptr;
    MDNode *mdn = cast<MDNode>(func->getMetadata("kdfi"));
    if (!mdn->getOperand(arg->getArgNo()))
        return nullptr;
    return cast<MDNode>(mdn->getOperand(arg->getArgNo()).get()); 
}
bool kdfi::is_pstr_type(Value *v)
{
    if (is_pstr_type(v->getType()))
        return true;
    return false; 
}

StructType *kdfi::get_pstr_type(Type *ty) {
    if (isa<PointerType>(ty)) {
        if (isa<StructType>(ty->getPointerElementType())) {
            if (ty->getPointerElementType()->getStructName().startswith("struct.atomic"))
                return nullptr;
            return cast<StructType>(get_type(ty->getPointerElementType()));
        }
    }
    return nullptr;
}
StructType *kdfi::get_pstr_type(Value *v)
{
    Type *ty = v->getType();
    if (auto sty = get_pstr_type(ty))
        return sty;
    return nullptr;
}

bool kdfi::is_pptr_type(Type *ty)
{
    if (!ty)
        return false;
    if (!isa<PointerType>(ty))
        return false;
    return is_priv_type(ty->getPointerElementType());
}

bool kdfi::is_pptr_type(Type *ty, StructType *psty)
{
    if (!ty)
        return false;
    if (!isa<PointerType>(ty))
        return false;
    StructType *sty = dyn_cast<StructType>(ty->getPointerElementType());
    if (!sty)
        return false;
    if (!is_same_struct(sty, psty))
        return false;
    return true;
}

bool kdfi::is_priv_type(Type *ty)
{
  if (!isa<StructType>(ty))
    return false;
  StructType *sty = cast<StructType>(get_type(ty));
  if (!sty)
    return false;
  return true;
}

bool kdfi::is_nested_pobj(Type *ty) {
  if (nested_pobj.count(ty))
    return true;
  return false;
}
bool kdfi::is_from_implicit_pptr(Value *val, StructType *psty) {
    Type *oriTy = val->stripPointerCasts()->getType();
    if (!isa<PointerType>(oriTy))
        return false;
    if (!is_pptr_type(oriTy, psty)) {
        if (!is_list_type(oriTy))
            return false;
        if (!isa<Instruction>(val))
            return false;

        Type *realTy = nullptr;
        ValueSet visited;

        //if (get_type(val) == psty->getPointerTo())
        //    return true;
        return false;
    }
    return true;
}

StructType *kdfi::get_container_srcty(Instruction *co) {
    static std::unordered_map<Instruction*, StructType*> co2srcty;
    if (co2srcty.count(co))
        return co2srcty[co];

    if (auto bi = dyn_cast<BitCastInst>(co->getOperand(0))) {
        if (auto srcty = get_pstr_type(bi->getOperand(0))) {
            co2srcty[co] = srcty;
            return srcty;
        }
    }
    return nullptr;
}
// return true if it has a mte-collision access
bool kdfi::collect_skip_maccess(Function *func, Value *v) {
    bool res = false;
    ValueSet visited;
    ValueList worklist;
    visited.insert(v);
    for (auto u : v->users()) {
        worklist.push_back(u); 
    }

    while (worklist.size()) {
        Value *vv = worklist.front();
        worklist.pop_front();
        if (visited.count(vv))
            continue;
        if (!isa<StoreInst>(vv))
            visited.insert(vv);
        Instruction *ii;
        if (isa<Instruction>(vv))
            ii = cast<Instruction>(vv);
        else if (isa<ConstantExpr>(vv)) {
            ii = cast<ConstantExpr>(vv)->getAsInstruction();
            dummyCE[ii] = func;
        }
        else
            continue;
        switch(ii->getOpcode()) {
            case Instruction::Store:
                if (visited.count(ii->getOperand(1)) ||
                    (std::find(worklist.begin(), worklist.end(), ii->getOperand(1)) != worklist.end())) {
                    Value *src = ii->getOperand(1);
                    if (isa<CallInst>(src) || isa<LoadInst>(src)) {
                        if (src != v && !is_builtin_container_of(cast<Instruction>(src)))
                            break;
                    }
                    mte_skip_inst.insert(ii);
                    res |= true;
                }
                break;
            case Instruction::Load:
                mte_skip_inst.insert(ii);
                res |= true;
                break;
            case Instruction::Call: {
                if (is_asm(ii)) {
                    for (int i=0; i<ii->getNumOperands(); ++i) {
                        if (visited.count(ii->getOperand(i)) ||
                        (std::find(worklist.begin(), worklist.end(), ii->getOperand(i)) != worklist.end())) {
                            if (is_asm_access(ii, i)) {
                                mte_skip_inst.insert(ii);
                                res |= true;
                                break;
                            }        
                        }
                    }
                    break;
                } 
                if (is_builtin_container_of(ii)) {
                    for (auto u : vv->users()) {
                        worklist.push_back(u);
                    }
                    break;
                }
                auto fname = get_callee_function_name(ii);
                for (auto s : skip_access_funcs) {
                    if (fname.startswith(s)) {
                        mte_skip_inst.insert(ii);
                        break;
                    }
                }
                break;

            }
            default:
                for (auto u : vv->users()) {
                    worklist.push_back(u);
                }
                break;
        }
    }
    return res;
}
void kdfi::get_equiv_geps(Instruction *i, InstructionSet *iset, int idx) {
    ValueSet visited;
    ValueList worklist;

    visited.insert(i);
    for (auto u : i->users()) {
        if (isa<Instruction>(u))
            worklist.push_back(u);
    }
    while(worklist.size()) {
        Value *v = worklist.front();
        if (!isa<Instruction>(v))
            continue;
        Instruction *ii = cast<Instruction>(v);
        worklist.pop_front();
        if (visited.count(ii))
            continue;
        visited.insert(ii);
        if (isa<CastInst>(ii) || isa<PHINode>(ii)) {
            for (auto u : ii->users())
                worklist.push_back(u);
        } else if (isa<SelectInst>(ii)) {
            if (!visited.count(ii->getOperand(0)))
                for (auto u : ii->users())
                    worklist.push_back(u);
        } else if (isa<GetElementPtrInst>(ii)) {
           if (is_i8gep(ii)) {
               int gep_idx = cast<ConstantInt>(ii->getOperand(1))->getZExtValue();
               if (idx == gep_idx)
                   iset->insert(ii);
           }
        }
    }
}


void kdfi::get_load(Value *val, InstructionSet *ldset, ValueSet *visited, bool direct, bool collision, bool pac_skip) {
    ValueList worklist;
    visited->insert(val);
    for (auto u : val->users()) {
        if (isa<Instruction>(u))
            worklist.push_back(u);
    }
    bool debug = false;
    while(worklist.size()) {
        Value *v = worklist.front();
        if (!isa<Instruction>(v))
            continue;
        Instruction *ii = cast<Instruction>(v);
        worklist.pop_front();
        if (visited->count(ii))
            continue;
        visited->insert(ii);
        if (debug)
            print_debug(ii, nullptr, "get_load");
        switch(ii->getOpcode()) {
            case Instruction::Store:
                if (pac_skip) {
                    if (visited->count(ii->getOperand(1)) ||
                        (std::find(worklist.begin(), worklist.end(), ii->getOperand(1)) != worklist.end())) 
                    pac_skip_sign.insert(ii);
                }
                break;
            case Instruction::Load: {
                ldset->insert(ii);
                bool cont = false;
                if (is_list_type(ii->getType()))
                    cont = true;
                if (auto ci = dyn_cast<CastInst>(ii->getOperand(0)))
                    if (is_list_type(ci->getOperand(0)->getType()))
                        cont = true;
                if (cont) {
                    for (auto u : ii->users()) {
                        if (isa<Instruction>(u))
                            worklist.push_back(u);
                    }
                }
                break;
                }
            case Instruction::Call: {
                if (is_asm_access(ii, 0) && visited->count(ii->getOperand(0))) {
                    if (ii->getType()->isAggregateType()) {
                        for (auto u : ii->users())
                            if (isa<ExtractValueInst>(u))
                                ldset->insert(cast<Instruction>(u));
                    }
                    else
                        ldset->insert(ii);
                }

                if (is_builtin_container_of(ii)) {
                    if (isa<ConstantInt>(ii->getOperand(1))) {
                    int idx = cast<ConstantInt>(ii->getOperand(1))->getZExtValue();
                    if (idx == 0) {
                        for (auto u : ii->users()) {
                            if (auto ui = dyn_cast<Instruction>(u))
                                worklist.push_back(ui);
                        }
                        
                    } else {
                        InstructionSet gset;
                        get_equiv_geps(ii, &gset, idx);
                        for(auto g : gset)
                            for (auto gu : g->users())
                                worklist.push_back(gu);
                    }
                    //if (!direct) {
                    //    for (auto u : ii->users()) {
                    //        if (auto ui = dyn_cast<Instruction>(u))
                    //            worklist.push_back(ui);
                    //    }
                    //}
                    }
                    break;
                
                }
                FunctionSet funcs;
                auto dir_func = get_callee_function_direct(ii);
                if (dir_func) {
                    funcs.insert(dir_func);
                } else {
                    if (!get_indirect_call_dest(ii, funcs))
                        continue;
                }
                for (auto callee : funcs) {
                    if (!callee)
                        continue;
                    if (is_skip_function(callee->getName().str()))
                        continue;

                    if (callee->isVarArg())
                        continue;
                    auto callee_name = callee->getName().str();
                    if (is_skip_function(callee_name) ||
                        is_alloc_function(callee_name) ||
                        is_free_function(callee_name))
                        continue;
                    if (debug){
                        errs() << "callee: " << callee->getName() << "\n";
                    }
                    // allow get_load across different function only for some functions
                    if (!collision) {
                        if (!callee->getName().contains("smk") && 
                            !callee->getName().contains("smack") &&
                            !callee->getName().contains("mount"))
                            continue;
                    }
                    if (debug)
                        errs() << "test1\n";
                    for (auto i=0; i<ii->getNumOperands(); ++i) {
                        if (callee->arg_size() <= i)
                            break;
                        if (visited->count(ii->getOperand(i)) ||
                            (std::find(worklist.begin(), worklist.end(), ii->getOperand(i))
                             != worklist.end())){
                            Argument *arg = callee->getArg(i);
                            InstructionSet _ldset;
                            get_load(arg, &_ldset, visited, direct, collision, pac_skip);
                            // for direct (priv ptr anal),
                            // collision argument should be filtered out
                            for (auto l : _ldset) 
                                ldset->insert(l);
                        }
                    }
                }
                break;
                }
                case Instruction::GetElementPtr:
                    if (!is_list_type(ii->getType())) {
                        if (direct) {
                            bool zero = true;
                            for (int i=1; i<ii->getNumOperands(); ++i) {
                                Value *op = ii->getOperand(i);
                                if (!isa<ConstantInt>(op)) {
                                    zero = false;
                                    break;
                                }
                                if (cast<ConstantInt>(op)->getZExtValue() >0) {
                                    zero = false;
                                    break;
                                }
                            }
                            if (!zero)
                                break;
                        }
                    } 
                    if (!visited->count(ii->getOperand(0)))
                        break;
                    
            default:
                for (auto u : ii->users()) {
                    if (auto ui = dyn_cast<Instruction>(u))
                        worklist.push_back(ui);
                }
                break;
        }
    }
    return;
}

bool is_this_cpu_asm(Value *v) {
   if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;

    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("tpidr_el1") != std::string::npos)
        return true;

    return false;
}

bool kdfi::is_cpu_ptr(Value *v) {
  if (!isa<LoadInst>(v))
    return false;

  if (isa<LoadInst>(v))
    if (is_per_cpu_gep(dyn_cast<Instruction>(cast<Instruction>(v)->getOperand(0))))
      return true;

  return false;

  // never reach here

  Instruction *addI = nullptr;
  for (auto u : v->users()) {
    if (auto bop = dyn_cast<BinaryOperator>(u)) {
      if (bop->getOpcode()==Instruction::Add) {
        addI = bop;
        break;
      }
    }
  }
  if (!addI)
    return false;

  Instruction *offset = dyn_cast<Instruction>(addI->getOperand(0));
  if (!offset)
    return false;
  if (is_asm(offset)) {
    if (is_this_cpu_asm(offset))
      return true;
  } else if (isa<LoadInst>(offset)) {
    if (is_per_cpu_gep(dyn_cast<Instruction>(offset->getOperand(0))))
      return true;
  }
  return false;
}

bool kdfi::is_phys_addr(Value *v) {
  ValueSet visited;
  ValueSet srcset;
  ValueList worklist;

  for (auto u : v->users())
    worklist.push_back(u);
  visited.insert(v);

  while (worklist.size()) {
    auto v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (isa<Argument>(v)) {
      for (auto u : v->users()) {
        worklist.push_back(u);
      }
      continue;
    }
    else if (!isa<Instruction>(v)) {
      continue;
    }
    auto ii = cast<Instruction>(v);
    switch(ii->getOpcode()) {
    case Instruction::Call: {
      if (is_builtin_container_of(ii)) {
        for (auto u : v->users())
          worklist.push_back(u);
      } else {
        FunctionSet funcs;
        get_call_dest(ii, funcs);
        for (int i=0; i<cast<CallInst>(ii)->getNumOperands(); ++i) {
          if (!visited.count(cast<CallInst>(ii)->getArgOperand(i)))
            continue;
          for (auto func : funcs) {
            if (func->arg_size() > i) {
              worklist.push_back(func->getArg(i));
            }
          }
        }
      }
      break;
    }
    case Instruction::Sub:
      if (auto ld = dyn_cast<LoadInst>(ii->getOperand(1))) {
        if (auto gv = dyn_cast<GlobalVariable>(ld->getOperand(0))) {
          if (gv->getName()=="physvirt_offset")
            return true;
        }

      }
      break;
    case Instruction::Select:
      if (!visited.count(ii->getOperand(0)))
        break;
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Add:
    case Instruction::LShr:
    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::PHI:
    case Instruction::ExtractValue:
      for (auto u : v->users()) {
        worklist.push_back(u);
      }
      break;
    default:
      break;
    }
  }
  return false;

}

bool kdfi::is_per_cpu(Function* func, Instruction *ii)
{
    ValueList worklist;
    ValueSet visited;
    worklist.push_back(ii);
    while(worklist.size()) {
        Value *v = worklist.front();
        worklist.pop_front();
        if (visited.count(v))
            continue;
        visited.insert(v);

        Instruction *vi;
        if (isa<Instruction>(v))
            vi = cast<Instruction>(v);
        else if (isa<ConstantExpr>(v)) {
            vi = cast<ConstantExpr>(v)->getAsInstruction();
            dummyCE[vi] = func;
        }
        else
            continue;
        if (is_per_cpu_gep(vi))
            return true;
        if (is_asm(vi))
            return true;
        for (int i=0; i<vi->getNumOperands(); i++) {
            worklist.push_back(vi->getOperand(i));
        }
    }
    return false;
}
bool kdfi::has_pptr_field(ConstantStruct *init, TypeSet &tset) {
    bool res = false;
    for (int i=0; i<init->getNumOperands(); ++i) {
        Value *elem = init->getOperand(i)->stripPointerCasts();
        Type *ety = elem->getType();
        if (cast<Constant>(elem)->isNullValue())
            continue;

        auto sty = get_pstr_type(ety);
        if (sty) {
          if (pptr.count(sty)) {
            tset.insert(ety);
            res |= true;
          }
        }

        if (auto ce = dyn_cast<ConstantStruct>(elem)) {
            if (has_pptr_field(ce, tset)) {
                res |= true;
            }
        }
        if (auto ce = dyn_cast<ConstantExpr>(elem)) {
            if ((ce->getOpcode() == Instruction::GetElementPtr)
                || (ce->getOpcode() == Instruction::BitCast)) {

                Type *ety = ce->getOperand(0)->stripPointerCasts()->getType();
                auto sty = get_pstr_type(ety);
                if (sty) {
                    if (pptr.count(sty)) {
                        tset.insert(ety);
                        res |= true;
                    }
                }
            }
        }

    }
    return res;
}


GlobalVariable *has_gv(Value *v) {
    if (isa<GlobalVariable>(v)) {
        return cast<GlobalVariable>(v);
    }
    if (!isa<User>(v))
        return nullptr;
    for (int i=0; i<cast<User>(v)->getNumOperands(); ++i) {
        if (isa<Constant>(cast<User>(v)->getOperand(i)))
            if (auto gv = has_gv(cast<User>(v)->getOperand(i)))
                return gv;
    }
    return nullptr;
}

Indices* kdfi::get_indices(Indices idx, StructType *srcty) {
    while(idx.size()) {
        if (idx.back() == 0) {
            int back = idx.back();
            idx.pop_back();
            if (srcty) {
                Type *elemty = get_element_type(srcty, &idx);
                if (elemty) {
                    if (isa<ArrayType>(elemty)) {
                        idx.push_back(back);
                        break;
                    }
                }
            }
        }
        else
            break;
    }
    if (idx.size() == 0)
        idx.push_back(0);
    if (srcty) {
        auto sname = srcty->getName();
        if (sname == "struct.rcu_data") {
            if (idx.size() == 4) {
                int first = idx.front();
                idx.pop_front();
                int second = idx.front();
                idx.pop_front();
                int third = idx.front();
                idx.push_front(second);
                idx.push_front(first);
                
                if (second == 12  && third == 1)  {
                    idx.pop_back();
                    idx.push_back(-1);
                }
            }    
        }
        if (sname == "struct.rcu_segcblist") {
            if (idx.size() == 3) {
                int first = idx.front();
                idx.pop_front();
                int second = idx.front();
                idx.push_front(first);
                
                if (second == 1)  {
                    idx.pop_back();
                    idx.push_back(-1);
                }
            }    
        }
        if (sname == "struct.pid") {
            if (idx.size() == 3) {
                int first = idx.front();
                idx.pop_front();
                int second = idx.front();
                idx.push_front(first);
                
                if (second == 2)  {
                    idx.pop_back();
                    idx.push_back(-1);
                }
            }    
        }

    }
    for (auto i : ind_keys){
        if (*i == idx)
            return i;
    }
    Indices* new_idx = new Indices(idx);
    ind_keys.insert(new_idx);
    return new_idx;
}

/////////////////////////////////////////////////////////////////////////////
// KDFI
/////////////////////////////////////////////////////////////////////////////

void kdfi::preprocess()
{
  collect_nested_type();
  collect_parent_type();

  collect_alloc();
  check_gv_initializer();
  collect_access_func();

  find_pstack_funcs();
}


void kdfi::get_union_elements(StructType *usty, TypeSet *typeset) {
   for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (!isa<CastInst>(&*I))
          continue;
        if (auto sty = get_pstr_type(I->getOperand(0)->getType())) {
          if (sty != usty)
            continue;
          if (auto esty=get_pstr_type(I->getType())) {
            typeset->insert(esty);
          }
        }
      }
    }
   }
}

void kdfi::collect_nested_type() {
  TypeList typelist;
  TypeSet visited, nested;

  Ty2TySet union2sty;  

  for (Module::iterator fi = m->begin(), fe = m->end();
      fi != fe; ++fi) {
   Function *func = dyn_cast<Function>(fi);
   if (!func)
     continue;
   if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
     continue;
   for(auto &B : *func) {
     for (auto I = B.begin(), E = B.end(); I != E; ++I) {
       if (!isa<CastInst>(&*I))
         continue;
       if (auto sty = get_pstr_type(I->getOperand(0)->getType())) {
         if (!sty->getName().startswith("union"))
           continue;
         auto esty = get_pstr_type(I->getType());
         if (!esty)
           continue;
         auto typeset = union2sty[sty];
         if (!typeset) {
           typeset= new TypeSet;
           union2sty[sty] = typeset;
         }
         typeset->insert(esty);
       }
     }
   }
  }


  for (auto sty : pobj) {
    typelist.push_back(sty);
  }

  // container_pobj: tagged at alloc
  for (auto sty : m->getIdentifiedStructTypes()) {
    if (!sty->hasName())
      continue;
    if (sty->getNumElements()==0)
      continue;
    auto _sty = cast<StructType>(get_type(sty));
    if (pobj.count(_sty))
      typelist.push_back(sty);
    if (auto esty = dyn_cast<StructType>(get_type(_sty->getElementType(0)))) {
      if (pobj.count(esty)) {
        typelist.push_back(_sty);
        container_pobj.insert(_sty);
      }
    }
  }

  while (typelist.size()) {
    auto ty = typelist.back();
    typelist.pop_back();
    if (isa<StructType>(ty)) {
      if (cast<StructType>(ty)->isOpaque())
        continue;
      if (is_list_type(ty))
        continue;
    }
    if (nested.count(ty))
      continue;
    nested.insert(ty);
    if (auto sty = dyn_cast<StructType>(ty)) {
      for (int i=0; i<sty->getNumElements(); ++i) {
        auto ety = sty->getElementType(i);
        typelist.push_back(get_type(ety));
      }
      if (sty->getName().startswith("union") &&
          union2sty.count(sty)) {
        auto typeset=union2sty[sty];
        for (auto t : *typeset) {
          auto esty=cast<StructType>(ty);
          errs() << "   - " << *t << "\n";
          typelist.push_back(t);
        }
      }

    } else if (auto arr = dyn_cast<ArrayType>(ty)) {
      typelist.push_back(get_type(arr->getElementType()));
    }
  }

  for (auto ty : nested) {
    if (isa<StructType>(ty) && !is_anon_type(ty->getStructName())) {
      if (cast<StructType>(ty)->getNumElements()==0)
        continue;
      nested_pobj.insert(get_type(ty));
      auto name = get_type(ty)->getStructName();
      if (name == "struct.ctl_node" ||
          name == "struct.ctl_dir" ||
          name == "struct.ctl_table_header" ||
          name == "struct.ctl_table") {
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_node"));
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_dir"));
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_table_header"));
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_table"));

      }
      if (name == "struct.ext4_inode_info") {
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent_header"));
          nested_pobj.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent"));
      }
    }

  }

  errs() << "nested pobj : " << nested_pobj.size() << "\n";
  for (auto ty : nested_pobj) {
    errs() << " - " << ty->getStructName() << "\n";
  }
}
bool kdfi::is_parent_type(StructType *sty) {
  bool res=false;
  Indices idx;
  static StructTypeSet not_parent;
  if (parent2off.count(sty))
    return true;
  if (not_parent.count(sty))
    return false;
  for (int i=0; i<sty->getNumElements(); ++i) {
    if (auto esty = get_pstr_type(sty->getElementType(i))) {
      if (pobj.count(esty) || pptr.count(esty)) {
        res |= true;
        auto SL = DL->getStructLayout(sty);
        idx.push_back(SL->getElementOffset(i));
        errs() << "copy_idx: " << sty->getName() << "-" << i << " ("<<SL->getElementOffset(i) << ")\n";
      }
    }
    else if (auto esty = dyn_cast<StructType>(sty->getElementType(i))) {
      if (is_parent_type(esty)) {
        res |= true;
        auto SL = DL->getStructLayout(sty);
        int base = SL->getElementOffset(i);
        auto eidx = parent2off[esty];
        for (auto off : *eidx) {
          idx.push_back(base+off);
          errs() << "copy_idx: " << sty->getName() << "-" << i << " ("<<base+off << ")\n";
        }
      }
    } else if (auto earr = dyn_cast<ArrayType>(sty->getElementType(i))) {
      if (auto esty = get_pstr_type(earr->getElementType())) {
        if (pobj.count(esty) || pptr.count(esty)) {
          res |= true;
          auto SL = DL->getStructLayout(sty);
          int base = SL->getElementOffset(i);
          int cnt = earr->getNumElements();

          errs() << "copy_idx: " << sty->getName() << "-" << i << " ("<<base << "+[" << cnt << "x8])\n";
          for (int j=0; j <cnt; ++j)
            idx.push_back(base+j*8);
        }
      }
    }
  }

  if (res) {
    parent2off[sty] = get_indices(idx);
  } else {
    not_parent.insert(sty);
  }
  return res;
}

void kdfi::collect_parent_type() {
  StructTypeSet structs;
  for (auto s : m->getIdentifiedStructTypes()) {
    if (!s->hasName())
      continue;
    if (is_list_type(s))
      continue;
    if (s->getNumElements()==0)
      continue;
    auto sty = cast<StructType>(get_type(s));
    structs.insert(sty);
  }

  for (auto sty : structs) {
    if (is_parent_type(sty))
      parent_type.insert(sty);
  }
}

void kdfi::check_gv_initializer() {
  for (auto &gv : m->globals()) {
    if (!is_pstr_type(gv.getType()))
      continue;
    if (!gv.hasName())
      continue;
    if (!gv.hasInitializer())
      continue;
    if (gv.getName().startswith("__param"))
      continue;
    if (gv.getName().startswith(".compound"))
      continue;
    StructType *sty = cast<StructType>(gv.getType()->getPointerElementType());
    Constant *init = gv.getInitializer();
    if (auto ci = dyn_cast<ConstantStruct>(init)) {
      TypeSet tset;
      if (has_pptr_field(ci, tset)) {
        errs() << "pptr: " << gv.getName() <<"\n";
        for (auto ety : tset)
          errs() << " - " << *ety <<"\n";
      }
    }
  }
 //   exit(1);
}

// get_alloc_type
// : get the struct type of the alloc inst 
//
StructType *kdfi::get_alloc_types(Instruction* ii, StructTypeSet *types)
{
    ValueSet visited;
    ValueList worklist;
    StructTypeSet typeset;
    bool isUniversal=false;
    bool multiple=false;
    GlobalVariable *cache=nullptr;
    auto fname = get_callee_function_name(ii);

    // special kmalloc caches
    if (fname.startswith("kmem_cache_alloc")) {
      Value *src = ii->getOperand(0);
      if (auto ld = dyn_cast<LoadInst>(src)) {
        if (auto gv = dyn_cast<GlobalVariable>(ld->getOperand(0)))
          cache = gv;
      }
      if (cache) {
        if (cache->getName().startswith("kmalloc_caches")) {
          cache=nullptr;
        }
      } 
    } 

    worklist.push_back(ii);

    while (worklist.size()) {
      auto v = worklist.back();
      worklist.pop_back();
      if (visited.count(v))
        continue;
      visited.insert(v);
      if (auto sty = get_pstr_type(v->getType())) {
        if (is_list_type(sty))
          continue;
        if (sty->getName() == "struct.atomic64_t")
          continue;
        if (is_anon_type(sty->getName()))
          continue;
        if (!sty->isSized()) {
          continue;
        }
        typeset.insert(sty);
      }

      for (auto u : v->users()) {
        if (!isa<Instruction>(u))
          continue;
        if (is_builtin_container_of(cast<Instruction>(u))) {
          worklist.push_back(u);
        } else if (isa<SelectInst>(u)) {
          if (cast<User>(u)->getOperand(0) == v)
            worklist.push_back(u);
        } else if (isa<PHINode>(u)) {
          worklist.push_back(u);
        } else if (isa<CastInst>(u)) {
          if (isa<TruncInst>(u))
            continue;
          if (is_err_ptr(u))
            continue;
          auto lsty = get_pstr_type(v->getType());
          auto rsty = get_pstr_type(u->getType());
          if (lsty && !lsty->isOpaque() && rsty && !rsty->isOpaque()) {
            auto lsize = DL->getTypeStoreSizeInBits(lsty);
            auto rsize = DL->getTypeStoreSizeInBits(rsty);
            if (rsize < lsize)
              continue;
          }
          worklist.push_back(u);
        } else if (isa<StoreInst>(u)) {
          auto dst = cast<User>(u)->getOperand(1);
          if (auto ci = dyn_cast<CastInst>(dst)) {
            if (isa<PointerType>(ci->getOperand(0)->getType())) {
              if (auto sty = get_pstr_type(ci->getOperand(0)
                                           ->getType()->getPointerElementType())) {
                if (!sty->isSized()) {
                  continue;
                }
                if (!is_list_type(sty) &&
                    sty->getName() != "struct.atomic64_t" &&
                    !is_anon_type(sty->getName()))
                  typeset.insert(sty);
              }
            }
          }
        } else if (isa<BinaryOperator>(u)) {
          auto op = cast<User>(u)->getOperand(1);
          if (!isa<ConstantInt>(op))
            continue;
          if (cast<ConstantInt>(op)->getSExtValue() < 32)
            worklist.push_back(u);
        }
        else if (auto ret = dyn_cast<ReturnInst>(u)) {
          if (auto func = ret->getFunction()) {
            for (auto _u : func->users()) {
              if (isa<Instruction>(_u)) {
                worklist.push_back(_u);
                isUniversal |= true;
              }
              if (isa<ConstantExpr>(_u)) {
                for (auto __u : _u->users()) {
                  if (isa<Instruction>(__u)) {
                    worklist.push_back(__u);
                    isUniversal |= true;
                  }
                }
              }
            }
          }
        }
      }
    }

    TypeSet nested;
    TypeList typelist;
    for (auto sty : typeset) {
      for (int i=0; i<sty->getNumElements(); ++i) {
        auto ety = sty->getElementType(i);
        if (auto nsty = dyn_cast<StructType>(ety)) {
          typelist.push_back(nsty);
        } else if (auto narr = dyn_cast<ArrayType>(ety)) {
          typelist.push_back(narr->getElementType());
        }
      }
    }
    while(typelist.size()) {
      auto ty = typelist.back();
      typelist.pop_back();
      if (nested.count(ty))
        continue;
      nested.insert(ty);
      if (auto sty = dyn_cast<StructType>(ty)) {
        for (int i=0; i<sty->getNumElements(); ++i) {
          auto ety = sty->getElementType(i);
          typelist.push_back(get_type(ety));
        }
      } else if (auto arr = dyn_cast<ArrayType>(ty)) {
        typelist.push_back(get_type(arr->getElementType()));
      }
    }
    StructType *allocTy = nullptr;
    for (auto ty : typeset) {
      if (!nested.count(ty)) {
        if (!allocTy)
          allocTy = ty;
        else {
          multiple=true;
          if (DL->getTypeStoreSizeInBits(allocTy) <
              DL->getTypeStoreSizeInBits(ty))
            allocTy = ty;
        }
      }
    }
    if (allocTy) {
      if (multiple && isUniversal) {
        for (auto ty : typeset) {
          types->insert(cast<StructType>(ty));
        }
      } else {
        types->insert(cast<StructType>(allocTy));
      }
 
      if (cache) {
        cache2sty[cache]=allocTy;
      }
    }
     return allocTy;
}
StructType *kdfi::get_free_type(Instruction *ci) {

  StructType *freeTy = nullptr;
  int op = 0;
  auto fname=get_callee_function_name(ci);
  if (fname.startswith("kmem_cache_free")) {
    if (auto ld = dyn_cast<LoadInst>(cast<CallInst>(ci)->getArgOperand(0))) {
      if (auto cache = dyn_cast<GlobalVariable>(ld->getOperand(0)->stripPointerCasts())) {
        if (cache2sty.count(cache)) {
          return cache2sty[cache];
        }
      }
    }
  }
  if (fname == "kmem_cache_free" || fname == "devm_kfree")
    op = 1;
  Value *src = cast<CallInst>(ci)->getArgOperand(op);
  if (!isa<BitCastInst>(src)) {
    if (auto s = dyn_cast<User>(src)) {
      for (auto u : s->users()) {
        if (isa<BitCastInst>(u)) {
          if (auto sty = get_pstr_type(u)) {
            if (pobj.count(sty) || is_nested_pobj(sty)) {
              freeTy = sty;
            }
          }
        }
      }
    }
  } else {
    src = cast<User>(src)->getOperand(0);
    if (auto sty = get_pstr_type(src)) {
      if (pobj.count(sty) ||
          is_nested_pobj(sty)) {
        freeTy = sty;
      }
    }
  }
  return freeTy;
}

StructType *kdfi::get_lookup_type(CallInst *ci) {
   Function *callee = get_callee_function_direct(ci);
   if (!callee)
       return nullptr;

   if (callee->getName().startswith("radix_tree_lookup")) {
       Value *src = ci->getArgOperand(0);
       if (auto gv = dyn_cast<GlobalValue>(src)) {
           if (gv->getName() == "irq_desc_tree") {
               return StructType::getTypeByName(*ctx, "struct.irq_desc");
           }
       }
   }
   return nullptr;
}

StructType *kdfi::get_i8gep_type(User *gep) 
{
  // i8gep 
  // - container -> container type + gep idx
  // - bitcast -> bitcast type + gep idnx
  if (!is_i8gep(gep))
      return nullptr;

  Value *src = gep->getOperand(0);
  StructType *sty = nullptr;
  ConstantInt *idx = cast<ConstantInt>(gep->getOperand(1));
  Indices *idx_key = get_indices({idx->getSExtValue()});

  if (isa<CallInst>(src)) {
    if (is_alloc_function(
                get_callee_function_name(cast<Instruction>(src)).str()))
      sty = alloc2sty[src];
    else if (auto _sty = get_lookup_type(cast<CallInst>(src))) {
        sty = _sty;
    }
    if (!sty) {
        for (auto u : src->users()) {
            if (isa<CastInst>(u)) {
                if (auto _sty = get_pstr_type(u)) {
                    if (!is_list_type(_sty) && !is_anon_type(_sty->getName()) &&
                        !_sty->getName().startswith("struct.atomic")) {
                        sty = _sty;
                        break;
                    }
                }
            }
        }
    }

    if (!sty && is_builtin_container_of(cast<Instruction>(src))) {
        Value *idx = cast<Instruction>(src)->getOperand(1);
        if (isa<ConstantInt>(idx)) {
            if (cast<ConstantInt>(idx)->getZExtValue() == 0) {
                if (auto ci = dyn_cast<CastInst>(cast<Instruction>(src)->getOperand(0))) {
                    if (auto _sty = get_pstr_type(ci->getOperand(0)))
                    if (!is_list_type(_sty) && !is_anon_type(_sty->getName()) &&
                        !_sty->getName().startswith("struct.atomic")) {
                            sty = _sty;
                    }
                }
            }
        }
    }
    if (sty)
        return sty;
  }
  bool found = false;
  while(!found) {
      if (auto _sty = get_pstr_type(src)) {
          sty = _sty;
          if (!is_list_type(_sty) &&
              !is_anon_type(_sty->getName()) &&
              !_sty->getName().startswith("struct.atomic")) {
              found = true;
              break;
          }
      }
      if (!isa<CastInst>(src) && !isa<GetElementPtrInst>(src))
          break;
      src = cast<User>(src)->getOperand(0);
  }
  if (src && found)
      return sty;
  else
      return nullptr;
}
int kdfi::gep2offset(StructType *sty, Indices *idx) {
    const StructLayout *SL;
    int off = 0;
   int count = 0;
    for (auto i : *idx) {
        SL = DL->getStructLayout(sty);
        if (!SL)
            return -1;
        if (sty->getNumElements() <= i)
            return -1;
        count++;
        if (count == 1)
            continue;
        off += SL->getElementOffset(i);
        Type *ety = sty->getElementType(i);
        if (!isa<StructType>(ety)) // TODO: array
            break;
        sty = cast<StructType>(ety);
    }
    if (count < idx->size())
        return -1;
    return off;

}

GlobalVariable *kdfi::get_global(Value *v, int *offset) {
  if (!isa<Constant>(v))
    return nullptr;
  if (isa<GlobalVariable>(v)) {
      return cast<GlobalVariable>(v);
  }
  else if (auto ce = dyn_cast<ConstantExpr>(v)) {
    auto opcode = ce->getOpcode();
    if (opcode == Instruction::BitCast) {
        return get_global(ce->getOperand(0), offset);
    } else if (opcode == Instruction::GetElementPtr) {
      auto _offset = gep2offset(ce->getAsInstruction());
      if (_offset>=0) {
        *offset = *offset + _offset;
      }
      return get_global(ce->getOperand(0), offset);
    }
  }
  return nullptr;
}

int kdfi::gep2offset(Instruction *gep) {
  if (is_i8gep(gep)) {
    if (auto ci = dyn_cast<ConstantInt>(gep->getOperand(gep->getNumOperands()-1)))
      return ci->getZExtValue();
  }
  auto sty = dyn_cast<StructType>(gep->getOperand(0)->getType()->getPointerElementType());
  if (!sty)
    return -1;

  int offset = 0;
  int i=1;
  Type *baseTy = sty;
  std::vector<Value*> offset_vec;

  while (i < gep->getNumOperands()) {
    Value *op = gep->getOperand(i);

    // array index
    if (op->getType()->getPrimitiveSizeInBits() == 64) {
      int idx = 0;
      if (isa<ConstantInt>(op))
        idx = cast<ConstantInt>(op)->getZExtValue();
      auto size = DL->getTypeStoreSizeInBits(baseTy);
      offset += idx * size;
      offset_vec.clear();
      offset_vec.push_back(ConstantInt::get(Type::getInt64Ty(*ctx), 0));
      if (i > 1) {
        if (!isa<ArrayType>(baseTy)) {
          print_debug(gep);
          errs() << *sty << "\n";
          errs() << *baseTy << "\n";
        }
        assert(isa<ArrayType>(baseTy));
        baseTy = cast<ArrayType>(baseTy)->getElementType();
        if (isa<StructType>(baseTy))
          sty = cast<StructType>(baseTy);
      }
      i++;
      continue;
    }

    if (!isa<ConstantInt>(op))
      return -1;

    // struct field index
    for (; i<gep->getNumOperands(); ++i) {
      Value *op = gep->getOperand(i);
      if (op->getType()->getPrimitiveSizeInBits() != 32)
        break;

      if (!isa<ConstantInt>(op))
        return -1;
      auto c = cast<ConstantInt>(op);
      offset_vec.push_back(op);
      if (!isa<StructType>(baseTy)) {
        return -1;
      }

      baseTy = cast<StructType>(baseTy)->getTypeAtIndex(c->getZExtValue());
    }

    offset += DL->getIndexedOffsetInType(sty, llvm::ArrayRef<Value*>(offset_vec));
  }

  return offset;
}

Indices *kdfi::i8gep2idx(StructType *sty, int offset) {
    Indices idx;
    idx.push_back(0);
    const StructLayout *SL;
    int off = 0;
    int count = 1;
    StructType *_sty = sty;
    while(true) {
        SL = DL->getStructLayout(_sty);
        if (!SL)
            return nullptr;
        int tmp = 0;
        for (int i=0; i<_sty->getNumElements(); ++i) {
            tmp = off+SL->getElementOffset(i);
            if (tmp < offset)
                continue;
            else {
                if (tmp > offset) {
                    if (i<=0)
                        return nullptr;
                    tmp = off + SL->getElementOffset(i-1);
                    idx.push_back(i-1);
                } else {
                    idx.push_back(i);
                }
                break;
            }
        }
        count++;
        if (count != idx.size())
            return nullptr;
        if (tmp == offset)
            break;
        // tmp < offset
        Type *ety = get_element_type(_sty, &idx);
        if (!ety)
            return nullptr;
        if (!isa<StructType>(ety))
            return nullptr;
        off += tmp;
        _sty = cast<StructType>(ety);
    }
    Indices *idx_key = get_indices(idx);
    return idx_key;
}



// collect_alloc
// : collect kernel object allocation site
void kdfi::collect_alloc()
{
  bool err = false;
  TypeSet mte_tys;
  TypeSet normal_tys;
  for (auto &gv : m->globals()) {
    if (auto sty = get_pstr_type(gv.getType())) {
      auto gname = gv.getName().str();
      if (gname.find(".") != std::string::npos) {
        continue;
      }
      normal_tys.insert(get_type(sty));
      if (pobj.count(sty)) {
        priv_gobj.insert(&gv);
        print_debug(&gv, "priv global object");
      }
      // global struct including gobj reference.
      if (gv.hasInitializer()) {
        auto init = gv.getInitializer();
        if (init && !init->isZeroValue()) {
          for (unsigned i=0; i < init->getNumOperands(); ++i) {
            if (priv_gobj.count(init->getAggregateElement(i)->stripPointerCasts()))
              gref_fields.insert(std::make_pair(sty, i));
            if (auto cs = dyn_cast<ConstantStruct>(init->getAggregateElement(i)->stripPointerCasts())) {
              for (unsigned j=0; j < cs->getNumOperands(); ++j) {
                if (priv_gobj.count(cs->getAggregateElement(j)->stripPointerCasts())) {
                  gref_fields.insert(std::make_pair(sty, i));
                }
              }
            }
          }
        }
      }
    }
    // global array including gobj reference.
    if (auto arr = dyn_cast<ArrayType>(gv.getType()->getPointerElementType())) {
      if (auto sty = dyn_cast<StructType>(arr->getElementType())) {
        if (gv.hasInitializer()) {
          auto init = gv.getInitializer();
          if (init && !init->isZeroValue()) {
            for (int i=0; i < arr->getNumElements(); ++i) {
               auto entry = init->getAggregateElement(i);
               if (!entry)
                 continue;
               if (entry->isZeroValue())
                 continue;
               for (unsigned j=0; j < entry->getNumOperands(); ++j) {
                 auto elem = entry->getAggregateElement(j);
                 if (priv_gobj.count(elem->stripPointerCasts()))
                   gref_fields.insert(std::make_pair(sty, j));
               }
            }
          }
        }
      }
    }

    // global priv pointer
    if (auto sty = get_pstr_type(gv.getType()->getPointerElementType())) {
      if (pobj.count(sty) || pptr.count(sty)) {
        priv_gptr.insert(&gv);
        print_debug(&gv, "priv global pointer");
      }
    }

  }
  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    bool found = false;
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    auto fname = func->getName().str();
    if (is_alloc_function(fname) || is_free_function(fname))
      continue;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (isa<AllocaInst>(&*I)) {
          auto sty = get_pstr_type(I->getType());
          if (!sty)
            continue;
          normal_tys.insert(get_type(sty));
        }
        else if (isa<CallInst>(&*I)) {
          auto fname = get_callee_function_name(&*I).str();
          if (is_alloc_function(fname)) {
            StructTypeSet alloc_types;
            StructType *sty = get_alloc_types(&*I, &alloc_types);
            if (alloc_types.size() ==1) {
              alloc2sty[&*I] = sty;
              normal_tys.insert(get_type(sty));
              if (pobj.count(sty) || container_pobj.count(sty)) {
                priv_alloc.insert(&*I);
                mte_tys.insert(get_type(sty));
                print_debug(sty, func, "alloc ty");

                int size = -1;
                if(sty->isSized())
                  size = DL->getTypeAllocSize(sty);
                else
                  size = get_struct_size(sty);
                errs() << "size: " << size << "\n";
                continue;
              }
              //normal_tys.insert(get_type(sty));
            }
           normal_alloc.insert(&*I);
          }
        }
      }
    }
  }
  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    bool found = false;
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    auto fname = func->getName().str();
    if (is_alloc_function(fname) || is_free_function(fname))
      continue;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (!isa<CallInst>(&*I))
          continue;
        fname = get_callee_function_name(&*I).str();
        if (is_free_function(fname)) {
          // collect free type
          StructType *freeTy = get_free_type(&*I);
          auto fname = func->getName();
          if (!freeTy) {
            normal_free.insert(&*I);
            continue;
          }
          print_debug(freeTy, func, "free ty");
          free2sty[&*I] = freeTy;
          priv_free.insert(&*I);
        }
      }
    }
  }

  errs() << "normal_free  : " << normal_free.size() << "\n";
  errs() << "priv_free    : " << priv_free.size() << "\n";
  errs() << "normal_tys size: " << normal_tys.size() << "\n";
  errs() << "mte_tys size: " << mte_tys.size() << "\n";
  for (auto ty : mte_tys) {
    errs() << " - " << ty->getStructName() << "\n";
  }

}

// Collect Memory Accessing Functions
void kdfi::collect_access_func() {
  int count = 0;
  FunctionSet noaccess, access;
  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    bool found = false;
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    count++;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (!isa<LoadInst>(&*I) && !isa<StoreInst>(&*I) &&
            !is_asm(&*I))
          continue;
        if (is_asm(&*I)) {
          for (int i=0; i<I->getNumOperands(); ++i) {
            if (is_asm_access(&*I, i)) {
              found = true;
              break;
            }
          }
        } else {
          int op = 0;
          if (isa<StoreInst>(&*I))
            op = 1;
          found = true;
        }
        if (found)
          break;
      }
      if (found)
        break;
    }

    if (!found)
      noaccess.insert(func);
    else
      access.insert(func);
  }

  FunctionSet rmset;
  for (auto func : noaccess) {
    bool found = false;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (!isa<CallInst>(&*I))
          continue;
        auto f = get_callee_function_direct(&*I);
        FunctionSet callees;
        if (!f) {
          get_indirect_call_dest(&*I, callees);
        } else {
          callees.insert(f);
        }
        for (auto ff : callees) {
          if (access.count(ff)) {
            rmset.insert(func);
            found = true;
            break;
          }
        }
        if (found)
          break;
      }
      if (found)
        break;
    }
  }
  for (auto rm : rmset) {
    noaccess.erase(rm);
    access.insert(rm);
  }

  for (auto func : access) {
    if (!is_skip_function(get_func_name(func->getName().str())))
      funcs.insert(func);
  }
  errs() << "Memory Access Function: " << access.size() << " / " << count << "\n";

  std::error_code EC;
  raw_fd_ostream out("noaccess.func", EC);
  for (auto f : noaccess) {
    out << get_func_name(f->getName().str()) << "\n";
  }
  total_access = 0;
  for (auto func : funcs) {
    //if (mte_skip_func.count(func))
    //    continue;
    //if (notcma.count(func))
    //    continue;
    ValueSet visited_mte, visited_pac;
    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (isa<LoadInst>(&*I) || isa<StoreInst>(&*I) || is_asm_access(&*I, 0))
          total_access++;
        else
          continue;
        if (isa<LoadInst>(&*I) || is_asm_load(&*I)) {
          if (isa<PointerType>(I->getType()))
            ptr_load.insert(&*I);
          else {
            for (auto u : I->users()) {
              if (isa<CastInst>(u) && isa<PointerType>(u->getType()) && !is_err_ptr(u)) {
                ptr_load.insert(&*I);
                break;
              }
            }
          }
        }
      }
    }
  }

  errs() << "total access: " << total_access << "\n";
  errs() << "ptr load : " << ptr_load.size() << "\n";


}
Instruction *kdfi::get_list_store_pair(Instruction *st)
{
    bool is_list = false;
    if (is_list_type(st->getOperand(0)->getType()))
        is_list = true;
    else {
        if (auto ci = dyn_cast<CastInst>(st->getOperand(0)))
            if (is_list_type(ci->getOperand(0)->getType()))
                is_list = true;
        if (auto ci = dyn_cast<CastInst>(st->getOperand(1)))
            if (is_list_type(ci->getOperand(0)->getType()))
                is_list = true;
    }       
    if (!is_list)
        return nullptr;

    // find: store src -> store dest / store dest -> store src
    Value *src = st->getOperand(0);
    Value *dst = st->getOperand(1);
    BasicBlock *bb = st->getParent();
    
    ValueSet srcs;
    srcs.insert(src);
    for (auto u : src->users()) {
        if (isa<CastInst>(u) ||
                (isa<GetElementPtrInst>(u) && is_list_type(u->getOperand(0)->getType()))) {
            srcs.insert(u);
        } 
    }
    if (isa<CastInst>(src) || (isa<LoadInst>(src) && is_list_type(src->getType()))) {
        for (auto u : cast<User>(src)->getOperand(0)->users()) {
            if (isa<CastInst>(u) ||
                (isa<GetElementPtrInst>(u) && is_list_type(u->getOperand(0)->getType()))) {
            srcs.insert(u);
            } 
        }
    }
    for (auto I = bb->begin(), E = bb->end(); I != E; ++I) {
        Value *dst = nullptr;
        if (isa<StoreInst>(&*I)) {
            dst = I->getOperand(1);
        } else if (is_asm_store(&*I, 1)) {
            dst = I->getOperand(0);
        } else {
            continue;
        }
        if (srcs.count(dst))
            return &*I;
    }      
    ValueSet dsts;
    dsts.insert(dst);
    for (auto u : dst->users()) {
        if (isa<CastInst>(u) ||
                (isa<GetElementPtrInst>(u) && is_list_type(u->getOperand(0)->getType()))) {
            dsts.insert(u);
        } 
    }
    if (isa<CastInst>(dst) || (isa<LoadInst>(dst) && is_list_type(dst->getType())))  {
        for (auto u : cast<User>(dst)->getOperand(0)->users()) {
            if (isa<CastInst>(u) ||
                (isa<GetElementPtrInst>(u) && is_list_type(u->getOperand(0)->getType()))) {
            dsts.insert(u);
            } 
        }
    }

    for (auto I = bb->begin(), E = bb->end(); I != E; ++I) {
        Value *src = nullptr;
        if (isa<StoreInst>(&*I)) {
            src = I->getOperand(0);
        } else if (is_asm_store(&*I, 1)) {
            src = I->getOperand(1);
        } else {
            continue;
        }
        if (dsts.count(src))
            return &*I;
    }      
    return nullptr;

}


void kdfi::get_pstr_from_pptr(Instruction *i, ValueSet *vset) {
    ValueSet visited;
    ValueList worklist;
    Value *start = i;
    if (isa<CastInst>(i))
        start = i->getOperand(0);
    visited.insert(start);
    for (auto u : start->users())
        worklist.push_back(u);
    while (worklist.size()) {
        Value *vv = worklist.front();
        worklist.pop_front();
        if (visited.count(vv))
            continue;
        if (!isa<StoreInst>(vv))
            visited.insert(vv);
        Instruction *ii;
        if (isa<Instruction>(vv))
            ii = cast<Instruction>(vv);
        else if (isa<ConstantExpr>(vv)) {
            ii = cast<ConstantExpr>(vv)->getAsInstruction();
            dummyCE[ii] = i->getFunction();
        }
        else
            continue;
        switch(ii->getOpcode()) {
            case Instruction::Load:
                vset->insert(vv);
                break;
            case Instruction::Store:
                if (!visited.count(ii->getOperand(0)) &&
                    std::find(worklist.begin(), worklist.end(), ii->getOperand(0)) == worklist.end())
                    vset->insert(ii->getOperand(0));
                break;
            case Instruction::BitCast:
            case Instruction::IntToPtr:
            case Instruction::PtrToInt:
                for (auto u : vv->users())
                    worklist.push_back(u);
            default:
                break;
        }
    }
}

StructType *kdfi::get_cast_pstr_type(Value *v) {
  if (auto sty = get_pstr_type(v))
    return sty;
  if (auto li = dyn_cast<LoadInst>(v)) {
    if (auto ci = dyn_cast<CastInst>(li->getOperand(0))) {
      if (!is_err_ptr(ci)) {
        if (auto pty = dyn_cast<PointerType>(ci->getOperand(0)->getType())) {
          if (auto sty = get_pstr_type(pty->getElementType()))
            return sty;
        }
        if (auto listTy = get_list_type(ci->getOperand(0)->getType()))
          return listTy;
      }
    }
    if (auto ce = dyn_cast<ConstantExpr>(li->getOperand(0))) {
      if (ce->getOpcode() == Instruction::BitCast) {
        return get_pstr_type(ce->getOperand(0)->getType());
      }
    }
  } else if (is_asm_load(v)) {
    Value *src = cast<CallBase>(v)->getArgOperand(0);
    if (auto pty = dyn_cast<PointerType>(src->getType())) {
      if (auto ety = pty->getPointerElementType()) {
        if (auto sty = get_pstr_type(ety)) {
          return sty;
        }
      }
    }
  }
  for (auto u : v->users()) {
    if (isa<CastInst>(u) && !is_err_ptr(u))
      if (auto sty = get_pstr_type(u))
        return sty;
    if (isa<StoreInst>(u) && u->getOperand(0)==v) {
      if (auto ci = dyn_cast<CastInst>(u->getOperand(1))) {
        if (auto pty = dyn_cast<PointerType>(ci->getOperand(0)->getType())) {
          if (auto sty = get_pstr_type(pty->getPointerElementType())) {
            return sty;
          }
        }
      }
    }
  }
  return nullptr;
}

// collect privilege global object reference uses in
// function call / ret / store src
void kdfi::collect_gref_use() {
  std::set<unsigned> emptyset = {};
  std::set<unsigned> skipset = {Instruction::Call,Instruction::Ret};
  std::set<unsigned> skipset2 = {Instruction::GetElementPtr};

  errs() << "tagged gv reference : " << gref.size() << "\n";

  // inter-procedural tagged gv store
  for (auto v : gref) {
    ValueSet strset;

    if (isa<StoreInst>(v)) {
      strset.insert(v);
    } else {
      collect_forward(v, Instruction::Store, 0, &emptyset, &strset);
    }
    for (auto u : strset) {
      int dst_op = -1;
      if (isa<StoreInst>(u)) {
        dst_op = 1;
      } else if (is_asm(u)) {
        dst_op = get_asm_addr(u);
      }

      if (dst_op < 0)
        continue;

      // collect gvs that may store gref (regardless of offset)
      // and consider the values being loaded from the gvs as safe ptrs
      int offset = 0;
      if (auto gv = get_global(cast<User>(u)->getOperand(dst_op), &offset)) {
        // print_debug(v, "gref");
        // print_debug(u, "tagged gvref store");
        // errs() << "gref_gv: " << gv->getName() << "+" << offset << "\n";
        gref_gvfields.insert(std::make_pair(gv, (unsigned)offset));
        gref_gv.insert(gv);
      }
    }
  }
}

void kdfi::get_gpfield(GlobalVariable *gv, Constant *c, int base) {
  if (!isa<ConstantAggregate>(c))
    return;
  if (c->isZeroValue())
    return;
  unsigned num = 0;
  StructType *_sty = nullptr;
  if (auto sty = dyn_cast<StructType>(c->getType())) {
    if (sty->hasName()) {
      if (sty->getName().startswith("struct.arm64_cpu_capabilities"))
        return;
      if (sty->getName().startswith("union.anon.81.2962"))
        return;
    }
    num = sty->getNumElements();
    _sty = cast<StructType>(get_type(sty));

  } else if (isa<ConstantVector>(c) || isa<ConstantArray>(c)) {
    num = c->getNumOperands();
  }

  for (unsigned i=0; i < num; ++i) {
    auto elem = c->getAggregateElement(i);
    if (!elem)
      continue;
    int offset = base;
    if (isa<ConstantStruct>(c)) {
      offset += DL->getStructLayout(cast<StructType>(c->getType()))->getElementOffset(i);
    } else if (isa<ConstantVector>(c) || isa<ConstantArray>(c)) {
      offset += DL->getTypeAllocSize(c->getAggregateElement((unsigned)0)->getType())*i;
    }
    // if (gv->getName()=="init_task") {
    //   if (_sty)
    //     errs() << "init_task ("<< i << ", +" << offset << ") " << *_sty->getElementType(i) <<"\n";
    // }
    if (elem->isZeroValue())
      continue;

    if (auto pty = get_pstr_type(elem->getType())) {
      if (pobj.count(pty) || pptr.count(pty)) {
        gpfields.insert(std::make_pair(gv, offset));
      } else if (_sty && i < _sty->getNumElements() ) {
        if (pty = get_pstr_type(_sty->getElementType(i))) {
          if (pobj.count(pty) || pptr.count(pty)) {
            gpfields.insert(std::make_pair(gv, offset));
          }
        }
      }
      if (!pobj.count(pty) && !pptr.count(pty)) {
        if (priv_gobj.count(elem) || priv_gobj.count(elem->stripPointerCasts())) {
          errs() << "gref_gvfield: " << gv->getName() << "+" << offset <<"\n";
          gref_gvfields.insert(std::make_pair(gv, (unsigned)offset));
          gref_gv.insert(gv);
        }
      }
    } else if (auto pty = get_pstr_type(elem->stripPointerCasts()->getType())) {
      if (pobj.count(pty) || pptr.count(pty)) {
        gpfields.insert(std::make_pair(gv, offset));
        errs() << "gpfields: " << gv->getName() << "+" << offset << "\n";
        continue;
      }
    } else {
      get_gpfield(gv, elem, offset);
    }
  }
}

void kdfi::get_listfield(GlobalVariable *gv, Constant *c, int base) {
  if (!isa<ConstantAggregate>(c))
    return;
  if (c->isZeroValue())
    return;
  unsigned num = 0;
  StructType *_sty = nullptr;
  if (auto sty = dyn_cast<StructType>(c->getType())) {
    if (sty->hasName()) {
      if (sty->getName().startswith("struct.arm64_cpu_capabilities"))
        return;
      if (sty->getName().startswith("union.anon.81.2962"))
        return;
    }
    num = sty->getNumElements();
    _sty = cast<StructType>(get_type(sty));

  } else if (isa<ConstantVector>(c) || isa<ConstantArray>(c)) {
    num = c->getNumOperands();
  }
  for (unsigned i=0; i < num; ++i) {
    auto elem = c->getAggregateElement(i);
    if (!elem)
      continue;
    int offset = base;
    if (isa<ConstantStruct>(c)) {
      offset += DL->getStructLayout(cast<StructType>(c->getType()))->getElementOffset(i);
    } else if (isa<ConstantVector>(c) || isa<ConstantArray>(c)) {
      offset += DL->getTypeAllocSize(c->getAggregateElement((unsigned)0)->getType())*i;
    }
    if (elem->isZeroValue())
      continue;
    if (auto pty = get_pstr_type(elem->getType())) {
      if (pty->getName().startswith("struct.list_head")) {
        list_fields.insert(std::make_pair(gv, offset));
        errs() << "list_fields: " << gv->getName() << "+" << offset << "\n";
      } else if (_sty && i < _sty->getNumElements() ) {
        if (pty = get_pstr_type(_sty->getElementType(i))) {
          if (pty->getName().startswith("struct.list_head")) {
            list_fields.insert(std::make_pair(gv, offset));
            errs() << "list_fields: " << gv->getName() << "+" << offset << "\n";
          }
        }
      }
    } else if (auto pty = get_pstr_type(elem->stripPointerCasts()->getType())) {
      if (pty->getName().startswith("struct.list_head")) {
        list_fields.insert(std::make_pair(gv, offset));
        errs() << "list_fields: " << gv->getName() << "+" << offset << "\n";
        continue;
      }
    } else {
      get_listfield(gv, elem, offset);
    }
  }
}


// collect privilege global object references
void kdfi::collect_gref() {

  for (auto &gv : m->globals()) {
    // struct pointer type global variable
    if (auto sty = get_pstr_type(gv.getType()->getPointerElementType())) {
      if (pptr.count(sty))
        priv_gptr.insert(&gv);
    }

    if (!gv.hasInitializer())
      continue;

    // struct type global variable
    if (auto sty = get_pstr_type(gv.getType())) {

      Constant *init = gv.getInitializer();
      if (!init)
        continue;
      if (auto cs = dyn_cast<ConstantStruct>(init)) {
        if (cs->isZeroValue())
          continue;
        get_gpfield(&gv, cs, 0);
      }
    }
    // array type global variable
    else if (is_parr_type(gv.getType())) {
      Constant *init = gv.getInitializer();
      if (!init)
        continue;
      if (init->isZeroValue())
        continue;

      unsigned num = init->getType()->getArrayNumElements();
      auto ety = cast<ArrayType>(init->getType())->getElementType();
      // struct pointer array
      if (auto sty = get_pstr_type(ety)) {
        if (!pptr.count(sty))
          continue;
        for (unsigned i=0; i<num; ++i) {
          if (!init->getAggregateElement(i)->isZeroValue()) {
            int offset = 8*i;
            gpfields.insert(std::make_pair(&gv, offset));
            errs() << "gpfields: " << gv.getName() << "+" << offset <<"\n";
          }
        }
      }
      // struct array
      else if (auto sty = dyn_cast<StructType>(ety)) {
        if (sty->hasName()) {
          if (sty->getName().startswith("struct.arm64_cpu_capabilities"))
            continue;
        }

        for (unsigned n=0; n < num; ++n) {
          if (!init->getAggregateElement(n))
            continue;
          auto elem = init->getAggregateElement(n)->stripPointerCasts();
          if (elem->isZeroValue())
            continue;
          int base = DL->getTypeAllocSize(sty)*n;
          get_gpfield(&gv, elem, base);
        }
      }
    }
    // pointer type global variable
    else if (isa<PointerType>(gv.getType()->getPointerElementType())) {
      Constant *elem = gv.getInitializer();
      int offset = 0;
      if (!elem)
        continue;
      if (elem->isZeroValue())
        continue;
      if (auto pty = get_pstr_type(elem->getType())) {
        if (pobj.count(pty) || pptr.count(pty)) {
          gpfields.insert(std::make_pair(&gv, offset));
          errs() << "gpfields: " << gv.getName() << "+" << offset << "\n";
        }
        if (priv_gobj.count(elem) || priv_gobj.count(elem->stripPointerCasts())) {
          errs() << "gref_gvfield: " << gv.getName() << "+" << offset <<"\n";
          gref_gvfields.insert(std::make_pair(&gv, (unsigned)offset));
          gref_gv.insert(&gv);
        }
      }
    }
  }

  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    if (is_alloc_function(func->getName().str()) || is_free_function(func->getName().str()))
      continue;

    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (isa<LoadInst>(&*I))
          continue;
        if (isa<StoreInst>(&*I)) {
          if (is_global(I->getOperand(0), &priv_gobj))
            gref.insert(&*I);
          continue;
        } else if (auto ci = dyn_cast<CallInst>(&*I)) {
          if (is_builtin_container_of(ci) || is_asm(ci) || is_alloc_inst(ci))
            continue;
          FunctionSet funcs;
          get_call_dest(&*I, funcs);

          for (auto f : funcs) {
            for (int i=0; i<ci->arg_size() && i<f->arg_size(); ++i) {
              if (is_global(ci->getArgOperand(i), &priv_gobj)) {
                gref.insert(f->getArg(i));
                inter_safe_ptr.insert(f->getArg(i));
              }
            }
          }
          continue;
        }

        for (auto &u : I->operands()) {
          if (is_global(u.get(), &priv_gobj)) {
            gref.insert(&*I);
            safe_ptr.insert(&*I);
          }
        }
      }
    }
  }
}

// collect non-priv and priv ptrs from load or gep
void kdfi::collect_ptr() { 
  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    
    Function *func = dyn_cast<Function>(fi);
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    if (is_alloc_function(func->getName().str()))
      continue;

    bool debug = false;
    if (func->getName()=="dev_vprintk_emit") debug=true;

    for (auto &arg : func->args()) {
      if (auto sty = get_cast_pstr_type(&arg)) {
        if (pobj.count(sty) || is_nested_pobj(sty)) {
          priv_ptr.insert(&arg);
          safe_ptr.insert(&arg);
        }
        else if (is_pte_type(sty)) {
          safe_ptr.insert(&arg);
        } else {
          unsafe_ptr.insert(&arg);
        }
        if (parent_type.count(sty)) {
          parent_ptr.insert(&arg);
          auto tset = copy2sty[&arg];
          if (!tset) {
            tset = new TypeSet;
            copy2sty[&arg] = tset;
          }
          tset->insert(sty);
        }
      }
    }

    for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (isa<LoadInst>(&*I)) {
          if (isa<IntegerType>(I->getType()) &&
              I->getType()->getPrimitiveSizeInBits() < 64)
            continue;

          bool is_priv_ptr = false;
          bool is_safe_ptr = false;
          bool is_unsafe_ptr = false;
          auto sty = get_cast_pstr_type(&*I);
          if (sty) {
            if (pobj.count(sty) ||
                is_nested_pobj(sty)) {
              is_priv_ptr = true;
              is_safe_ptr = true;
            } else if (is_pte_type(sty) || is_list_type(sty)) {
              is_safe_ptr = true;
            } else {
              is_unsafe_ptr = true;
            }
            if (parent_type.count(sty)) {
              parent_ptr.insert(&*I);
              auto tset = copy2sty[&*I];
              if (!tset) {
                tset = new TypeSet;
                copy2sty[&*I] = tset;
              }
              tset->insert(sty);
            }
          }

          // gref_gvfields
          int offset = 0;
          if (auto gv = get_global(I->getOperand(0), &offset)) {
            if (gref_gvfields.count(std::make_pair(gv, (unsigned)offset))) {
              is_priv_ptr=true;
              is_safe_ptr=true;
            }
          }

          if (is_priv_ptr)
            priv_ptr.insert(&*I);
          if (is_safe_ptr)
            safe_ptr.insert(&*I);
          if (is_unsafe_ptr)
            unsafe_ptr.insert(&*I);

        } else if (is_asm(&*I)) {
          if (is_asm_get_current(&*I)) {
            priv_ptr.insert(&*I);
            safe_ptr.insert(&*I);
            auto tset = copy2sty[&*I];
            if (!tset) {
              tset = new TypeSet;
              copy2sty[&*I] = tset; 
            }
            tset->insert(taskTy);
            parent_ptr.insert(&*I);
          }
          else if (is_asm_load(&*I)) {
            if (auto sty = get_cast_pstr_type(&*I)) {
              if (pobj.count(sty) ||
                  is_nested_pobj(sty)) {
                priv_ptr.insert(&*I);
                safe_ptr.insert(&*I);
              }
              else if (is_pte_type(sty) || is_list_type(sty)) {
                safe_ptr.insert(&*I);
              } else {
                unsafe_ptr.insert(&*I);
              }
              if (parent_type.count(sty)) {
                parent_ptr.insert(&*I);
                auto tset = copy2sty[&*I];
                if (!tset) {
                  tset = new TypeSet;
                  copy2sty[&*I] = tset;
                }
                tset->insert(sty);
              }
            }
          }
        } else if (isa<GetElementPtrInst>(&*I)) {
          if (auto sty = get_pstr_type(I->getOperand(0)->getType())) {
            if (pobj.count(sty) ||
                is_nested_pobj(sty)) {
              priv_ptr.insert(I->getOperand(0));
              safe_ptr.insert(I->getOperand(0));
            } else if (is_pte_type(sty))
              // is_list_type(sty) ||
              safe_ptr.insert(I->getOperand(0));
          }

          StructType *sty = nullptr;
          // nested struct field
          sty = get_cast_pstr_type(&*I);
          if (!isa<PointerType>(I->getType()))
            continue;

          if (sty) {
            if (parent_type.count(sty)) {
                parent_ptr.insert(&*I);
                auto tset = copy2sty[&*I];
                if (!tset) {
                  tset = new TypeSet;
                  copy2sty[&*I] = tset;
                }
                tset->insert(sty);
            }
          }
          sty = nullptr;

          // struct pointer field
          sty = get_pstr_type(I->getType()->getPointerElementType());

          bool is_gref_field=false;
          if (!sty) {
            // check if this is global object reference in global variable
            sty = get_pstr_type(I->getOperand(0)->getType());
            if (!sty)
              continue;
            if (I->getNumOperands() < 3)
              continue;
            if (!isa<ConstantInt>(I->getOperand(2)))
              continue;
            continue;
            int idx = cast<ConstantInt>(I->getOperand(2))->getZExtValue();
            bool found=false;
            for (auto f : gref_fields) {
              if (f.first!=sty)
                continue;
              if (f.second != idx)
                continue;
              found = true;
            }
            if (!found)
              continue;
            is_gref_field=true;
          }

          ValueSet ldset, inter_ldset;
          std::set<unsigned> skipset1 = {Instruction::GetElementPtr, Instruction::Call, Instruction::Ret};
          std::set<unsigned> skipset2 = {Instruction::GetElementPtr};

          collect_forward(&*I, Instruction::Load, 0, &skipset1, &ldset);
          collect_forward(&*I, Instruction::Load, 0, &skipset2, &inter_ldset);
          for (auto ld : inter_ldset) {
            if (pobj.count(sty) ||
                is_nested_pobj(sty) || is_gref_field) {
                priv_ptr.insert(ld);
                if (ldset.count(ld))
                  safe_ptr.insert(ld);
                else 
                  inter_safe_ptr.insert(ld);
            } else if (/*is_list_type(sty) || */is_pte_type(sty)) {
              if (ldset.count(ld))
                safe_ptr.insert(ld);
              else
                inter_safe_ptr.insert(ld);
            }
            else {
              if (ldset.count(ld))
                unsafe_ptr.insert(ld);
              else
                inter_unsafe_ptr.insert(ld);
            }

            if (parent_type.count(sty) && !is_gref_field) {
                parent_ptr.insert(ld);
                auto tset = copy2sty[ld];
                if (!tset) {
                  tset = new TypeSet;
                  copy2sty[ld] = tset;
                }
                tset->insert(sty);
            }
          }
        } else if (isa<CallInst>(&*I)) {
          if (auto sty = get_cast_pstr_type(&*I)){
            if (pobj.count(sty) || is_nested_pobj(sty)) {
              priv_ptr.insert(&*I);
              safe_ptr.insert(&*I);
            } else if (is_list_type(sty)) {
              continue;
            } else if (is_pte_type(sty)) {
              safe_ptr.insert(&*I);
            } else {
              unsafe_ptr.insert(&*I);
            }
            if (parent_type.count(sty)) {
              parent_ptr.insert(&*I);
              auto tset = copy2sty[&*I];
              if (!tset) {
                tset = new TypeSet;
                copy2sty[&*I] = tset;
              }
              tset->insert(sty);
            }
          }
          FunctionSet funcs;
          auto ci = cast<CallInst>(&*I);
          get_call_dest(&*I, funcs);

          for (auto f : funcs) {
            for (int i=0; i < ci->arg_size() && i<f->arg_size(); ++i) {
              int offset = 0;
              if (auto gv = get_global(ci->getArgOperand(i), &offset)) {

                ValueSet refset, gepset, ldset;
                std::set<unsigned> emptyset={};
                std::set<unsigned> skipset={Instruction::GetElementPtr, Instruction::Add, Instruction::Sub};

                if (gref_gvfields.count(std::make_pair(gv, (unsigned)offset))) {
                  refset.insert(f->getArg(i));
                } else if (gref_gv.count(gv)) {
                  collect_forward(f->getArg(i), Instruction::GetElementPtr, 0, &emptyset, &gepset);
                  for (auto gep : gepset) {
                    auto off = gep2offset(cast<Instruction>(gep));
                    if (off > 0) {
                      if (gref_gvfields.count(std::make_pair(gv, (unsigned)(offset+off)))) {
                        refset.insert(gep);
                      }
                    }
                  }
                }
                for (auto ref : refset) {
                  collect_forward(ref, Instruction::Load, 0, &skipset, &ldset);
                  for (auto ld : ldset) {
                    inter_safe_ptr.insert(ld);
                  }
                }
              }
            }
          } // funcs
        } else if (isa<AllocaInst>(&*I)) {
          stack_ref.insert(&*I);
        }
      } // &*I 
    } // &B
  } // func

}

void kdfi::collect_ptr_access() {
  std::set<unsigned> emptyset = {};
  std::set<unsigned> skipset = {Instruction::Call, Instruction::Ret};
  ValueSet intra_both_access;
  UseSet visited_ld, visited_str;

  errs() << "\nsafe_ptr      : " << safe_ptr.size() << "\n";
  errs() << "\ninter_safe_ptr      : " << inter_safe_ptr.size() << "\n";
  for (auto ld : safe_ptr) {
    ValueSet ldset, strset;
    // intra-procedural safe access
    if (!isa<Argument>(ld)) {
      collect_forward(ld, Instruction::Load, 0, &skipset, &ldset, &visited_ld);
      collect_forward(ld, Instruction::Store, 1, &skipset, &strset, &visited_str);
      for (auto i : ldset)
        intra_safe_access.insert(i);
      for (auto i : strset)
        intra_safe_access.insert(i);
    }
  }

  visited_ld.clear();
  visited_str.clear();

  for (auto ld : safe_ptr) {
    ValueSet ldset, strset;
    // inter-procedural safe access
    collect_forward(ld, Instruction::Load, 0, &emptyset, &ldset, &visited_ld);
    collect_forward(ld, Instruction::Store, 1, &emptyset, &strset, &visited_str);
    for (auto i : ldset) {
      safe_access.insert(i);
    }
    for (auto i : strset) {
      safe_access.insert(i);
    }
  }

  visited_ld.clear();
  visited_str.clear();

  for (auto ld : inter_safe_ptr) {
    ValueSet ldset, strset;
    // inter-procedural safe access
    collect_forward(ld, Instruction::Load, 0, &emptyset, &ldset, &visited_ld);
    collect_forward(ld, Instruction::Store, 1, &emptyset, &strset, &visited_str);
    for (auto i : ldset)
      safe_access.insert(i);
    for (auto i : strset)
      safe_access.insert(i);
  }

  errs() << "\nunsafe_ptr    : " << unsafe_ptr.size() << "\n";
  errs() << "\ninter_unsafe_ptr    : " << inter_unsafe_ptr.size() << "\n";

  visited_ld.clear();
  visited_str.clear();

  for (auto ld : unsafe_ptr) {
    ValueSet ldset, strset;

    // intra-procedural unsafe access
    collect_forward(ld, Instruction::Load, 0, &skipset, &ldset, &visited_ld);
    collect_forward(ld, Instruction::Store, 1, &skipset, &strset, &visited_str);
    for (auto i : ldset)
      intra_unsafe_access.insert(i);
    for (auto i : strset)
      intra_unsafe_access.insert(i);
  }
  
  visited_ld.clear();
  visited_str.clear();

  for (auto ld : unsafe_ptr) {
    ValueSet ldset, strset;

    // inter-procedrual unsafe access
    collect_forward(ld, Instruction::Load, 0, &emptyset, &ldset, &visited_ld);
    collect_forward(ld, Instruction::Store, 1, &emptyset, &strset, &visited_str);
    for (auto i : ldset)
      unsafe_access.insert(i);
    for (auto i : strset)
      unsafe_access.insert(i);
  }

  visited_ld.clear();
  visited_str.clear();

  for (auto ld : inter_unsafe_ptr) {
    ValueSet ldset, strset;

    // inter-procedrual unsafe access
    collect_forward(ld, Instruction::Load, 0, &emptyset, &ldset, &visited_ld);
    collect_forward(ld, Instruction::Store, 1, &emptyset, &strset, &visited_str);
    for (auto i : ldset)
      unsafe_access.insert(i);
    for (auto i : strset)
      unsafe_access.insert(i);
  }

  for (auto i : intra_unsafe_access) {
    if (intra_safe_access.count(i))
      intra_both_access.insert(i);
  }
  for (auto i : intra_both_access) {
    intra_unsafe_access.erase(i);
  }

  for (auto i : unsafe_access) {
    if (safe_access.count(i))
      both_access.insert(i);
  }

  for (auto i : both_access) {
    unsafe_access.erase(i);
  }

  //for (auto i : safe_access) {
  //  if (!intra_unsafe_access.count(i))
  //    inter_safe_access.insert(cast<Instruction>(i));
  //}
  for (auto i : intra_unsafe_access) {
    if (both_access.count(i)) {
      inter_safe_access.insert(cast<Instruction>(i));
    }
  }
  for (auto i : unsafe_access) {
    if (!intra_unsafe_access.count(i)) {
      inter_unsafe_access.insert(cast<Instruction>(i));
    }
  }

  int safe_load=0;
  int safe_store=0;
  int safe_copy=0;
  for (auto i : safe_access) {
    if (isa<LoadInst>(i) || is_asm_load(i))
      safe_load++;
    else if (isa<StoreInst>(i) || is_asm_store(i))
      safe_store++;
    else if (isa<CallInst>(i))
      safe_copy++;
  }

  int unsafe_load = 0;
  int unsafe_store = 0;
  int unsafe_copy = 0;
  for (auto i : unsafe_access) {
    if (isa<LoadInst>(i) || is_asm_load(i))
      unsafe_load++;
    else if (isa<StoreInst>(i) || is_asm_store(i))
      unsafe_store++;
    else if (isa<CallInst>(i))
      unsafe_copy++;
  }

  int both_load = 0;
  int both_store = 0;
  int both_copy = 0;
  for (auto i : both_access) {
    if (isa<LoadInst>(i) || is_asm_load(i))
      both_load++;
    else if (isa<StoreInst>(i) || is_asm_store(i))
      both_store++;
    else if (isa<CallInst>(i))
      both_copy++;
  }


  errs() << "safe_access   : " << safe_access.size() << "\n";
  errs() << "    load      : " << safe_load << "\n";
  errs() << "   store      : " << safe_store << "\n";
  errs() << "    copy      : " << safe_copy << "\n";

  errs() << "unsafe_access : " << unsafe_access.size() << "\n";
  errs() << "    load      : " << unsafe_load << "\n";
  errs() << "   store      : " << unsafe_store << "\n";
  errs() << "    copy      : " << unsafe_copy << "\n";

  errs() << "both_access   : " << both_access.size() << "\n";
  errs() << "    load      : " << both_load << "\n";
  errs() << "   store      : " << both_store << "\n";
  errs() << "    copy      : " << both_copy << "\n";


  errs() << "intra_safe_access  : " << intra_safe_access.size() << "\n";
  errs() << "intra_unsafe_access: " << intra_unsafe_access.size() << "\n";
  errs() << "inter_safe_access  : " << inter_safe_access.size() << "\n";
  errs() << "inter_unsafe_access: " << inter_unsafe_access.size() << "\n";




  int gv_cnt=0;
  for (auto &gv : m->globals()) {
    if (!gv.hasName())
      continue;
    if (gv.getName().startswith("__param"))
      continue;
    if (gv.getName().startswith(".compound"))
      continue;
    all_gv.insert(&gv);
    gv_cnt++;
  }

  TypeSet styset;
  for (auto s : m->getIdentifiedStructTypes()) {
    if (!s->hasName())
      continue;
    if (is_anon_type(s->getName()))
      continue;
    
    auto sty = cast<StructType>(get_type(s));
    styset.insert(sty);
  } 


  errs() << "total global variables: " << gv_cnt << "\n";
  errs() << "total struct types    : " << styset.size() << "\n";

}

void kdfi::collect_pptr_ref() {

  // priv_ref struct type: struct types that contain priv pointer as its first field.
  for (auto s : m->getIdentifiedStructTypes()) {
    if (!s->hasName())
      continue;
    if (is_anon_type(s->getName()))
      continue;
    if (s->getNumElements()==0)
      continue;
    auto sty = cast<StructType>(get_type(s));

    TypeSet visited;
    auto esty = get_pstr_type(sty->getElementType(0));
    while(esty) {
      if (visited.count(esty))
        break;
      visited.insert(esty);
      if (pptr.count(get_type(esty))) {
        priv_ref.insert(sty);
        break;
      }
      if (auto _sty = dyn_cast<StructType>(esty)) {
      if (_sty->getNumElements()==0)
        break;
        esty = get_pstr_type(_sty->getElementType(0));
      } else {
        break;
      }  
    }
  }

  for (Module::iterator fi = m->begin(), fe = m->end();
         fi != fe; ++fi) {
      Function *func = dyn_cast<Function>(fi);
      if (!func)
        continue;
      if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
        continue;
      if (is_alloc_function(func->getName().str()))
        continue;
      for (auto &arg : func->args()) {
        if (auto sty = get_cast_pstr_type(&arg)) {
          if (priv_reftype.count(sty)) {
            pptr_ref.insert(&arg);
          }
        }
        if (isa<PointerType>(arg.getType())) {
          if (auto sty = get_pstr_type(arg.getType()->getPointerElementType())) {
            if (pptr.count(sty)) {
              pptr_ref.insert(&arg);
            }
          }
        }
      }

      for (auto &B : *func) {
        for (auto I = B.begin(), E = B.end(); I != E; ++I) {
          if (isa<AllocaInst>(&*I)) {
            if (auto sty = get_pstr_type(I->getType()->getPointerElementType())) {
              if (pptr.count(sty)) {
                pptr_ref.insert(&*I);
              }
            }
            if (auto sty = get_pstr_type(I->getType())) {
              if (priv_reftype.count(sty)) {
                pptr_ref.insert(&*I);
              }
            }
          }
          else if (isa<BinaryOperator>(&*I)) {
            // per_cpu ptr
            std::set<unsigned> skipset = {/*Instruction::Add,*/ Instruction::Sub,
                                  Instruction::Shl, Instruction::GetElementPtr};
            if (I->getOpcode()==Instruction::Add) {
              if (is_global(I->getOperand(1), &gpptr, &skipset)) {
                pptr_ref.insert(&*I);
              }

              else if (auto ce = dyn_cast<ConstantExpr>(I->getOperand(1))) {
                if (ce->getOpcode()==Instruction::PtrToInt) {
                  auto ety = cast<PointerType>(ce->getOperand(0)->getType())->getPointerElementType();
                  // ptrtoint (%struct.xxx**)
                  if (auto sty = get_pstr_type(ety)) {
                    if(pptr.count(sty))
                      pptr_ref.insert(&*I);

                  // ptrtoint ([n x %struct.xxx*]*)
                  } else if (auto ty = get_parr_type(ce->getOperand(0)->getType())) {
                    if (auto sty = get_pstr_type(ty)) {
                      if (pptr.count(sty))
                        pptr_ref.insert(&*I);
                    }
                  }
                }
              }
            }
          } else if (isa<IntToPtrInst>(&*I)) {
            // per_cpu ptr
            // inttoptr i64 to %struct.xxx**
            if (auto sty = get_pstr_type(I->getType()->getPointerElementType())) {
              if (auto b = dyn_cast<BinaryOperator>(I->getOperand(0))) {
                if (b->getOpcode()==Instruction::Add) {
                  if (pptr.count(sty)) {
                    pptr_ref.insert(&*I);
                  }
                }
              }
            // inttoptr i64 to [n x %struct.xxx*]*
            } else if (auto ty = get_parr_type(I->getType())) {
              if (auto sty = get_pstr_type(ty)) {
                if (auto b = dyn_cast<BinaryOperator>(I->getOperand(0))) {
                  if (b->getOpcode()==Instruction::Add) {
                    if (pptr.count(sty)) {
                      pptr_ref.insert(&*I);
                    }
                  }
                }
              }
            }
          }
          else if (isa<GetElementPtrInst>(&*I)) {
            // struct * field
            if (auto sty = get_pstr_type(I->getType()->getPointerElementType())) {
              if (pptr.count(sty)) {
                pptr_ref.insert(&*I);
              }
            }
            // struct ** field
            if (auto pty = dyn_cast<PointerType>(I->getType())) {
              if (pty = dyn_cast<PointerType>(pty->getPointerElementType())) {
                if (auto sty = get_pstr_type(pty->getPointerElementType())) {
                  if (pptr.count(sty)) {
                    ValueSet ldset;
                    std::set<unsigned> skipset = {Instruction::Add, Instruction::Sub,
                                                  Instruction::Shl, Instruction::GetElementPtr};
                    collect(&*I, Instruction::Load, 0, &skipset, &ldset);
                    for (auto ld : ldset) {
                      pptr_ref.insert(ld);
                    }
                  }
                }
              }
            }
          } else if (isa<LoadInst>(&*I)) {
            if (auto ce = dyn_cast<ConstantExpr>(I->getOperand(0))) {
              if (ce->getOpcode()==Instruction::GetElementPtr) {
                if (auto sty = get_pstr_type(ce->getType()->getPointerElementType())) {
                  if (pptr.count(sty)) {
                    pptr_load.insert(&*I);
                  }
                }
              }
              if (ce->getOpcode()==Instruction::BitCast) {
                if (ce = dyn_cast<ConstantExpr>(ce->getOperand(0))) {
                  if (ce->getOpcode()==Instruction::GetElementPtr) {
                    if (auto sty = get_pstr_type(ce->getType()->getPointerElementType())) {
                      if (pptr.count(sty)) {
                        pptr_load.insert(&*I);
                      }
                    }
                  }
                }
              }
            }
          } else if (isa<StoreInst>(&*I)) {
            if (auto ce = dyn_cast<ConstantExpr>(I->getOperand(1))) {
              if (ce->getOpcode()==Instruction::GetElementPtr) {
                if (auto sty = get_pstr_type(ce->getType()->getPointerElementType())) {
                  if (pptr.count(sty)) {
                    pptr_store.insert(&*I);
                  }
                }
              }
              if (ce->getOpcode()==Instruction::BitCast) {
                if (ce = dyn_cast<ConstantExpr>(ce->getOperand(0))) {
                  if (ce->getOpcode()==Instruction::GetElementPtr) {
                    if (auto sty = get_pstr_type(ce->getType()->getPointerElementType())) {
                      if (pptr.count(sty)) {
                        pptr_store.insert(&*I);
                      }
                    }
                  }
                }
              }
            }

          } else if (isa<CallInst>(&*I)) {

            // stlr *struct.ptr, **struct.ptr gep @global
            if (is_asm_store(&*I)) {
              auto op = get_asm_addr(&*I);
              auto addr = I->getOperand(op);
              if (auto ce = dyn_cast<ConstantExpr>(addr)) {
                if (ce->getOpcode()==Instruction::GetElementPtr) {
                  if (auto sty = get_pstr_type(ce->getType()->getPointerElementType())) {
                    if (pptr.count(sty)) {
                      pptr_store.insert(&*I);
                    }
                  }
                }
              }
              continue;
            }

            if (is_pac_skip(&*I)) {
              auto skip = I->getOperand(0);
              skip_ref.insert(skip);
              if (isa<CastInst>(skip))
                skip_ref.insert(cast<User>(skip)->getOperand(0));
              continue;
            }
            if (auto pty = dyn_cast<PointerType>(I->getType())) {
              if (auto sty = get_pstr_type(pty->getPointerElementType())) {
                if (pptr.count(sty)) {
                  pptr_ref.insert(&*I);
                  continue;
                }
              }
              if (auto sty = get_pstr_type(I->getType())) {
                if (priv_reftype.count(sty)) {
                  pptr_ref.insert(&*I);
                  continue;
                }
              }
            }
            if (is_alloc_inst(&*I)) {
              for (auto u : I->users()) {
                if (isa<CastInst>(u) && isa<PointerType>(u->getType())) {
                  if (auto sty = get_pstr_type(u->getType()->getPointerElementType())) {
                    if (pptr.count(sty)) {
                      pptr_ref.insert(&*I);
                      break;
                    }
                  }
                  if (auto sty = get_pstr_type(u->getType())) {
                    if (priv_reftype.count(sty)) {
                      pptr_ref.insert(&*I);
                      break;
                    }
                  }
                }
              }
            }
          } // CallInst
        }
      }
    }

    for (auto &gv : m->globals()) {
      // struct.xxx*
      if (auto sty = get_pstr_type(gv.getType()->getPointerElementType())) {
        if (pobj.count(sty) || pptr.count(sty)) {
          gpptr.insert(&gv);
        }

      // struct.xxx
      } else if (auto sty = get_pstr_type(gv.getType())) {
        if (priv_reftype.count(sty)) {
          gpptr.insert(&gv);
        }
      } else if (auto ty = get_parr_type(gv.getType())) {

        // [n x struct.xxx*]
        if (auto sty = get_pstr_type(ty)) {
          if (pobj.count(sty) || pptr.count(sty)) {
         //   errs() << "priv struct pointer array: " << gv.getName() << "\n";
         //   gpptr.insert(&gv);
          }
        }
        // [n x struct.xxx]
        if (auto sty = dyn_cast<StructType>(ty)) {
          if (priv_reftype.count(sty)) {
            gpptr.insert(&gv);
          }
        }
      }
    }

  }

// equal to KDFIInstrument::collect
  void kdfi::collect(Value *v, unsigned target_opcode, unsigned target_opnum,
                               std::set<unsigned> *skip_opcodes, ValueSet *results,
                               UseSet *visited) {
    UseSet _visited;
    UseList worklist;
    bool debug = false;
    if (!visited)
      visited = &_visited;

    for (auto &u : v->uses())
      worklist.push_back(&u);

    while(worklist.size()) {
      auto u = worklist.back();
      auto op = u->getOperandNo();
      auto vv = u->getUser();
      worklist.pop_back();

      if (visited->count(u))
        continue;
      visited->insert(u);


      if (debug)
        print_debug(vv, "collect-vv");

      if (isa<Argument>(vv)) {
        for (auto &u : vv->uses())
          worklist.push_back(&u);
        continue;
      }
      if (!isa<Instruction>(vv))
        continue;
      if (isa<TruncInst>(vv)) {
        if (is_err_ptr(vv))
          continue;
      }
      auto i = cast<Instruction>(vv);
      if (i->getOpcode() == target_opcode) {
        if (target_opnum < 0 || op == target_opnum) {
          results->insert(vv);
          continue;
        }
      }
      if (skip_opcodes && !is_asm(i))
        if (skip_opcodes->count(i->getOpcode()))
          continue;
      switch(i->getOpcode()) {
      case Instruction::Call:
        if (is_asm(i)) {
          int addr_op = get_asm_addr(i);
          if (op<0 || addr_op != op) {
            continue;
          }
          if (isa<IntegerType>(u->get()->getType()) &&
              u->get()->getType()->getPrimitiveSizeInBits() < 64) {
            continue;
          }
          if (target_opcode==Instruction::Load && is_asm_load(i)) {
            results->insert(i);
          } else if (target_opcode==Instruction::Store && is_asm_store(i)) {
              results->insert(i);
          }
        } else if (is_builtin_container_of(i)) {
          if (skip_opcodes && skip_opcodes->count(Instruction::GetElementPtr))
            continue;
          for (auto &uu : i->uses())
            worklist.push_back(&uu);
        } else if (is_alloc_inst(i)) {
          continue;
        } else if (auto callee=get_callee_function_direct(i)) {
          if (is_alloc_function(callee->getName().str()))
            continue;
          if (op >= callee->arg_size())
            continue;
          auto arg = callee->getArg(op);
          for(auto &uu : arg->uses()) {
            worklist.push_back(&uu);
          }
        }
        break;
      case Instruction::Select:
        if (op==1 || op==2) {
          for (auto &uu : i->uses())
            worklist.push_back(&uu);
        }
        break;
      case Instruction::PHI:
      case Instruction::GetElementPtr:
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
        for (auto &uu : i->uses()) {
          worklist.push_back(&uu);
        }
        break;

      case Instruction::Ret:
        for (auto u : i->getFunction()->users()) {
          if (auto ci = dyn_cast<CallInst>(u)) {
            if (is_alloc_function(ci->getFunction()->getName().str()))
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

  void kdfi::collect_pptr_access() {
    std::set<unsigned> emptyset = {};
    std::set<unsigned> skipset = {/*Instruction::Add,*/ Instruction::Sub,
                                  Instruction::Shl, Instruction::GetElementPtr};
    ValueSet eraseset;
    UseSet visited_ld, visited_str, visited_str_src;

    // intra-procedural
    for (auto ref : pptr_ref) {
      ValueSet ldset, strset;
      collect(ref, Instruction::Load, 0, &skipset, &ldset);
      collect(ref, Instruction::Store, 1, &skipset, &strset);
      for (auto i : ldset) {
        pptr_load.insert(cast<Instruction>(i));
      } for (auto i : strset) {
        pptr_store.insert(cast<Instruction>(i));
      }
    }

    for (auto ref : skip_ref) {
      ValueSet ldset, strset;
      std::set<unsigned> skipset2 = {Instruction::Call, Instruction::Ret};

      collect(ref, Instruction::Load, 0, &skipset2, &ldset);
      collect(ref, Instruction::Store, 1, &skipset2, &strset);
      for (auto i : ldset) {
        skip_load.insert(cast<Instruction>(i));
      } for (auto i : strset) {
        skip_store.insert(cast<Instruction>(i));
      }
    }

    // gptr and global pobj
    // check load/store to gptr or global pobj
    for (Module::iterator fi = m->begin(), fe = m->end(); fi != fe; ++fi) {
      Function *func = dyn_cast<Function>(fi);
      if (!func)
        continue;
      if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
        continue;

      for (auto &B : *func) {
        for (auto I = B.begin(), E = B.end(); I != E; ++I) {
          if (!isa<LoadInst>(&*I) && !isa<StoreInst>(&*I) && !is_asm(&*I))
            continue;
          int op=-1;
          if (isa<LoadInst>(&*I))
            op = 0;
          else if (isa<StoreInst>(&*I))
            op = 1;
          else {
            op = get_asm_addr(&*I);
          }
          if (op<0)
            continue;
          if (is_global(I->getOperand(op), &gpptr, &skipset)) {
            if (isa<LoadInst>(&*I) || is_asm_load(&*I)) {
              pptr_load.insert(&*I);
            } else {
              pptr_store.insert(&*I);
            }
          } 
        }
      }
    }

    // dump pptr access results

    errs() << "pptr_store: " << pptr_store.size() << "\n";
    errs() << "pptr_load: " << pptr_load.size() << "\n";
    errs() << "stack_ref: " << stack_ref.size() << "\n";


    return;

    collect_reachable_funcs();

    std::set<unsigned> skip_ops = {Instruction::Ret};

    for (auto s : priv_ptr) {
      collect_forward(s, Instruction::Load, 0, &emptyset, &priv_load, &visited_ld);
      collect_forward(s, Instruction::Store, 1, &emptyset, &priv_store, &visited_str);
    }
    visited_ld.clear();
    visited_str.clear();
    for (auto s : stack_ref) {
      collect_forward(s, Instruction::Load, 0, &emptyset, &stack_access, &visited_ld);
      collect_forward(s, Instruction::Store, 1, &emptyset, &stack_access, &visited_str);
    }
    visited_ld.clear();
    visited_str.clear();

    ValueSet auth_load, auth_store, auth_store_src;
    for (auto s : pptr_load) {
      if (!reachable_funcs.count(s->getFunction())) // not reachable
        continue;
      ValueSet this_load;
      collect_forward(s, Instruction::Load, 0, &skip_ops, &this_load, &visited_ld);
      for (auto i : this_load) {
        if (i != s) {
          auth_load.insert(i);
        }
      }
      collect_forward(s, Instruction::Store, 1, &skip_ops, &auth_store, &visited_str);
      collect_forward(s, Instruction::Store, 0, &skip_ops, &auth_store_src, &visited_str_src);      
    }
    

    visited_ld.clear();
    visited_str.clear();
    visited_str_src.clear();

    int authenticated_load_priv = 0;
    int authenticated_load_both = 0;
    int authenticated_store_priv = 0;
    int authenticated_store_both = 0;
    ValueSet authenticated_pac_src, authenticated_pac_dst;
    int authenticated_pac_src_dst = 0;

    for (auto i : auth_load) {
      if (both_access.count(i))
        authenticated_load_both++;
      else if (priv_load.count(i))
        authenticated_load_priv++;
      else
        authenticated_load_both++; // void ptr, etc.
    }
    for (auto i : auth_store) {
      if (both_access.count(i))
        authenticated_store_both++;
      else if (priv_store.count(i))
        authenticated_store_priv++;
      else 
        authenticated_store_both++; // void ptr, etc.
      
      if (pptr_store.count(cast<Instruction>(i))) {
        authenticated_pac_dst.insert(i);
      }
    }
    for (auto i : auth_store_src) {
      if (pptr_store.count(cast<Instruction>(i))) {
        authenticated_pac_src.insert(i);
        if (authenticated_pac_dst.count(i))
          authenticated_pac_src_dst++;
      }
    }
  
    errs() << "authenticated -> load: " << auth_load.size() << "\n";
    errs() << "          & priv: " << authenticated_load_priv << "\n";
    errs() << "          & mixed: " << authenticated_load_both << "\n";
    errs() << "authenticated -> store: " << auth_store.size() << "\n";
    errs() << "          & priv: " << authenticated_store_priv << "\n";
    errs() << "          & mixed: " << authenticated_store_both << "\n";
    errs() << "authenticated -> PAC SIGN\n";
    errs() << "          & src: " << authenticated_pac_src.size() << "\n";
    errs() << "          & dst: " << authenticated_pac_dst.size() << "\n";
    errs() << "          & src+dst: " << authenticated_pac_src_dst << "\n";

    visited_ld.clear();
    visited_str.clear();

    Value2Val pac2ptr;
  

    // priv_ptr, safe_ptr, unsafe_ptr
    InstructionSet unpriv_ptr_load, void_ptr_load;

    for (auto s : ptr_load) {
      if (pptr_load.count(s) && !skip_load.count(s)) // authenticated
        continue;
      //if (priv_load.count(s) || stack_access.count(s)) // loaded from priv. obj or stack
      //  continue;
      if (stack_access.count(s)) // loaded from stack
        continue;

      if (!reachable_funcs.count(s->getFunction())) // not reachable
        continue;

      // Exclude global variables from the memory corruption attack surface
      if (isa<LoadInst>(s)) {
        if (is_global(cast<LoadInst>(s)->getOperand(0), &all_gv)) {
          continue;
        }
      }
     if (auto sty = get_cast_pstr_type(s)) {
        auto sname = sty->getName();
        // Exclude struct.page
        if (sname.startswith("struct.page"))
          continue;
      }

      if (is_init(s))
        continue;

      if (unsafe_ptr.count(s))
        unpriv_ptr_load.insert(s);
      else 
        void_ptr_load.insert(s);
    }


    for (int n=0; n<2; ++n) {
      InstructionSet *vv = n ? &void_ptr_load : &unpriv_ptr_load;
      if (n) {
        errs() << "void ptr load: " << void_ptr_load.size() << "\n";
      } else {
        errs() << "unpriv ptr load: " << unpriv_ptr_load.size() << "\n";
      }

    int unprotected_ptr_load = 0;
    int unrestricted_ptr_load = 0;
    int has_pptr_load = 0;
    int has_fptr_load = 0;
    int not_reachable = 0;
    int mte_protected = 0;

    ValueSet unrestricted_load_unsafe, unrestricted_store_unsafe;
    ValueSet unprotected_load_unrestricted, unprotected_store_unrestricted;
    ValueSet unrestricted_pac_src, unrestricted_pac_dst, unrestricted_pac_oracle;
    ValueSet unprotected_pac_src, unprotected_pac_dst, unprotected_pac_oracle;

      for (auto s : *vv) {
        // Collect the Non-PAC-auted memory access
        ValueSet this_load, this_store, this_store_src;
        int this_cnt = 0;
        bool this_has_pptr_load = false;
        bool this_has_fptr_load = false;
        bool is_unreachable = !reachable_funcs.count(s->getFunction());
        bool is_mte_protected = priv_load.count(s);

        collect_forward(s, Instruction::Load, 0, &skip_ops, &this_load);
        collect_forward(s, Instruction::Store, 1, &skip_ops, &this_store);
        collect_forward(s, Instruction::Store, 0, &skip_ops, &this_store_src);

        for (auto i : this_load) {
          if (i == s)
            continue;
          if (pptr_load.count(cast<Instruction>(i))) {
            this_has_pptr_load = true; // priv. ptr -> PAC
          } else if (isa<PointerType>(i->getType())) {
            if (i->getType()->getPointerElementType()->isFunctionTy()) 
              this_has_fptr_load = true; // function pointer -> CFI
          }
          if (is_init(i)) {
            continue;
          }
          unprotected_load.insert(i);
          if (!unsafe_access.count(i)) {
            this_cnt++;
          }
        }
        for (auto i : this_store) {
          if (i == s)
            continue;
          if (is_init(i)) {
            continue;
          }
          unprotected_store.insert(i);
          if (!unsafe_access.count(i)) {
            this_cnt++;
          }
          if (pptr_store.count(cast<Instruction>(i))) {
            // unprotected ptr -> PAC store (PAC oracle dst)
            unprotected_pac_dst.insert(i);
            auto ptrset = pac2ptr[i];
            if (!ptrset) {
              ptrset = new ValueSet();
              pac2ptr[i] = ptrset;
            }
            ptrset->insert(s);
          
          }
        }
        for (auto i : this_store_src) {
          if (i == s)
            continue;
          if (is_init(i)) {
            continue;
          }
          if (pptr_store.count(cast<Instruction>(i))) {
            // unprotected ptr -> PAC store (PAC oracle src)
            unprotected_pac_src.insert(i);
            auto ptrset = pac2ptr[i];
            if (!ptrset) {
              ptrset = new ValueSet();
              pac2ptr[i] = ptrset;
            }
            ptrset->insert(s);
          }
        }
        
        if (this_has_pptr_load) {
          has_pptr_load++;
        }
        if (this_has_fptr_load) {
          has_fptr_load++;
        }
        if (is_unreachable) {
          not_reachable++;
        }
        if (is_mte_protected) {
          mte_protected++;
        }
        
        if (!this_has_pptr_load && !this_has_fptr_load && !is_unreachable && !is_mte_protected) {
          unrestricted_ptr_load++;
          // if (this_cnt > 30) {
          //   print_debug(s, nullptr, "unprotected load");
          //   errs() << "increment " << this_cnt << " unprotected access\n";
          // }
          for (auto i : this_load) {
            if (i == s)
              continue;
            if (is_init(i))
              continue;
            if (unsafe_access.count(i))
              unrestricted_load_unsafe.insert(i);
            else 
              unprotected_load_unrestricted.insert(i);
          }
          for (auto i : this_store) {
            if (i == s)
              continue;
            if (is_init(i))
              continue;
            if (pptr_store.count(cast<Instruction>(i))) {
              // unprotected ptr -> PAC store (PAC oracle dst)
              unrestricted_pac_dst.insert(i);
              auto ptrset = pac2ptr[i];
              if (!ptrset) {
                ptrset = new ValueSet();
                pac2ptr[i] = ptrset;
              }
              ptrset->insert(s);
            }
            if (unsafe_access.count(i))
              unrestricted_store_unsafe.insert(i);
            else
              unprotected_store_unrestricted.insert(i);
          }
          for (auto i : this_store_src) {
            if (i == s)
              continue;
            if (is_init(i))
              continue;
            if (pptr_store.count(cast<Instruction>(i))) {
              // unprotected ptr -> PAC store (PAC oracle src)
              unrestricted_pac_src.insert(i);
              auto ptrset = pac2ptr[i];
              if (!ptrset) {
                ptrset = new ValueSet();
                pac2ptr[i] = ptrset;
              }
              ptrset->insert(s);
            }
          }
        } 
      } // ValueSet
      int unprotected_load_priv = 0;
      int unprotected_load_both = 0;
      int unprotected_load_unsafe = 0;
      int unprotected_store_priv = 0;
      int unprotected_store_both = 0;
      int unprotected_store_unsafe = 0;
      int unrestricted_load_priv = 0;
      int unrestricted_load_both = 0;
      int unrestricted_store_priv = 0;
      int unrestricted_store_both = 0;
      for (auto i : unprotected_load) {
        if (unsafe_access.count(i))
          unprotected_load_unsafe++;
        else if (both_access.count(i))
          unprotected_load_both++;
        else if (priv_load.count(i))
          unprotected_load_priv++;
        else
          unprotected_load_both++;
      }
      for (auto i : unprotected_store) {
        if (unsafe_access.count(i)) 
          unprotected_store_unsafe++;
        else if (both_access.count(i))
          unprotected_store_both++;
        else if (priv_store.count(i))
          unprotected_store_priv++;
        else
          unprotected_store_both++;
      }
      for (auto i : unprotected_load_unrestricted) {
        if (both_access.count(i))
          unrestricted_load_both++;
        else if (priv_load.count(i))
          unrestricted_load_priv++;
        else
          unrestricted_load_both++;
      }
      for (auto i : unprotected_store_unrestricted) {
        if (both_access.count(i))
          unrestricted_store_both++;
        else if (priv_store.count(i))
          unrestricted_store_priv++;
        else
          unrestricted_store_both++;
      }
      
      errs() << "unprotected_ptr_load: " << unprotected_ptr_load << "\n";
      errs() << "unprotected_ptr_access: " << unprotected_load.size() + unprotected_store.size() << "\n";
      errs() << "  load : " << unprotected_load.size() << "\n";
      errs() << "    & priv: " << unprotected_load_priv << "\n";
      errs() << "    & both: " << unprotected_load_both << "\n";
      errs() << "    & unsafe: " << unprotected_load_unsafe << "\n";
  
      errs() << "  store: " << unprotected_store.size() << "\n";
      errs() << "    & priv: " << unprotected_store_priv << "\n";
      errs() << "    & both: " << unprotected_store_both << "\n";
      errs() << "    & unsafe: " << unprotected_store_unsafe << "\n";
      errs() << "unprotected ptr has pptr load: " << has_pptr_load << "\n";
      errs() << "unprotected ptr has fptr load: " << has_fptr_load << "\n";
      errs() << "unprotected ptr not reachable: " << not_reachable << "\n";
      errs() << "unprotected ptr mte protected: " << mte_protected << "\n";
      errs() << "unrestricted_ptr_load: " << unrestricted_ptr_load << "\n";
      errs() << "unrestricted_ptr_access: " << unprotected_load_unrestricted.size()+unprotected_store_unrestricted.size() << "\n";
      errs() << "  load    : " << unprotected_load_unrestricted.size() << "\n";
      errs() << "    & priv: " << unrestricted_load_priv << "\n";
      errs() << "    & both: " << unrestricted_load_both << "\n";
      errs() << "    & unsafe: " << unrestricted_load_unsafe.size() << "\n";
      errs() << "  store   : " << unprotected_store_unrestricted.size() << "\n";
      errs() << "    & priv: " << unrestricted_store_priv << "\n";
      errs() << "    & both: " << unrestricted_store_both << "\n";
      errs() << "    & unsafe: " << unrestricted_store_unsafe.size() << "\n";
      for (auto i : unprotected_pac_src) {
        if (unprotected_pac_dst.count(i))
          unprotected_pac_oracle.insert(i);
      }
  
      for (auto i : unrestricted_pac_src) {
        if (unrestricted_pac_dst.count(i))
          unrestricted_pac_oracle.insert(i);
      }
  
      errs() << "unprotected PAC oracle\n";
      errs() << "  src: " << unprotected_pac_src.size() << "\n";
      errs() << "  dst: " << unprotected_pac_dst.size() << "\n";
      errs() << "  oracle: " << unprotected_pac_oracle.size() << "\n";
  
      errs() << "unrestricted PAC oracle\n";
      errs() << "  src: " << unrestricted_pac_src.size() << "\n";
      errs() << "  dst: " << unrestricted_pac_dst.size() << "\n";
      errs() << "  oracle: " << unrestricted_pac_oracle.size() << "\n";
  
      
      for (auto i : unrestricted_pac_src) {
        print_debug(i, nullptr, "PAC oracle src");
        for (auto j : *pac2ptr[i]) {
          print_debug(j, nullptr, "From untrusted ptr");
        }
      }
      for (auto i : unrestricted_pac_dst) {
        print_debug(i, nullptr, "PAC oracle dst");
        for (auto j : *pac2ptr[i]) {
          print_debug(j, nullptr, "From untrusted ptr");
        }
      }
      for (auto i : unrestricted_pac_oracle) {
        print_debug(i, nullptr, "PAC oracle");
      }

    } // for



    ValueSet oob_load, oob_store, oob_store_src, oob_pac_src, oob_pac_dst, oob_pac_oracle;
    int oob_load_priv = 0;
    int oob_load_both = 0;
    int oob_load_unsafe = 0;
    int oob_store_priv = 0;
    int oob_store_both = 0;
    int oob_store_unsafe = 0;
    analyze_oob2(*m, &oob_load, &oob_store, &oob_store_src);

    for (auto i : oob_load) {
      if (unsafe_access.count(i))
        oob_load_unsafe++;
      else if (both_access.count(i))
        oob_load_both++;
      else if (priv_load.count(i))
        oob_load_priv++;
      else
        oob_load_both++;
    }
    for (auto i : oob_store) {
      if (unsafe_access.count(i))
        oob_store_unsafe++;
      else if (both_access.count(i))
        oob_store_both++;
      else if (priv_store.count(i))
        oob_store_priv++;
      else
        oob_store_both++;
      if (pptr_store.count(cast<Instruction>(i))) {
        oob_pac_dst.insert(i);
      }
    }
    for (auto i : oob_store_src) {
      if (pptr_store.count(cast<Instruction>(i))) {
        oob_pac_src.insert(i);
        if (oob_pac_dst.count(i)) 
          oob_pac_oracle.insert(i);
      }
    }

  
    errs() << "oob -> load: " << oob_load.size() << "\n";
    errs() << "          & priv: " << oob_load_priv << "\n";
    errs() << "          & both: " << oob_load_both << "\n";
    errs() << "          & unsafe: " << oob_load_unsafe << "\n";
    errs() << "oob -> store: " << oob_store.size() << "\n";
    errs() << "          & priv: " << oob_store_priv << "\n";
    errs() << "          & both: " << oob_store_both << "\n";
    errs() << "          & unsafe: " << oob_store_unsafe << "\n";

    errs() << "oob -> PAC SIGN\n";
    errs() << "          & src: " << oob_pac_src.size() << "\n";
    errs() << "          & dst: " << oob_pac_dst.size() << "\n";
    errs() << "          & src+dst: " << oob_pac_oracle.size() << "\n";

  }


void kdfi::collect_pptr_copy() {

  std::set<unsigned> emptyset = {};
  std::set<unsigned> skipset = {Instruction::GetElementPtr, Instruction::Add, Instruction::Shl, Instruction::Sub};
  std::set<unsigned> skipset2 = {Instruction::Call, Instruction::Ret,
                                Instruction::GetElementPtr, Instruction::Add,
                                Instruction::Shl, Instruction::Sub};
  std::set<StringRef> prefixes0 = {"llvm.memcpy", "llvm.memmove",
                                  "kmemdup", "kmemdup_nul"};
  std::set<StringRef> prefixes1 = {"llvm.memcpy", "llvm.memmove"};


  UseSet visited_ld, visited_str;
  
  errs() << "\nparent_ptr      : " << parent_ptr.size() << "\n";
  for (auto ptr : parent_ptr) {
    ValueSet callset;
    // inter-procedural safe access
    collect_forward(ptr, Instruction::Call, 0, &skipset, &callset, nullptr, &prefixes0);
    collect_forward(ptr, Instruction::Call, 1, &skipset, &callset, nullptr, &prefixes1);
    // if (callset.size())
    //   print_debug(ptr, "pptr_ptr");
    for (auto i : callset) {
      auto fname = cast<Instruction>(i)->getFunction()->getName();
      if (fname.startswith("kmemdup"))
        continue;
      // print_debug(i, "copy");
      ptr_copy.insert(cast<Instruction>(i));
      copy2sty[i] = copy2sty[ptr];
    }
  }

  for (auto ptr : parent_ptr) {
    ValueSet callset, gepset;
    collect_forward(ptr, Instruction::GetElementPtr, 0, &skipset2, &gepset, nullptr);

    int offset_max = -1;
    int offset_min = INT_MAX;
    for (auto sty : *copy2sty[ptr]) {
      auto offs = parent2off[cast<StructType>(sty)];
      for (auto off : *offs) {
        if (off > offset_max)
          offset_max = off;
        if (off < offset_min)
          offset_min = off;
      }
    }

    bool gep_dbg=true;
    for (auto gep : gepset) {
      int base = gep2offset(cast<Instruction>(gep));
      if (base < 0)
        continue;
      if (base > offset_max)
        continue;


      callset.clear();

      collect_forward(gep, Instruction::Call, 0, &skipset2, &callset, nullptr, &prefixes0);
      collect_forward(gep, Instruction::Call, 1, &skipset2, &callset, nullptr, &prefixes1);


      for (auto i : callset) {
        if (ptr_copy.count(cast<Instruction>(i)))
          continue;
        auto fname = cast<Instruction>(i)->getFunction()->getName();
        if (fname.startswith("kmemdup"))
          continue;

        fname = get_callee_function_name(cast<Instruction>(i));
        if (fname.startswith("llvm")) {
          if (auto ci = dyn_cast<ConstantInt>(cast<Instruction>(i)->getOperand(2))) {
            if (ci->getZExtValue() < (offset_min - base))
              continue;
          }
        } else {
          if (auto ci = dyn_cast<ConstantInt>(cast<Instruction>(i)->getOperand(1))) {
            if (ci->getZExtValue() < (offset_min - base))
              continue;
          }
        }
        if (gep_dbg && callset.size()) {
          gep_dbg = true;
          // print_debug(ptr, "gep_ptr");
          // errs() << "base: " << base << " offset[" << offset_min << ", "<< offset_max <<"]\n";
        }

        // print_debug(i, "copy");
        ptr_copy.insert(cast<Instruction>(i));
        copy2sty[i] = copy2sty[ptr];
        copy2base[i] = base;
      }
    }
  }

  errs() << "ptr_copy:  " << ptr_copy.size() << "\n";
}

void kdfi::find_cmp(Value* val, std::set<Use*> *cmpset) {
  ValueSet visited;
  ValueSet srcset;
  ValueList worklist;

  visited.insert(val);
  for (auto u : val->users())
    worklist.push_back(u);

  while (worklist.size()) {
    auto v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    if (!isa<ICmpInst>(v)) {
      visited.insert(v);
      if (auto ity = dyn_cast<IntegerType>(v->getType()))
        if (ity->getBitWidth() < 64)
          continue;
    }

    if (isa<Argument>(v)) {
      for (auto u : v->users()) {
        worklist.push_back(u);
      }
      continue;
    }
    else if (!isa<Instruction>(v)) {
      continue;
    }
    auto ii = cast<Instruction>(v);

    switch(ii->getOpcode()) {
    case Instruction::ICmp: 
      if (visited.count(ii->getOperand(0)))
        cmpset->insert(&ii->getOperandUse(0));
      if (visited.count(ii->getOperand(1)))
        cmpset->insert(&ii->getOperandUse(1));
      break;

    case Instruction::Call: {
      if (is_builtin_container_of(ii)) {
        for (auto u : v->users())
          worklist.push_back(u);
      } else {
        FunctionSet funcs;
        get_call_dest(ii, funcs);
        for (int i=0; i<cast<CallInst>(ii)->getNumOperands(); ++i) {
          if (!visited.count(cast<CallInst>(ii)->getArgOperand(i)))
            continue;
          for (auto func : funcs) {
            if (func->arg_size() > i) {
              worklist.push_back(func->getArg(i));
            }
          }
        }
      }
      break;
    }
    case Instruction::GetElementPtr:
      if (!visited.count(ii->getOperand(0)))
        break;

      for (auto u : ii->users())
        worklist.push_back(u);
      break;
    case Instruction::Select:
      if (!visited.count(ii->getOperand(1)) && !visited.count(ii->getOperand(2)))
        break;
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
    case Instruction::PHI:
    case Instruction::ExtractValue:
      for (auto u : v->users()) {
        worklist.push_back(u);
      }
      break;
    default:
      break;
    }
  }
}

// PeTAL
void kdfi::process()
{
  // privileged object protection
  collect_gref();
  collect_gref_use();
  collect_ptr();
 
  collect_ptr_access();

  // privileged pointer protection
  collect_pptr_ref();
  collect_pptr_copy();
  collect_pptr_access();
}

/////////////////////////////////////////////////////////////////////////////
// Dump 
/////////////////////////////////////////////////////////////////////////////

void kdfi::dump_inst_sty(raw_fd_ostream &out, Instruction *i, StructType *sty)
{
    int size = 0;
    dump_inst(out, i);
    auto fname = get_callee_function_name(i);
    if (sty) {
        if (i->getFunction()->getName() == "sock_alloc_inode" || 
                i->getFunction()->getName() == "sock_free_inode")
            size = 704;
        else if (i->getFunction()->getName() == "con_init")
            size = 800;
        else if (i->getFunction()->getName().startswith("_of_fixed_"))
            size = 48;
        else if (sty->isSized())
            size = DL->getTypeAllocSize(sty);
        else
            size = get_struct_size(sty);

        if (fname.startswith("kcalloc"))
            if (auto ci = dyn_cast<ConstantInt>(i->getOperand(0)))
                size = size * ci->getZExtValue();
    } else {
        if (fname.startswith("kzalloc") || fname.startswith("__alloc_percpu"))  {
            if (auto ci = dyn_cast<ConstantInt>(i->getOperand(0)))
                size = ci->getZExtValue();
        } else if (fname.startswith("kcalloc")) {
            if (auto ci0 = dyn_cast<ConstantInt>(i->getOperand(1)))
                if (auto ci1 = dyn_cast<ConstantInt>(i->getOperand(1)))
                    size = ci0->getZExtValue() * ci1->getZExtValue();
        } else if (fname.startswith("devm_kmalloc")) {
            if (auto ci = dyn_cast<ConstantInt>(i->getOperand(1)))
                size = ci->getZExtValue();
        }
    }

    if (fname.startswith("kmem_cache_alloc")) {
        Value *src = i->getOperand(0);
        GlobalVariable *cache = nullptr;
        User *gep = nullptr;
        if (auto ld = dyn_cast<LoadInst>(src)) {
            if (auto gv = dyn_cast<GlobalVariable>(ld->getOperand(0)))
                cache = gv;
            else if (auto ce = dyn_cast<ConstantExpr>(ld->getOperand(0))) {
                if (ce->getOpcode() == Instruction::GetElementPtr) {
                    if (auto gv = dyn_cast<GlobalVariable>(ce->getOperand(0)))
                        cache = gv;
                    gep = ce;
                }
            } else if (gep = dyn_cast<GetElementPtrInst>(ld->getOperand(0))) {
                if (auto gv = dyn_cast<GlobalVariable>(gep->getOperand(0)))
                    cache = gv;
            }
        }
        if (cache) {
            if (cache->getName().startswith("kmalloc_caches")) {
                if (gep) {
                    if (gep->getNumOperands() == 4) {
                        if (auto c = dyn_cast<ConstantInt>(gep->getOperand(3))) {
                            switch(c->getZExtValue()) {
                            case 0:
                                size = 0;
                                break;
                            case 1:
                                size = 96;
                                break;
                            case 2:
                                size = 192;
                                break;
                            case 3:
                                size = 8;
                                break;
                            case 4:
                                size = 16;
                                break;
                            case 5:
                                size = 32;
                                break;
                            case 6:
                                size = 64;
                                break;
                            case 7:
                                size = 128;
                                break;
                            case 8:
                                size = 256;
                                break;
                            case 9:
                                size = 512;
                                break;
                            case 10:
                                size = 1024;
                                break;
                            case 11:
                                size = 2048;
                                break;
                            default:
                                break;
                            }
                        }
                    }
                }
            } else {
                for (auto u : cache->users()) {
                    if (auto st = dyn_cast<StoreInst>(u)) {
                        if (st->getOperand(1) == cache) {
                            Value *create = st->getOperand(0);
                            if (auto ci = dyn_cast<CallInst>(create)) {
                                auto f = get_callee_function_name(ci);
                                if (!f.startswith("kmem_cache_create"))
                                    continue;
                                Value *op = ci->getArgOperand(1);
                                if (isa<ConstantInt>(op)) {
                                    size = cast<ConstantInt>(op)->getZExtValue();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    out << "size    : " << size <<"\n";

}

void kdfi::dump_alloc_inst(raw_fd_ostream &out)
{
    out << "mte alloc [" << priv_alloc.size() << "]\n";
    while(priv_alloc.size()) {
        auto it = priv_alloc.begin();
        Function *func = (*it)->getFunction();
        dump_func(out, func);
        while (it != priv_alloc.end()) {
            if (is_same_func((*it)->getFunction(), func)) {
                dump_inst_sty(out, *it, alloc2sty[*it]);
                it = priv_alloc.erase(it);
            } else {
                ++it;
            }
        }
        out << "\n";
    }
    // out << "normal alloc [" << normal_alloc.size() << "]\n";
    // while(normal_alloc.size()) {
    //     auto it = normal_alloc.begin();
    //     Function *func = (*it)->getFunction();
    //     dump_func(out, func);
    //     while (it != normal_alloc.end()) {
    //         if (is_same_func((*it)->getFunction(), func)) {
    //             dump_inst_sty(out, *it, alloc2sty[*it]);
    //             it = normal_alloc.erase(it);
    //         } else {
    //             ++it;
    //         }
    //     }
    //     out << "\n";
    // }
    out << "mte free [" << priv_free.size() << "]\n";
    while(priv_free.size()) {
        auto it = priv_free.begin();
        Function *func = (*it)->getFunction();
        dump_func(out, func);
        while (it != priv_free.end()) {
            if (is_same_func((*it)->getFunction(), func)) {
                dump_inst_sty(out, *it, free2sty[*it]);
                it = priv_free.erase(it);
            } else {
                ++it;
            }
        }
        out << "\n";
    }
}

 bool is_nullcmp(Value *v) {
    if (auto icmp = dyn_cast<ICmpInst>(v)) {
        if (auto c = dyn_cast<Constant>(icmp->getOperand(1))) {
            if (c->isNullValue()) {
                return true;
            }
        }
    }
    return false;
  }

void kdfi::collect_reachable_funcs(Function *func) 
{
  if (!func)
    return;
  if (reachable_funcs.count(func))
    return;
  reachable_funcs.insert(func);


  for (auto &B : *func) {
    for (auto I = B.begin(), E = B.end(); I != E; ++I) {
      if (!isa<CallInst>(&*I))
        continue;
      if (is_alloc_function(get_callee_function_name(&*I).str()))
        continue;
      if (is_builtin_container_of(&*I))
        continue;
      
      FunctionSet funcs;
      get_call_dest(&*I, funcs);
      for (auto callee : funcs) {
        collect_reachable_funcs(callee);
      }
    }
  }
}

void kdfi::collect_reachable_funcs()
{
  FunctionSet interface_funcs;
  std::ifstream input("interface.func");
  std::string line;
  while (std::getline(input, line)) {
    auto func = m->getFunction(line);
    if (func)
      interface_funcs.insert(func);
  }
  input.close();

  for (Module::iterator fi = m->begin(), fe = m->end();
      fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (!func)
      continue;
    if (func->getName().startswith("__arm64_sys_"))
      interface_funcs.insert(func);
  }
  errs() << "interface funcs: " << interface_funcs.size() << "\n";
  for (auto func : interface_funcs) {
    collect_reachable_funcs(func);
  }
}

void kdfi::dump_listfield()
{
  std::error_code EC;
  std::string path = knob_dump_path;
  if (path == "")
    path = "list.gv";
  raw_fd_ostream out(path, EC);
  // global pfield
  out << "global lfield [" << list_fields.size() << "]\n";
  for (auto s : list_fields) {
    out << " - " << s.first->getName() << "+" << s.second <<"\n";
  }
}

void kdfi::dump()
{
  std::error_code EC;
  std::string path = knob_dump_path;
  if (path == "")
    path = "kdfi.dump";
  raw_fd_ostream out(path, EC);

  // pobj types
  out << "pobj [" << pobj.size() << "]\n";
  for (auto ty : pobj) {
    out << " - " << ty->getStructName() << "\n";
  }

  // nested pobj types
  out << "nested pobj [" << nested_pobj.size() << "]\n";
  for (auto ty : nested_pobj) {
    out << " - " << ty->getStructName() << "\n";
  }

  out << "global pobj [" << priv_gobj.size() << "]\n";
  for (auto obj : priv_gobj) {
    out << " - " << obj->getName() << "\n";
  }

  // global pobj
  out << "global pptr [" << priv_gptr.size() << "]\n";
  for (auto ptr : priv_gptr) {
    out << " - " << ptr->getName() << "\n";
  }

  // global pfield
  out << "global pfield [" << gpfields.size() << "]\n";
  for (auto s : gpfields) {
    out << " - " << s.first->getName() << "+" << s.second <<"\n";
  }
  // global pfield
  out << "global gvref [" << gref_gv.size() << "]\n";
  for (auto s : gref_gv) {
    out << " - " << s->getName() << "\n";
  }

  // priv pointer ref type
  out << "pptr ref [" << priv_ref.size() << "]\n";
  for (auto s : priv_ref) {
    out << " - " << s->getStructName() << "\n";
  }


  // alloc inst
  dump_alloc_inst(out);

  // inter_safe access
  out << "safe access [" << inter_safe_access.size() << "]\n";
  while(inter_safe_access.size()) {
    auto it = inter_safe_access.begin();
    Function *func = (*it)->getFunction();
    dump_func(out, func);
    while (it != inter_safe_access.end()) {
      if (is_same_func((*it)->getFunction(), func)) {
        dump_inst(out, *it);
        it = inter_safe_access.erase(it);
      } else {
        ++it;
      }
    }
    out << "\n";
  }

  // inter_unsafe access
  out << "unsafe access [" << inter_unsafe_access.size() << "]\n";
  while(inter_unsafe_access.size()) {
    auto it = inter_unsafe_access.begin();
    Function *func = (*it)->getFunction();
    dump_func(out, func);
    while (it != inter_unsafe_access.end()) {
      if (is_same_func((*it)->getFunction(), func)) {
        dump_inst(out, *it);
        it = inter_unsafe_access.erase(it);
      } else {
        ++it;
      }
    }
    out << "\n";
  }


  if (knob_dump_pptr) {
    out << "ptr load [" << pptr_load.size() << "]\n";
    while(pptr_load.size()) {
      auto it = pptr_load.begin();
      Function *func = (*it)->getFunction();
      dump_func(out, func);
      while (it != pptr_load.end()) {
        if (is_same_func((*it)->getFunction(), func)) {
          dump_inst(out, *it);
          it = pptr_load.erase(it);
        } else {
          ++it;
        }
      }
      out << "\n";
    }

    out << "ptr store [" << pptr_store.size() << "]\n";
    while(pptr_store.size()) {
      auto it = pptr_store.begin();
      Function *func = (*it)->getFunction();
      dump_func(out, func);
      while (it != pptr_store.end()) {
        if (is_same_func((*it)->getFunction(), func)) {
          dump_inst(out, *it);
          it = pptr_store.erase(it);
        } else {
          ++it;
        }
      }
      out << "\n";
    }
  }

  out << "ptr copy [" << ptr_copy.size() << "]\n";
  while(ptr_copy.size()) {
    auto it = ptr_copy.begin();
    Function *func = (*it)->getFunction();
    dump_func(out, func);
    while (it != ptr_copy.end()) {
      if (is_same_func((*it)->getFunction(), func)) {
        dump_inst(out, *it);
        auto tset = copy2sty[*it];
        int base = copy2base[*it];

        std::set<int> offsets;
        for (auto sty : *tset) {
          auto offs = parent2off[cast<StructType>(sty)];
          for (auto off : *offs) {
            if (base > 0) {
              if (off < base)
                continue;
              offsets.insert(off-base);
            } else
              offsets.insert(off);
          }
        }
        for (auto off : offsets)
          out << off << " ";
        out << "\n";
        it = ptr_copy.erase(it);
      } else {
        ++it;
      }
    }
    out << "\n";
  }

  out << "priv stack [" << pstack_func.size() << "]\n";
  for (auto f : pstack_func)
    out << "- " << f->getName() << "\n";

}


/////////////////////////////////////////////////////////////////////////////
// Initialization
/////////////////////////////////////////////////////////////////////////////
void kdfi::initialize_rt() {
    createPACFunc = m->getOrInsertFunction(createPACFuncName,
                                          Type::getInt8PtrTy(*ctx),
                                          Type::getInt8PtrTy(*ctx),
                                          Type::getInt64Ty(*ctx));
    checkPACFunc = m->getOrInsertFunction(checkPACFuncName,
                                         Type::getInt8PtrTy(*ctx),
                                         Type::getInt8PtrTy(*ctx),
                                         Type::getInt64Ty(*ctx));
    convertPACFunc = m->getOrInsertFunction(convertPACFuncName,
                                           Type::getInt8PtrTy(*ctx),
                                           Type::getInt8PtrTy(*ctx),
                                           Type::getInt64Ty(*ctx));
    stripPACFunc = m->getOrInsertFunction(stripPACFuncName,
                                           Type::getInt8PtrTy(*ctx),
                                           Type::getInt8PtrTy(*ctx));
}

void kdfi::initialize_kdfi_struct()
{
    int count = 0;
    auto list = load_list(knob_obj_list);
    for (auto name : *list){
        if (is_anon_type(name) || is_skip_type(name)) {
           continue;
        }
        StructType *sty = StructType::getTypeByName(*ctx, name);
        if (!sty) {
          errs() << name << " does not exist\n";
          continue;
        }

        pobj.insert(sty);
        errs() << " - " << sty->getName() << "\n";
        if (name == "struct.sock") {
          pobj.insert(StructType::getTypeByName(*ctx, "struct.inet_timewait_sock"));
          pobj.insert(StructType::getTypeByName(*ctx, "struct.request_sock"));
        }
        else if (name == "struct.ctl_node" ||
          name == "struct.ctl_dir" ||
          name == "struct.ctl_table_header" ||
          name == "struct.ctl_table") {
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_node"));
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_dir"));
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_table_header"));
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ctl_table"));
        }
        else if (name == "struct.ext4_inode_info") {
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent_header"));
          pobj.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent"));
        }
    }
    for (auto obj : pobj) {
      pptr.insert(obj);
    }
    list = load_list(knob_ptr_list);
    for (auto name : *list){
        if (is_anon_type(name) || is_skip_type(name)) {
           continue;
        }
        StructType *sty = StructType::getTypeByName(*ctx, name);
        if (!sty) {
          errs() << name << " does not exist\n";
          continue;
        }

        pptr.insert(sty);
        errs() << " - " << sty->getName() << "\n";
        if (name == "struct.sock") {
          pptr.insert(StructType::getTypeByName(*ctx, "struct.inet_timewait_sock"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.request_sock"));
        }
        else if (name == "struct.ctl_node" ||
          name == "struct.ctl_dir" ||
          name == "struct.ctl_table_header" ||
          name == "struct.ctl_table") {
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ctl_node"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ctl_dir"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ctl_table_header"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ctl_table"));
        }
        else if (name == "struct.ext4_inode_info") {
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent_header"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent"));
        }
    }

    count = 0;
    list = load_list(knob_gobj_list);

    for (auto name : *list){
      auto gv = m->getGlobalVariable(name, true);
      if (!gv) {
        errs() << name << " does not exist\n";
        continue;
      }
      priv_gobj.insert(gv);
      errs() << " - " << gv->getName() << "\n";
      count++;
    }
    errs() << "Privilege Global Object: " << count << "\n";

    count = 0;
    list = load_list(knob_ptr_list);
    for (auto name : *list){
      if (is_anon_type(name) || is_skip_type(name)) {
          continue;
      }

      StructType *sty = StructType::getTypeByName(*ctx, name);
      if (!sty) {
        errs() << name << " does not exist\n";
        continue;
      }
      pptr.insert(sty);
      errs() << " > " << sty->getName() << "\n";
      count++;
      if (name == "struct.ctl_node") {
        sty = StructType::getTypeByName(*ctx, "struct.ctl_table");
        pptr.insert(sty);
      }
      if (name == "struct.ext4_inode_info") {
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent_header"));
          pptr.insert(StructType::getTypeByName(*ctx, "struct.ext4_extent"));
        }
    }

    for (auto ptr : pptr) 
      pobj.insert(ptr);

    errs() << "Privileged Object: " << pobj.size() << "\n";
    errs() << "Privileged Pointer: " << count << "\n";

    count = 0;
    list = load_list(knob_gptr_list);
    for (auto name : *list){
      auto gv = m->getGlobalVariable(name, true);
      if (!gv) {
        errs() << name << " does not exist\n";
        continue;
      }
      if (!is_pstr_type(gv->getType()->getPointerElementType()))
          continue;
      priv_gptr.insert(gv);
      errs() << " - " << gv->getName() << "\n";
      count++;
    }
    errs() << "Privileged Global Pointer: " << count << "\n";
}

void kdfi::find_pstack_funcs() {
  
  int cnt=0;
  int stack_cnt=0;
  int load_cnt=0;
  int store_cnt=0;
  int copy_cnt=0;

  std::set<StringRef> prefixes0 = {"llvm.memcpy", "llvm.memmove",
                                  "kmemdup", "kmemdup_nul"};

 // for (Module::iterator fi = m->begin(), fe = m->end();
 //      fi != fe; ++fi) {
 //   Function *func = dyn_cast<Function>(fi);
 //   if (!func)
 //     continue;
 //   if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
 //     continue;
 //   if (is_alloc_function(func->getName().str()))
 //     continue;

  for (auto func : funcs) {
  
   for(auto &B : *func) {
      for (auto I = B.begin(), E = B.end(); I != E; ++I) {
        if (isa<AllocaInst>(&*I))
          stack_cnt++;
        if (isa<LoadInst>(&*I) || is_asm_load(&*I))
          load_cnt++;
        if (isa<StoreInst>(&*I) || is_asm_store(&*I))
          store_cnt++;
        if (isa<CallInst>(&*I)) {
          auto fname = get_callee_function_name(&*I);
          for (auto str : prefixes0) {
            if (fname.startswith(str)) {
              copy_cnt++;
            }
          }
        }
      }
   }
    cnt++;
  }
  //errs() << "Priv stack  : " << visited.size() << "\n";
  //for (auto f : visited) {
  //  pstack_func.insert(f);
  //}

  errs() << "All function: " << cnt << "\n";
  errs() << "All stack obj: " << stack_cnt << "\n";
  errs() << "All store    : " << store_cnt << "\n";
  errs() << "All load     : " << load_cnt << "\n";
  errs() << "All copy     : " << copy_cnt << "\n";
}


bool kdfi::doInitialization(Module &module)
{
  m = &module;
  ctx = &module.getContext();
  DL = &m->getDataLayout();
  int8ty = Type::getInt8Ty(*ctx);
  int32ty = Type::getInt32Ty(*ctx);
  taskTy = StructType::getTypeByName(*ctx, "struct.task_struct");
  iteration = 0;
  initialize_struct_size(module, "struct.size");
  initialize_kdfi_struct();
  initialize_skip_func(knob_skip_func_list, "");
  initialize_alloc_func(knob_alloc_func_list);
  initialize_free_func(knob_free_func_list);
  initialize_function_code(module, knob_func_code_list);
  initialize_rt();
  initialize_list_struct("");
  PAC_MASK_CONST = ConstantInt::get(Type::getInt64Ty(*ctx), 0xFFFFFFFFFFFF);

  skip_access_funcs.insert("llvm.memcpy");
  skip_access_funcs.insert("llvm.memset");
  skip_access_funcs.insert("_raw_spin_lock");
  skip_access_funcs.insert("_raw_spin_unlock");

  Indices idx = {0};
  Indices *idx_key = get_indices(idx);

}

bool filter_64(Value *v) {
  if (v->getType()->isIntegerTy()) {
    if (v->getType()->getPrimitiveSizeInBits() < 64)
      return true;
  }
  if (auto ii = dyn_cast<Instruction>(v)){
    auto fname = ii->getFunction()->getName();
    if (fname == "__builtin_container_of" || fname == "builtin_container_of")
      return true;

    //// iov offset is checked
    //if (ii->getFunction()->getName().startswith("do_iter_"))
    //  return true;

  }
  if (auto li = dyn_cast<LoadInst>(v)) {
    if (is_per_cpu_gep(li->getOperand(0))){
      return true;
    } 

    // iov offset is checked
    if (auto gep = dyn_cast<GetElementPtrInst>(li->getOperand(0))) {
      auto ty = gep->getOperand(0)->getType();
      if (isa<PointerType>(ty)) {
        if (auto sty = dyn_cast<StructType>(ty->getPointerElementType())) {
          if (sty->getName().startswith("struct.iov_iter"))
            return true;
        }
      }
    }

    if (auto gv = has_gv(li->getOperand(0))) {
    
      if (gv->getName().startswith("__per_cpu_"))
        return true;
      if (gv->isConstant())
        return true;
    }
  }
  if (auto bop = dyn_cast<BinaryOperator>(v)) {
    if (bop->getOpcode() == Instruction::And) {
      //if (auto ci = dyn_cast<ConstantInt>(bop->getOperand(1))) {
        return true;
      //}
    }
    if (bop->getOpcode() == Instruction::LShr) {
      return true;
    }
    
  }

  return false;
}

bool kdfi::is_variable_64(Value *v) {
  bool res = false;
  
  ValueSet visited, srcset;
  Value *var = nullptr;
  backward(v, &visited, &srcset, nullptr, nullptr, &filter_64);

  for (auto u : srcset) {
    auto ty = u->getType();
    if (ty->isPointerTy() || ty->getPrimitiveSizeInBits() == 64) {
      var = u;
      res = true;
      break;
    }
  }

  if (res) {
    print_debug(v, nullptr, "is_variable_64");
    print_debug(var, nullptr, "64-bit variable");
  }
  return res;
}

void kdfi::collect_listfield(Module &module) {
  for (auto &gv : m->globals()) {

    if (!gv.hasInitializer())
      continue;

    // struct type global variable
    if (auto sty = get_pstr_type(gv.getType())) {
      Constant *init = gv.getInitializer();
      if (!init)
        continue;
      if (auto cs = dyn_cast<ConstantStruct>(init)) {
        if (cs->isZeroValue())
          continue;
        get_listfield(&gv, cs, 0);
      }
    }
  }
  dump_listfield();
}


void kdfi::analyze_oob2(Module &module, ValueSet *oob_load, ValueSet *oob_store, ValueSet *oob_store_src) {
  // 64-bit load -> Add, Mul, GEP Variable index
  ValueSet _oob_load, _oob_store;
  ValueSet loadset, oobset;
  UseSet visited_add, visited_gep, visited_mul, visited_ld, visited_st, visited_stsrc;
  std::set<unsigned> skipset = {Instruction::Trunc, Instruction::IntToPtr};
  std::set<unsigned> emptyset = {Instruction::Trunc, Instruction::IntToPtr};

  for (auto &F : module) {
    if (is_init(&F))
      continue;
    for (auto &B : F) {
      for (auto &I : B) {
        if (!isa<LoadInst>(&I))
          continue;
        if (I.getType()->getPrimitiveSizeInBits() != 64) {
          continue;
        }
        if (priv_load.count(&I) || stack_access.count(&I)) // Exclude MTE-protected and stack
          continue;
        if (is_global(I.getOperand(0), &all_gv)) { // Exclude globals
          continue;
        }
        
        loadset.insert(&I);
      }
    }
  }

  // Find potential variable add, gep, mul 
  int oob_loads = 0;
  for (auto ld : loadset) {
    ValueSet tmpset;
    collect_forward(ld, Instruction::Add, -1, &skipset, &tmpset, &visited_add);
    collect_forward(ld, Instruction::GetElementPtr, 2, &skipset, &tmpset, &visited_gep);
    collect_forward(ld, Instruction::Mul, -1, &skipset, &tmpset, &visited_mul);

    // Filter out 32-bit only instructions
    bool is_oob_load = false;
    for (auto i : tmpset) {
      for (int op=0; op < cast<Instruction>(i)->getNumOperands(); ++op) {
        if (cast<Instruction>(i)->getOperand(op)->getType()->getPrimitiveSizeInBits() == 64) {
            oobset.insert(i);
            is_oob_load = true;
            break;
        }
      }
    }
    if (is_oob_load)
      oob_loads++;
  }

  errs() << "# of OOB loads: " << oob_loads <<"\n";
  // Collect memory access using potential oob
  for (auto i : oobset) {
    collect_forward(i, Instruction::Load, 0, &emptyset, &_oob_load, &visited_ld);
    collect_forward(i, Instruction::Store, 1, &emptyset, &_oob_store, &visited_st);
    collect_forward(i, Instruction::Store, 0, &emptyset, oob_store_src, &visited_stsrc);
  }
  for (auto i : _oob_load) {
    oob_load->insert(i);
  }
  for (auto i : _oob_store) {
    oob_store->insert(i);
  }
}

void kdfi::analyze_oob(Module &module) {
  // Case 1. GetElementPtr with 64-bit variable
  // Case 2. PtrToInt then Add 64-bit variable

  InstructionSet gepset, addset;
  InstructionSet variable_gep, variable_add;

  for (auto &F : module) {
    for (auto &B : F) {
      for (auto &I : B) {
        auto ii = &I;
        if (isa<GetElementPtrInst>(ii)) {
          for (int i=1; i<ii->getNumOperands(); ++i) {
            if (!isa<ConstantInt>(ii->getOperand(i))) {
              // exclude for loop
              auto op = ii->getOperand(i);
              for (auto u : op->users()) {
                if (auto bop = dyn_cast<BinaryOperator>(u)) {
                  if (bop->getOpcode()==Instruction::Add) {
                    if (auto ci = dyn_cast<ConstantInt>(bop->getOperand(1))) {
                      if (ci->getZExtValue() == 1)
                        continue;
                    }
                  }
                }
              }
              gepset.insert(ii);
              break;
            }
          }
          gepset.insert(&I);
        } else if (isa<PtrToIntInst>(ii)) {
          for (auto u : ii->users()) {
            if (auto bop = dyn_cast<BinaryOperator>(u)) {
              if (bop->getOpcode()==Instruction::Add) {
                auto op1 = bop->getOperand(0);
                auto op2 = bop->getOperand(1);
                if ((op1 != ii) && !isa<ConstantInt>(op1)) {
                  addset.insert(bop);
                  break;
                }
                if ((op2 != ii) && !isa<ConstantInt>(op2)) {
                  addset.insert(bop);
                  break;
                }
              }
            }
          }
        }
      }
    }
  }

  errs() << "Potential GEP: " << gepset.size() << "\n";
  errs() << "Potential Pointer Add: " << addset.size() << "\n";


  // Verify the operand is a 64-bit variable
  errs() << "Verify 64-bit GEP\n";
  for (auto ii : gepset) {
    for (int i=1; i<ii->getNumOperands(); ++i) {
      auto op = ii->getOperand(i);
      if (isa<ConstantInt>(op))
        continue;
      if (is_variable_64(op)) {
        variable_gep.insert(ii);
        break;
      }
    }
  }

  errs() << "Verify 64-bit Pointer Add\n";

  for (auto ii : addset) {
    auto op1 = ii->getOperand(0);
    auto op2 = ii->getOperand(1);
    if (!isa<PtrToIntInst>(op1) && is_variable_64(op1)) {
      variable_add.insert(ii);
    } else if (!isa<PtrToIntInst>(op2) && is_variable_64(op2)) {
      variable_add.insert(ii);
    }
  }

  errs() << "Variable GEP: " << variable_gep.size() << "\n";
  errs() << "Variable Pointer Add: " << variable_add.size() << "\n";


  std::set<unsigned> emptyset = {};
  
  // Collect variable pointer access

  int num = 0;
  UseSet visited_ld, visited_str;
  for (auto s : variable_gep) {
    collect_forward(s, Instruction::Load, 0, &emptyset, &variable_access, &visited_ld);
    collect_forward(s, Instruction::Store, 1, &emptyset, &variable_access, &visited_str);      
    if ((variable_access.size() - num) > 10) {
      print_debug(s, nullptr, "variable_gep "+(std::to_string(variable_access.size()-num)));
    }
    num = variable_access.size();
  }

  visited_ld.clear();
  visited_str.clear();

  for (auto s : variable_add) {
    collect_forward(s, Instruction::Load, 0, &emptyset, &variable_access, &visited_ld);
    collect_forward(s, Instruction::Store, 1, &emptyset, &variable_access, &visited_str);      
    if ((variable_access.size() - num) > 10) {
      print_debug(s, nullptr, "variable_add "+(std::to_string(variable_access.size()-num)));
    }
    num = variable_access.size();
  }

  visited_ld.clear();
  visited_str.clear();

  errs() << "Variable Access: " << variable_access.size() << "\n";

}

void kdfi::collect_listcopy(Module &module) {
  // TODO: populate parent2off and parent_ptr
  auto sty = StructType::getTypeByName(*ctx, "struct.list_head");
  pobj.insert(sty);
  collect_parent_type();
  collect_ptr();
  collect_pptr_copy();
}

bool kdfi::runOnModule(Module &module)
{
  return kdfiPass(module);
}

bool kdfi::doFinalization(Module &module)
{
  //delete_md();
  errs() << "erase dummyCE\n";
  for (auto m : dummyCE) {
      m.first->deleteValue();
  }
  return false;
}

bool kdfi::kdfiPass(Module &module)
{
  if (knob_mode == "oob") {
    preprocess();
    analyze_oob(module);

  } else if (knob_mode == "list") {
    collect_listfield(module);
    collect_listcopy(module);
  } else {
    preprocess();
    process();
    dump();
  }
  return true;
}

static RegisterPass<kdfi>
X("kdfi", "kdfi Pass");
