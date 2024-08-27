#include "pta.h"
#include "utility.h"
#include <fstream>
#include <regex>

using namespace llvm;
int arg_cnt=0;
#define NUM_START 0
#define NUM_OP 3

#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IFDIR 0040000
#define DEBUG (!!std::getenv("PTA_DEBUG"))
#define DEBUG_USELIST (!!std::getenv("PTA_USELIST"))

char pta::ID;

bool _is_err_ptr(Value *v) {
  if (!isa<CastInst>(v)) {
    return false;
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
bool invalid_switch_context(Instruction *ii, ValueList *uselist) {
  Value *cmd = nullptr;
  std::set<int> cvals;
  BasicBlockSet bbset, visited;
  BasicBlockList worklist;
  auto bb = ii->getParent();
  
  worklist.push_back(bb);
  while (worklist.size()) {
    auto _bb = worklist.back();
    worklist.pop_back();
    if (visited.count(_bb))
      continue;
    visited.insert(_bb);
    for (auto u : _bb->users()) {
      if (isa<SwitchInst>(u)) {
        auto si = cast<SwitchInst>(u);
        bool is_common_pred = true;
        if (!bb->getSinglePredecessor()) {
          for (auto pred : predecessors(bb)) {
            BasicBlockSet tmpset;
            if (!bb_can_reach(_bb, pred, &tmpset)) {
              is_common_pred = false;
              break;
            }
          }
        }
        if (is_common_pred) {
          cmd = si->getCondition();
          for (auto it = si->case_begin(); it != si->case_end(); ++it) {
            if (it->getCaseSuccessor() == _bb) {
              cvals.insert(it->getCaseValue()->getSExtValue());
            }
          }
          break;
        }
      }
    } 
    for (auto pred : predecessors(_bb)) {
      worklist.push_back(pred);
    }
  }

  // Not a switch context
  if (!cvals.size())
    return false;

  for (auto u : *uselist) {
    if (u == ii)
      continue;
    if (!isa<Instruction>(u))
      continue;
    auto ui = cast<Instruction>(u);
    if (!ui->getFunction()->getName().contains("ioctl"))
      continue;
  
    visited.clear();
    bb = ui->getParent();
    worklist.push_back(bb);
    while (worklist.size()) {
      auto _bb = worklist.back();
      worklist.pop_back();
      if (visited.count(_bb))
        continue;
      visited.insert(_bb);
      for (auto u : _bb->users()) {
        if (isa<SwitchInst>(u)) {
          auto si = cast<SwitchInst>(u);
          bool is_common_pred = true;
          if (!bb->getSinglePredecessor()) {
            for (auto pred : predecessors(bb)) {
              BasicBlockSet tmpset;
              if (!bb_can_reach(_bb, pred, &tmpset)) {
                is_common_pred = false;
                break;
              }
            }
          }
          if (is_common_pred) {
            cmd = si->getCondition();
            for (auto it = si->case_begin(); it != si->case_end(); ++it) {
              if (it->getCaseSuccessor() == _bb) {
                if (cvals.count(it->getCaseValue()->getSExtValue()))
                  return false;
              }
            }
            return true;
          }
        }
      }
      for (auto pred : predecessors(_bb)) {
        worklist.push_back(pred);
      }
    }



    // BasicBlockSet _bbset;
    // auto _bb = ui->getParent();
    // _bbset.insert(_bb);
    // while (true) {
    //   if (_bb->getUniquePredecessor()) {
    //     _bb = _bb->getUniquePredecessor();
    //     _bbset.insert(_bb);
    //   } else if (_bb->hasNPredecessors(2)) {
    //     auto it = pred_begin(_bb);
    //     auto pred0 = *it++;
    //     auto pred1 = *it;
    //     BasicBlockSet __bbset;
    //     __bbset.insert(pred0);
    //     while (pred0->getUniquePredecessor()) {
    //       pred0 = pred0->getUniquePredecessor();
    //       __bbset.insert(pred0);
    //     }
         
    //     while(true) {
    //       if (__bbset.count(pred1)) {
    //         _bbset.insert(pred1);
    //         _bb = pred1;
    //         break;
    //       }
    //       if (pred1->getUniquePredecessor())
    //         pred1 = pred1->getUniquePredecessor();
    //       else 
    //         break;
    //     }
    //     if (_bb != pred1)
    //       break;
    //   } else
    //     break;
    // }
    
    // for (auto bb : _bbset) {
    //   for (auto u : bb->users()) {
    //     if (isa<SwitchInst>(u)) {
    //       auto si = cast<SwitchInst>(u);
    //       for (auto it = si->case_begin(); it != si->case_end(); ++it) {
    //         if (it->getCaseSuccessor() == bb) {
    //           if (cvals.count(it->getCaseValue()->getSExtValue()))
    //             return false;
    //         }
    //       }
    //       return true;
    //     }
    //   } 
    // }


  } 
  return false;
}

bool pta::is_skip_func(Function *func) {
  if (is_skip_function(func->getName().str())) {
    return true;
  }
  if (func->getName().endswith("free") ||
      func->getName().endswith("release") ||
      func->getName().startswith("kasan") ||
      func->getName().startswith("tracepoint_" ) ||
      func->getName().startswith("trace_") ||
      func->getName().startswith("__traceiter"))
    return true;
  return false;
}
bool pta::is_address_space_op(Value *v) {
  if (!isa<CallInst>(v))
    return false;
  auto ci = cast<CallInst>(v);
  auto func = ci->getCalledFunction();
  if (func)
    return false;
  auto cv = ci->getCalledOperand();
  auto load = dyn_cast<LoadInst>(cv);
  if (!load)
    return false;
  auto gep = dyn_cast<GetElementPtrInst>(load->getOperand(0));
  if (!gep)
    return false;
  auto sty = get_pstr_type(m, gep->getOperand(0)->getType());
  if (!sty)
    return false;
  if (sty->getName().startswith("struct.address_space_operations"))
    return true;
  return false;
}
bool pta::has_shift(ValueList *uselist) {
  for (auto u : *uselist) {
    if (!isa<Instruction>(u))
      continue;
    if (cast<Instruction>(u)->getFunction()->getName()=="do_mount")
      continue;
    if (cast<Instruction>(u)->isShift()) {
      return true;
    }
  }
  return false;
}

bool pta::can_load(Indices *idx, ValueList *uselist) {
  if (idx->size()<1)
    return false;
  int offset = idx->back();
  if (offset != 0) {
    if (auto ii = cast<Instruction>(uselist->back())) {
      if (ii->getFunction()->getName()=="path_init" && idx->back()==8)
        return true;
    }
    bool has_copy = false;
    for (auto rit=uselist->rbegin(); rit != uselist->rend(); ++rit) {
      if (isa<StoreInst>(*rit))
        break;
      if (auto ci = dyn_cast<CallInst>(*rit)) {
        if (is_copy_func(get_callee_function_name(ci))) {
          int size=get_copy_size(ci);
           if (size > 0 && offset<0 &&
                    (-1)*offset< size)  {
             has_copy=true;
            break;
          }
        }
      }
    }
    if (!has_copy)
      return false;
  }

  if (has_shift(uselist)) {
    return false;
  }
  return true;
}
bool pta::is_skip_type(Type *ty) {
  auto sty = get_pstr_type(m, ty);
  if (!sty)
    return false;

  auto sname = get_struct_name(sty->getStructName().str());
  if (sname == "")
    return false;
  if (sname == "struct.page" ||
      sname == "struct.pmd_t" ||
      sname == "struct.pte_t" ||
      sname == "struct.pagemapread" ||
      sname == "struct.pagemap_entry_t" ||
      sname == "struct.iov_iter" ||
      sname == "struct.iovec" ||
      sname == "struct.mm_walk" ||
      sname == "struct.wait_queue_head")
    return true;
  return false;
}

bool pta::is_object_type(Type *ty) {
  if (!isa<StructType>(ty))
    return false;
  return true;
}

bool is_increment(Instruction *store) {
  auto val = store->getOperand(0);
  auto dst = store->getOperand(1);
  if (!isa<Instruction>(val) ||
      !isa<Instruction>(dst))
    return false;
 
  if (cast<Instruction>(val)->getOpcode() != Instruction::Add ||
      cast<Instruction>(dst)->getOpcode() != Instruction::Load)
    return false;
  if (cast<Instruction>(val)->getOperand(0) != dst)
    return false;
  return true;

}
int pta::get_copy_size(CallInst *ci) {
  auto fname = get_callee_function_name(ci);
  if (fname.startswith("llvm.memcpy") ||
      fname == "__arch_copy_from_user" ||
      fname.startswith("_copy_from_user") ||
      fname == "strlcpy" ||
      fname == "strncpy_from_user" ) {

    if (ci->arg_size() < 3) {
      if (auto casti = dyn_cast<CastInst>(ci->getArgOperand(0))) {
        if (auto sty = get_pstr_type(m, casti->getOperand(0)->getType())) {
          return DL->getTypeStoreSizeInBits(sty);
        }
      }
      if (auto casti = dyn_cast<CastInst>(ci->getArgOperand(1))) {
        if (auto sty = get_pstr_type(m, casti->getOperand(0)->getType())) {
          return DL->getTypeStoreSizeInBits(sty);
        }
      }
      return -1;
    }

    Value *v = ci->getArgOperand(2);
    if (auto c = dyn_cast<ConstantInt>(v))
      return c->getSExtValue();
    if (auto bi = dyn_cast<BinaryOperator>(v)) {
      if (bi->getOpcode() == Instruction::Mul) {
        if (auto c = dyn_cast<ConstantInt>(bi->getOperand(1)))
          return c->getSExtValue();
      }
    }
  }
    return -1;
}

void pta::dump_backward_sty(ValueSet *srcset, TypeSet *psty, ValueSet *pobj,
                            InstructionSet *palloca,
                            Type2ChkInst *psty2inst, Value2ChkInst *pobj2inst) {
  StructTypeSet _psty;
  if (srcset->size() > 0) {
    for (auto s : *srcset) {
      Instruction *ii = nullptr;
      if (isa<ConstantExpr>(s)) {
        ii = cast<ConstantExpr>(s)->getAsInstruction();
      } else if (isa<Instruction>(s)) {
        ii = cast<Instruction>(s);
      } else if (isa<GlobalValue>(s)) {
        if (s->hasName())
          pobj->insert(s);
      }
      if (!ii) {
        print_error(ii, nullptr, "dump unknown");
        continue;
      }
      if (is_global(ii)) {
        get_global(ii, psty, pobj, psty2inst, pobj2inst);
      }

      if (psty2inst) {
        if (isa<AllocaInst>(ii)) {
          if (palloca) {
            print_debug(ii, "found");
            palloca->insert(ii);
          }
          continue;
        }
      }
      if (auto sty = get_pstr_type(m, ii->getType())) {
        if (!is_skip_type(sty) && !is_list_struct(sty) &&
            sty->getName()!="struct.atomic_64") {
            if (!psty->count(sty)&&!_psty.count(sty))
              errs() << "found " << sty->getName() <<"\n";
          _psty.insert(sty);
          if (psty2inst) {
            auto iset = (*psty2inst)[sty];
            if (!iset) {
              iset = new InstructionSet;
              (*psty2inst)[sty] = iset;
            }
            iset->insert(ii);
          }
        }
      }
      if (isa<GetElementPtrInst>(ii)) {
        Value * op = ii->getOperand(0);
        auto sty = get_pstr_type(m, op->getType());
        if (sty && !is_skip_type(sty) && !is_list_struct(sty) &&
            sty->getName()!="struct.atomic_64") {
          if (!psty->count(sty)&&!_psty.count(sty))
            errs() << "found " << sty->getName() <<"\n";
          _psty.insert(sty);

          if (psty2inst) {
            auto iset = (*psty2inst)[sty];
            if (!iset) {
              iset = new InstructionSet;
              (*psty2inst)[sty] = iset;
            }
            iset->insert(ii);
          }
        }
      }
    }
  }

  TypeSet nested;
  TypeList typelist;
  ValueSet allocaset;
  for (auto sty : _psty) {
    for (int i=0; i<sty->getNumElements(); ++i) {
      auto ety = sty->getElementType(i);
      typelist.push_back(get_type(m, ety));
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
        typelist.push_back(get_type(m, ety));
      }
    } else if (auto arr = dyn_cast<ArrayType>(ty)) {
      typelist.push_back(get_type(m, arr->getElementType()));
    }
  }

  for (auto ty : _psty) {
    if (nested.count(ty)) {
      //errs() << ty->getName() << " is nested type!\n";
      continue;
    }
    if (!is_object_type(ty)) {
      //errs() << ty->getName() << " is not an object type!\n";
      continue;
    }
    psty->insert(ty);
  }
}

bool pta::is_asm_user(Value *v) {
    if (!isa<CallBase>(v))
        return false;
    if (!cast<CallBase>(v)->isInlineAsm())
        return false;
    InlineAsm *ia = cast<InlineAsm>(cast<CallBase>(v)->getCalledOperand());
    auto str = ia->getAsmString();
    if (str.find("\tbics\txzr") == 0) {
        return true;
    }
    return false;
}
bool pta::is_cmp_func(StringRef fname) {
  if (fname == "")
    return false;
  if (cmp_funcs.count(fname.str())==0)
    return false;
  return true;
}
bool pta::is_copy_func(StringRef fname, bool write) {
  if (fname == "")
    return false;
  if (fname.startswith("llvm.memcpy"))
    return true;
  if (fname.startswith("_copy_from_user"))
    return true;
  if (fname.startswith("_copy_to_user"))
    return true;
  if (copy_funcs.count(fname.str())==0)
    return false;
  return true;
}
bool pta::is_parse_func(StringRef fname) {
  if (fname == "")
    return false;
  if (parse_funcs.count(fname.str())==0)
    return false;
  return true;
}
bool pta::is_proc_parse_func(StringRef fname) {
  if (fname == "")
    return false;
  if (proc_parse_funcs.count(fname.str())==0)
    return false;
  return true;
}

bool pta::is_perm_func(StringRef fname) {
    if (fname == "")
        return false;
    if (perm_funcs.count(fname.str()) == 0)
        return false;
    return true;
}
//bool pta::is_alloc_func(StringRef fname) {
//  StringRef _fname = get_func_name(fname);
//  if (alloc_funcs.count(_fname.str())>0)
//    return true;
//  if (fname.startswith("__kmalloc"))
//    return true;
//  return false;
//}

bool pta::get_string(Value *v, StringRef *str) {
  if (isa<ConstantExpr>(v))
    return get_string(cast<ConstantExpr>(v)->getAsInstruction(), str);
  if (isa<GetElementPtrInst>(v))
    return get_string(cast<Instruction>(v)->getOperand(0), str);
  if (isa<GlobalVariable>(v)) {
    if (v->hasName()) {
      if (v->getName().contains("str")) {
        std::string name_str;
        llvm::raw_string_ostream ss(name_str);
        ss << *v;
        StringRef name_s = name_str;
        name_s = name_s.split("\"").second;
        name_s = name_s.split("\\00").first;
        *str = name_s;
        return true;
      }
    }
  }
  return false;
}
bool pta::is_builtin_container_of(Value *v) {
    if (!v)
        return false;
    if (!isa<CallInst>(v))
        return false;
    CallInst *ci = cast<CallInst>(v);
    Function *callee = get_callee_function_direct(ci);
    if (!callee)
      return false;
    if (callee->getName() == "__builtin_container_of")
      return true;
    if (callee->getName() == "make_kuid" || 
        callee->getName() == "strchr" || callee->getName() == "strchrnul")
      return true;
    return false;
}
StringRef pta::get_func_name(StringRef fname) {
    if (fname.find_first_of(".") != fname.find_last_of("."))
        return fname.substr(0, fname.find_last_of("."));
    else if (fname.find_first_of(".")) {
      return fname.substr(0, fname.find_first_of("."));
    }
    return fname;
}

Indices* pta::get_indices(Indices idx) {
    for (auto i : ind_keys){
        if (*i == idx)
            return i;
    }
    Indices* new_idx = new Indices(idx);
    ind_keys.insert(new_idx);
    return new_idx;
}

bool pta::check_visited(Value *val, ValueSet *visited, ValueList *worklist) {
    if (visited->count(val))
        return true;
    if (std::find(worklist->begin(), worklist->end(), val) != worklist->end())
        return true;
    return false;
}


bool pta::check_visited(Value *val, ValueList *uselist, ValueList *worklist) {
    if (std::find(uselist->begin(), uselist->end(), val) != uselist->end())
        return true;
    if (std::find(worklist->begin(), worklist->end(), val) != worklist->end())
        return true;
    return false;
}
void pta::push_idx(Value *dst, int val) {
  if (val2off.count(dst)) {
    auto idx = val2off[dst];
    auto _idx = *idx;
    _idx.push_back(val);
    val2off[dst] = get_indices(_idx);
  } else {
    if (DEBUG) {
      print_error(dst, nullptr, "No dst offset");
    }
  }
}

void pta::push_idx(Value *dst, Value *src, int val) {
  copy_offset(dst, src, 0);
  push_idx(dst, val);
}

void pta::push_idx_safe(Value *dst, Value *src, int val) {
  if (val2off.count(dst)) {
    //if (val2off[dst]->size() < val2off[src]->size()+1)
    return;
  }
  copy_offset(dst, src, 0);
  push_idx(dst, val);
}

void pta::pop_idx(Value *dst) {
   if (val2off.count(dst)) {
    auto idx = val2off[dst];
    auto _idx = *idx;
    _idx.pop_back();
    val2off[dst] = get_indices(_idx);
  } else {
    if (DEBUG) {
      print_error(dst, nullptr, "No dst offset");
    }
  }
}

void pta::copy_offset(Value *dst, Indices *idx) {
  val2off[dst] = idx;
}

void pta::copy_offset(Value *dst, Value *src, int offset) {
  //if (val2off.count(dst))
  //    return;
  if (val2off.count(src)) {
    Indices *idx = val2off[src];
    Indices _idx = *idx;
    if (offset && idx->size() > 0) {
      int last = _idx.back() + offset;
      _idx.pop_back();
      _idx.push_back(last);
    }
    val2off[dst] = get_indices(_idx);
  } else {
    if (DEBUG) {
      print_error(src, nullptr, "No copy offset");
    }
  }
}

void pta::copy_offset_check(Value *dst, Value *src, int offset) {
  if (val2off.count(src)) {
    Indices *idx = val2off[src];
    Indices _idx = *idx;

    if (is_builtin_container_of(dst)) {
      auto di = cast<Instruction>(dst);
      if (isa<ConstantInt>(di->getOperand(1))) {
        offset += cast<ConstantInt>(di->getOperand(1))->getZExtValue();
      }
    } else if (isa<GetElementPtrInst>(dst)) {
      auto di = cast<Instruction>(dst);
      int gep_offset = gep2offset(di);
      if (gep_offset>0)
        offset -= gep_offset;
    }


    if (offset && idx->size() > 0) {
      int last = _idx.back() + offset;
      _idx.pop_back();
      _idx.push_back(last);
    }

    val2off[dst] = get_indices(_idx);
  } else {
    if (DEBUG) {
      print_error(src, nullptr, "No copy offset");
    }
  }
}

void pta::copy_offset_safe(Value *dst, Value *src) {
  if (val2off.count(dst)) {
    return;
  }
  copy_offset(dst, src, 0);
}

void pta::copy_offset_safe(Value *dst, Value *src, int offset) {
  if (val2off.count(dst) && val2off.count(src)) {
    if (val2off[dst]->size() <= val2off[src]->size())
      return;
  }
  copy_offset(dst, src, offset);
}

// return copy function source arg number
int pta::get_copy_src(Instruction *ii, bool write) {
  auto fname = get_callee_function_name(ii);
  if (fname == "")
    return -1;
  if (fname.startswith("kstrto"))
      return 0;
  if (fname.startswith("proc_get_long"))
      return 0;
  if (fname.startswith("__do_proc_dointvec"))
      return write ? 3 : 0;
  if (fname.startswith("do_proc_dou"))
      return write ? 2 : 0;
  if (copy_funcs.count(fname.str()) || fname.startswith("llvm.memcpy"))
      return 1;
  if (fname.startswith("_copy_from_user"))
    return write ? 1 : -1;
  if (fname.startswith("_copy_to_user"))
    return write ? -1 : 1;
  return -1;
}


// return copy function dest arg number
int pta::get_copy_dst(Instruction *ii, bool write) {
  auto fname = get_callee_function_name(ii);
  if (fname == "")
    return -1;
  if (fname.startswith("proc_get_long"))
      return 2;
  if (fname.startswith("kstr")) {
      if (fname.endswith("from_user"))
          return 3;
      else
          return 2;
  }
  // if the first argument of proc function is ctl_table,
  // the actual data being copied is table->data.
  if (auto sty = get_pstr_type(m, ii->getOperand(0)->getType())) {
    if (sty->getName().startswith("struct.ctl_table")) {
      if (write && val2off.count(ii)) {
        Indices *idx = val2off[ii];
        Indices _idx = *idx;
        _idx.push_back(8);
        val2off[ii->getOperand(0)] = get_indices(_idx);
      }
    }
  }
  if (fname.startswith("__do_proc_dointvec"))
    return write ? 0 : 3;
  if (fname.startswith("do_proc_dou"))
    return write ? 0 : 2;
  if (copy_funcs.count(fname.str()) || fname.startswith("llvm.memcpy"))
      return 0;
  if (fname.startswith("_copy_from_user"))
    return write ? 0 : -1;
  if (fname.startswith("_copy_to_user"))
    return write ? -1 : 0;
  
  return -1;
}

int pta::get_parse_src(Instruction *ii) {
  auto fname = get_callee_function_name(ii);
  if (fname == "")
    return -2;
  return 0;
}

int pta::get_parse_dst(Instruction *ii) {
  auto fname = get_callee_function_name(ii);
  if (fname == "")
    return -2;
  if (is_proc_parse_func(fname))
    return -2;

  return -1;
}

// TODO: perm_check, cmp predicate
int pta::get_cmp_true(StringRef fname) {
  if (fname == "")
    return -1;
  if (fname.startswith("bcmp"))
      return 0;
  if (fname.startswith("__fdget"))
      return 1;
  return 0;
}

int pta::gep2offset(Instruction *gep) {
  if (is_i8gep(gep)) {
    if (auto ci = dyn_cast<ConstantInt>(gep->getOperand(gep->getNumOperands()-1)))
      return ci->getZExtValue();
  }
  auto base = gep->getOperand(0);
  Type *baseTy = nullptr;
  auto sty = get_pstr_type(m, base->getType());
  if (sty)
    baseTy = sty;
  else if (auto aty = dyn_cast<ArrayType>(cast<PointerType>(base->getType())->getPointerElementType())) {
    baseTy = aty;
  } else
    return -1;

  int offset = 0;
  int i=1;
  std::vector<Value*> offset_vec;

  while (i < gep->getNumOperands()) {
    Value *op = gep->getOperand(i);
    // array index
    if (op->getType()->getPrimitiveSizeInBits() == 64) {
      int idx = 0;
      if (isa<ConstantInt>(op))
        idx = cast<ConstantInt>(op)->getZExtValue();
      auto size = DL->getTypeStoreSizeInBits(baseTy)/8;
      offset += idx * size;
      offset_vec.clear();
      offset_vec.push_back(ConstantInt::get(Type::getInt64Ty(*ctx), 0));
      if (i > 1) {
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
      assert(isa<StructType>(baseTy));
      baseTy = cast<StructType>(baseTy)->getTypeAtIndex(c->getZExtValue());
    }

    offset += DL->getIndexedOffsetInType(sty, llvm::ArrayRef<Value*>(offset_vec));

  }

  return offset;
}

int pta::i8gep2idx(StructType *sty, int offset) {
    const StructLayout *SL;
    int off = 0;
    StructType *_sty = sty;
    SL = DL->getStructLayout(_sty);
    int tmp = 0;
    for (unsigned i=0; i<_sty->getNumElements(); ++i) {
      tmp = off+SL->getElementOffset(i);
      if (tmp < offset)
        continue;
      else if (tmp > offset) {
        if (i<=0)
          return -1;
        return i-1;
      } else { // tmp == offset
        return i;
      }
    }
    return -1;
}
bool pta::is_i8gep(User *gep) {
    Value *src = gep->getOperand(0);
    if (src->getType() != Type::getInt8PtrTy(*ctx))
        return false;
    if (!isa<ConstantInt>(gep->getOperand(1)))
        return false;
    return true;
}
void pta::get_global(Instruction *ii, TypeSet *psty, ValueSet *pobj,
                     Type2ChkInst *psty2inst, Value2ChkInst *pobj2inst) {
  if (is_asm_get_current(ii)) {
    psty->insert(taskTy);
    if (psty2inst) {
      auto iset = (*psty2inst)[taskTy];
      if (!iset) {
        iset = new InstructionSet;
        (*psty2inst)[taskTy] = iset;
      }
      iset->insert(ii);
    }
  }
  else if (!isa<CallInst>(ii)) {
    for (unsigned i=0; i<ii->getNumOperands(); i++) {
      auto op = ii->getOperand(i)->stripPointerCasts();
      if (isa<GlobalVariable>(op)) {
        if (op->hasName()) {
          if (op->getName().contains("str"))
            continue;
          if (!pobj->count(op))
            print_debug(op, nullptr, "found ");
          pobj->insert(op);

          if (pobj2inst) {
            auto iset = (*pobj2inst)[op];
            if (!iset) {
              iset = new InstructionSet;
              (*pobj2inst)[op]=iset;
            }
            iset->insert(ii);
          }
        }
      }
    }
  }
}
bool pta::is_global(Instruction *ii) {
  if (is_asm_get_current(ii))
      return true;
  if (!isa<CallInst>(ii)) {
    for (unsigned i=0; i<ii->getNumOperands(); i++) {
      auto op = ii->getOperand(i)->stripPointerCasts();
      if (isa<GlobalVariable>(op)) {
        if (op->hasName())
          if (op->getName().contains("str"))
            continue;
        return true;
      }
    }
  }
  return false;
}

Type *pta::findPrivType(Value *addr) {
    Type *ty = addr->getType();
    if (isa<PointerType>(ty))
        if (isa<StructType>(ty->getPointerElementType()))
            return ty->getPointerElementType();
    if (isa<ConstantExpr>(addr)) {
        auto vi = cast<ConstantExpr>(addr)->getAsInstruction();
        return findPrivType(vi);
    }
    if (!isa<Instruction>(addr))
        return nullptr;
    Instruction *addrI = cast<Instruction>(addr);
    if (isa<CastInst>(addrI->getOperand(0)))
        return findPrivType(cast<Instruction>(addrI->getOperand(0)));
    else if (isa<CallInst>(addrI)) {
        Function *ff = get_callee_function_direct(addrI);
        if (!ff) {
            //print_error(addrI, nullptr, "no function callee");
            return nullptr;
        }
        //print_debug(addrI, "priv call");
        if (ff->getName() == "__continer_of") {
            return findPrivType(addrI->getOperand(0));
        }
    }
    else if (isa<GetElementPtrInst>(addrI))
        return findPrivType(addrI->getOperand(0));
    return nullptr;
}
Type *pta::findCondType(Instruction *condI, bool *is_ptr) {
    if (isa<CallInst>(condI)) {
        Function *ff = get_callee_function_direct(condI);
        if (!ff) {
            //print_error(condI, nullptr, "no function callee");
            goto out;
        }
        *is_ptr = false;
        if (ff->getName() == "ns_capable")
            return nsTy;
        if (ff->getName() == "capable")
            return credTy;
        print_debug(condI, "cond call");
        int argno = 0;
        for (auto ai = ff->arg_begin(); ai != ff->arg_end(); ++ai, ++argno) {
            Type *ty = ai->getType();
            if (is_list_struct(ty))
                return findPrivType(cast<CallInst>(condI)->getArgOperand(argno));
            if (isa<PointerType>(ty)) {
                if (isa<StructType>(ty->getPointerElementType())) {
                    return ty->getPointerElementType();
                }
            }
        }
    } else {
        //Type *ty = condI->getType();
        //if (isa<PointerType>(ty))
        //    if (isa<StructType>(ty->getPointerElementType()))
        //        return ty->getPointerElementType();
        if (isa<CmpInst>(condI)) {
            Type *res = nullptr;
            if (isa<Instruction>(condI->getOperand(0)))
                res = findCondType(cast<Instruction>(condI->getOperand(0)), is_ptr);
            else if (isa<Instruction>(condI->getOperand(1)))
                res = findCondType(cast<Instruction>(condI->getOperand(1)), is_ptr);
            if (!res) {
                Type *ty = condI->getOperand(0)->getType();
                if (isa<PointerType>(ty)) {
                    if (isa<StructType>(ty->getPointerElementType())) {
                        res = ty->getPointerElementType();
                    }
                }
            }
            if (res)
                return res;
            else
                goto out;
        } if (isa<BinaryOperator>(condI)) {
            if (isa<Instruction>(condI->getOperand(0)))
                return findCondType(cast<Instruction>(condI->getOperand(0)), is_ptr);
            else if (isa<Instruction>(condI->getOperand(1)))
                return findCondType(cast<Instruction>(condI->getOperand(1)), is_ptr);
        } else if (isa<LoadInst>(condI)) {
            *is_ptr = false;
            return findPrivType(condI->getOperand(0));
        //Type *loadTy = stripPointerType(condI->getType());
        //if (isa<StructType>(loadTy))
        //    return loadTy;
        //else {
        //    Value *loadV = condI->getOperand(0);
        //    if (isa<GetElementPtrInst>(loadV)) {
        //        loadTy = stripPointerType(loadV->getType());
        //        if (isa<StructType>(loadTy))
        //            return loadTy;
        //    }
        //    goto out;
        //}
        }
    }
out:
    return nullptr;
}
Type *pta::findPrivType(BasicBlock *bb, bool *is_ptr) {
    Instruction *termI = bb->getTerminator();
    if (!isa<BranchInst>(termI)) {
        //print_error(termI, nullptr, "no branch");
        return nullptr;
    } 

    BranchInst *brI = cast<BranchInst>(termI);
    if (brI->isUnconditional()) {
        BasicBlock *pred = bb->getSinglePredecessor();
        if (!pred) {
            //print_debug(bb, bb->getParent(), "multiple preds");
            return nullptr;    
        } else {
            return findPrivType(pred, is_ptr);
        }
    }

    Value *condV = brI->getOperand(0);
    if (!isa<Instruction>(condV)) {
        //print_debug(brI, "not condI");
        return nullptr;
    } 
    return findCondType(cast<Instruction>(condV), is_ptr);
}

BasicBlockSet *pta::findErrorBB(Function *func, int op) {

    InstructionList worklist;
    InstructionSet visited;
    InstructionSet phiset;
    InstructionSet ephi;
    Val2Idx phi2idx;

    BasicBlockSet *bbset = nullptr;
    for (auto &B : *func) {
        for (auto I = B.begin(), E = B.end(); I != E; ++I) {
            if (!isa<PHINode>(&*I))
                continue;
            if (auto ity = dyn_cast<IntegerType>(I->getType())) {
                if (ity->getBitWidth() == 1)
                    continue;
            }
            PHINode *phi = cast<PHINode>(&*I);
            bool is_ptr = isa<PointerType>(phi->getType());

            Indices idx;
            for (unsigned i=0; i<phi->getNumIncomingValues(); ++i) {
                Value *v = phi->getIncomingValue(i);
                if (is_ptr) {
                    if (auto ci = dyn_cast<ConstantExpr>(v)) {
                        Instruction *constI = ci->getAsInstruction();
                        if (isa<IntToPtrInst>(constI)) {
                            v = constI->getOperand(0);
                        }
                    }
                }
                if (auto cval = dyn_cast<ConstantInt>(v)) {
                    int ival = cval->getSExtValue();
                    // EPERM/EACCES/EROFS
                    int err;
                    err = (op == 0) ? -1 :
                        (op == 1) ? -13 : -30;
                    if (ival == err) {
                        phiset.insert(phi);
                        idx.push_back(i);
                    }
                }
            }
            if (!idx.empty()){
                Indices *idx_key = get_indices(idx);
                phi2idx[phi] = idx_key;
            }
        }
    }
    for (auto iter = phiset.begin(); iter != phiset.end(); ++iter) {
        Instruction *phi = *iter;
        worklist.push_back(phi);
        while (!worklist.empty()) {
            Instruction *ii = worklist.back();
            worklist.pop_back();
            if (visited.count(ii)) {
                if (isa<PHINode>(ii) && ii != phi
                    && ephi.count(ii) != 0)
                    ephi.insert(phi);
                continue;
            }
            visited.insert(ii);

            for (auto u : ii->users()) {
                if (isa<ReturnInst>(u)) {
                    ephi.insert(phi);
                }
                else if (isa<PHINode>(u) || isa<CastInst>(u)) {
                    worklist.push_back(cast<Instruction>(u));
                }   
            }
        }
    }
    for (auto phi : ephi) {
        print_debug(phi, "ephi");
        Indices *idx = phi2idx[phi];
        if (!idx)
            continue;
        if (!bbset) {
            bbset = new BasicBlockSet;
        }
        for (auto ii : *idx) {
            bbset->insert(cast<PHINode>(phi)->getIncomingBlock(ii));
        }
    }

    return bbset;
}

bool pta::isInterestingFunc(Function *func) {
    Type *retTy = func->getReturnType();
    if (!isa<IntegerType>(retTy) && !isa<PointerType>(retTy))
        return false;
    if (auto ity = dyn_cast<IntegerType>(retTy)) {
        if (ity->getBitWidth() == 1)
            return false;
    }
    BasicBlock *termB = &func->back();
    Instruction *retI = termB->getTerminator();
    if (!isa<ReturnInst>(retI))
        return false;
    Value *retV = retI->getOperand(0);
    if (!isa<PHINode>(retV))
        return false;

    return true;
}

StructType *pta::find_gv_cast(Value *v) {
  auto gv = dyn_cast<GlobalVariable>(v);
  if (!gv)
    return nullptr;
  for (auto u : gv->users()) {
    if (isa<CastInst>(u)) {
      if (auto sty = get_pstr_type(m, u->getType())) {
        if (sty->hasName())
          return sty;
      }
    } else if (auto ce = dyn_cast<ConstantExpr>(u)) {
      if (ce->getOpcode()==Instruction::BitCast) {
        if (auto sty = get_pstr_type(m, u->getType())) {
          if (sty->hasName())
            return sty;
        }
      }
    }
  }
  return nullptr;
}

void pta::find_ptypes(pfunc *pf, Value *dst,
                      ValueList *uselist, ValueSet *callset,
                      bool pcheck, bool isptr) {
    if (pcheck) {
      if (!uselist) {
        print_debug(dst, "no uselist");
        return;
      }
      bool res = pcheck_passed(dst, uselist);
      if (!res) {
        if (DEBUG) {
          print_debug(dst, "unchecked");
        }
        return;       
      }
    }
    if (isptr) {
      print_debug(dst, "strdst_ptr");
    } else {
      print_debug(dst, "strdst obj");
    }

    ValueSet srcset, visited, ldset, dstset;

    if (isa<GlobalVariable>(dst)) {
      if (dst->hasName()) {
        if (!isptr)
          pf->gpobj->insert(dst);
        else
          pf->gpptr->insert(dst);
      }
      return;
    }
    if (pf->sysctl_data) {
      if (auto sty = get_pstr_type(m, dst->getType())) {
        if (sty->getName().startswith("struct.ctl_table")) {
          if (pf->sysctl_data->hasName()) {
            pf->gpobj->insert(pf->sysctl_data);
            if (auto sty = get_pstr_type(m, pf->sysctl_data->getType())) {
              if (sty->hasName())
                pf->pobj->insert(sty);
              else {
                if (sty = find_gv_cast(pf->sysctl_data))
                  pf->pobj->insert(sty);
              }
            }
          }
          return;
        } 
      }
    }

    // privilege object types
    backward_find_sty(dst, &visited, &srcset, &ldset, uselist, callset);
    if (!isptr)
      dump_backward_sty(&srcset, pf->pobj, pf->gpobj, pf->palloca,
                        pf->pobj2inst, pf->gpobj2inst);
    else
      dump_backward_sty(&srcset, pf->pptr, pf->gpptr);
    // privilege pointer types
    while (ldset.size()) {
      srcset.clear();
      dstset.clear();
      for (auto ld : ldset) {
        if (isa<LoadInst>(ld)) {
          Value *dst = cast<User>(ld)->getOperand(0);
          dstset.insert(dst);
        } else if (auto ci = dyn_cast<CallInst>(ld)) {
          if (obj2strdst.count(ld)) {
            auto _strdst = obj2strdst[ld];
            for (auto dst : *_strdst) {
              dstset.insert(dst);
            }
          }
          if (ci->getFunction()->getName().startswith("prepare_creds")) {
            pf->pptr->insert(taskTy);
          }
        }
      }
      ldset.clear();
      for (auto dst : dstset) {
        backward_find_sty(dst, &visited, &srcset, &ldset, uselist, callset);
      }
      dump_backward_sty(&srcset, pf->pptr, pf->gpptr);  
    }
}

void pta::backward_find_sty(Value *_v, ValueSet *visited,
                            ValueSet *srcset, ValueSet *ldset,
                            ValueList *uselist, ValueSet *callset,
                            bool isVal, std::map<Value*, ValueList*> *ld2ulist) {
  ValueSet _srcset, _ldset;
  ValueList worklist, ulist;
  std::set<std::pair<Value*, Value*>> udpair;
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

  if (ld2ulist) {
    while (ulist.size()) {
      auto prev = ulist.back();
      if (udpair.count(std::make_pair(prev, v))) {
        break;
      }
      if (isa<User>(prev)) {
        if (is_use_def(cast<User>(prev), v)) {
          break;
        }
      }
      ulist.pop_back();
    }
    ulist.push_back(v);
  }

  if (is_skip_type(v->getType()))
    continue;

  if (_is_err_ptr(v))
    continue;

  if (!isVal) {
    int size = v->getType()->isPointerTy() ? 64 
              : v->getType()->getPrimitiveSizeInBits();
    if (size < 64)
      continue;
  } else {
    // Value should be a non-pointer
    if (isa<PointerType>(v->getType()))
      continue;
  }
  
  if (DEBUG) {
    print_debug(v, "bsty");
  }

  if (auto arg = dyn_cast<Argument>(v)) {
    // Find the caller from the uselist first.
    bool found=false;
    if (uselist) {
      for (auto it = uselist->begin(); it != uselist->end(); ++it) {
        if (*it == v && (it != uselist->begin())) {
          worklist.push_back(*(--it));
          udpair.insert(std::make_pair(v, *it));
          found=true;
          break;
        }
      }
    }
    // If there is no caller from the uselist, find it from callset.
    if (!found) {
      for (auto c : *callset) {
        auto ci = dyn_cast<CallInst>(c);
        FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
          if (callee == arg->getParent()) {
            int i = arg->getArgNo();
            if (i < ci->arg_size()) {
              if (val2off.count(arg) && val2off.count(ci->getOperand(i))) {
                auto idx = val2off[arg];
                auto _idx = val2off[ci->getOperand(i)];
                if (idx == _idx) {            
                  worklist.push_back(ci->getArgOperand(i));
                }
              } else {
                worklist.push_back(ci->getArgOperand(i));
              }
            }
          }
        }
      }
    }
    continue;
  } else if (isa<Instruction>(v)) {
    if (is_global(cast<Instruction>(v))) {
      _srcset.insert(v);
      continue;
    }
    ii = cast<Instruction>(v);
  }
  else if (isa<ConstantExpr>(v)) {
    ii = cast<ConstantExpr>(v)->getAsInstruction();
  }

  if (!ii)
    continue;

  if (auto sty = get_pstr_type(m, ii->getType())) {
    if (!is_list_struct(sty)) {
      _srcset.insert(v);
    }
  } 

  for (auto u : ii->users()) { 
    if (!isa<CastInst>(u))
      continue;
    if (auto sty = get_pstr_type(m, u->getType())) {
      if (!_is_err_ptr(u) && !is_skip_type(u->getType()) && !is_list_struct(sty))
        _srcset.insert(u);
    }
  }

  switch(ii->getOpcode()) {
    case Instruction::Alloca: {
      _srcset.insert(v);
      break;
      //_srcset.clear();
      //if (ldset)
      //  _ldset.clear();
      //return;
    }
    case Instruction::GetElementPtr: {
      if (is_skip_type(ii->getOperand(0)->getType()))
        break;
      if (auto sty = get_pstr_type(m, ii->getOperand(0)->getType())) {
        if (!is_list_struct(sty)) {
          _srcset.insert(v);
        }
      }
      worklist.push_back(ii->getOperand(0));
      break;
    }
    case Instruction::Call:
      if (is_asm_get_current(ii)) {
        _srcset.insert(ii);
        break;
      }
      else if (is_address_space_op(ii))
        break;
      else if (is_builtin_container_of(ii)) {
        if (get_callee_function_name(ii) == "make_kuid")
          worklist.push_back(ii->getOperand(1));
        else
          worklist.push_back(ii->getOperand(0));
      } else if (auto callee = get_callee_function_direct(ii)) {
        if (is_alloc_function(callee->getName().str())) {
          if (ldset) {
            _ldset.insert(v);
            if (ld2ulist)
              ld2ulist->insert(std::make_pair(v, new ValueList(ulist)));
          }
        } else if (is_skip_func(callee)) {
          break;
        } else {
          auto term = callee->back().getTerminator();
          if (term) {
            worklist.push_back(term);
            udpair.insert(std::make_pair(v, term));
          }
        }
      }
      break;

    case Instruction::Select:
      worklist.push_back(ii->getOperand(1));
      worklist.push_back(ii->getOperand(2));
      break;

    case Instruction::Load:
      if (ldset) {
        _ldset.insert(v);
        if (ld2ulist)
          ld2ulist->insert(std::make_pair(v, new ValueList(ulist)));
      }
      break;

    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::Trunc:
    case Instruction::Mul:
    case Instruction::UDiv:
    case Instruction::SDiv:
      if (isVal) {
        for (unsigned i=0; i<ii->getNumOperands(); ++i)
          worklist.push_back(ii->getOperand(i));
      }
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

  for (auto s : _srcset) {
    srcset->insert(s);
  }
  if (ldset) {
    for (auto l : _ldset) {
      ldset->insert(l);
    } 
  }
  return;
}

bool pta::is_from_alloca(Value *val, ValueSet *callset, ValueList *uselist) {
  ValueList worklist;
  ValueSet visited;

  if (from_alloca.count(val))
    return true;

  worklist.push_back(val);

  while (worklist.size()) {

  Instruction *ii = nullptr;
  Value *v = worklist.back();
  worklist.pop_back();
  if (visited.count(v))
    continue;
  if (from_alloca.count(v))
    return true;
  visited.insert(v);
  if (auto arg = dyn_cast<Argument>(v)) {
    if (!callset)
      continue;
    for (auto c : *callset) {
      auto ci = dyn_cast<CallInst>(c);
      if (ci->arg_size() <= arg->getArgNo())
        continue;
      FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
          if (callee == arg->getParent()) {
            worklist.push_back(ci->getArgOperand(arg->getArgNo()));
            break;
          }
        }
    }
    continue;
  } else if (isa<Instruction>(v)) {
    ii = cast<Instruction>(v);
  } else if (isa<ConstantExpr>(v)) {
    ii = cast<ConstantExpr>(v)->getAsInstruction();
  }

  if (!ii)
    continue;

  switch(ii->getOpcode()) {
    case Instruction::Alloca: {
      from_alloca.insert(val);
      return true;
    }
    case Instruction::GetElementPtr: {
      worklist.push_back(ii->getOperand(0));
      break;
    }
    case Instruction::Call:
      if (is_address_space_op(ii))
        break;
      if (is_builtin_container_of(ii)) {
        if (get_callee_function_name(ii) == "make_kuid")
          worklist.push_back(ii->getOperand(1));
        else
          worklist.push_back(ii->getOperand(0));
      } else if (auto callee = get_callee_function_direct(ii)) {
        if (is_alloc_function(callee->getName().str()))
          break;
        if (is_skip_func(callee)) {
          break;
        }
        worklist.push_back(callee->back().getTerminator());
      }
      break;

    case Instruction::Select:
      worklist.push_back(ii->getOperand(1));
      worklist.push_back(ii->getOperand(2));
      break;

    case Instruction::Load:
      if (uselist) {
        if (std::find(uselist->begin(), uselist->end(), ii) != uselist->end())
          return true;
      }
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

  return false;
}


// backward: find the source of the value (i.e., load, alloca or gv).
// usage: call backward and insert the 'users' of srcset elements.
void pta::backward(Value *_v, std::set<size_t> *visited, ValueSet *srcset,
        ValueSet *callset, ValueList *uselist, bool recursive) {

  ValueList worklist;
  worklist.push_back(_v);

  while (worklist.size()) {
    Instruction *ii = nullptr;
    Value *v = worklist.back();
    worklist.pop_back();
    if (!v)
      continue;
    Indices *idx = nullptr;
    if (val2off.count(v))
      idx = val2off[v];
    llvm::hash_code hash = hash_value(std::make_pair(v, idx));
    if (visited->count(hash)) {
      continue;
    }

    visited->insert(hash);

    if (uselist) {
      if (std::find(uselist->begin(), uselist->end(), v) != uselist->end()) {
        continue;
      }
    }
    if (DEBUG) {
      print_debug(v, "backward");
      if (val2off.count(v)) {
        auto idx = val2off[v];
        dump_indices(errs(), *idx);
      }
    }

    if (isa<Instruction>(v)) {
      ii = cast<Instruction>(v);
    } else if (isa<ConstantExpr>(v)) {
      ii = cast<ConstantExpr>(v)->getAsInstruction();
    } else if (isa<GlobalVariable>(v)) {
      srcset->insert(v); 
    } else if (auto arg = dyn_cast<Argument>(v)) {
      bool found_callee = false;
      if (uselist)
        for (auto it = uselist->begin(); it != uselist->end(); ++it) {
          if (auto ci = dyn_cast<CallInst>(*it)) {
            if (get_callee_function_direct(ci)==arg->getParent()) {
              worklist.push_back(ci->getArgOperand(arg->getArgNo()));
              copy_offset_safe(ci->getArgOperand(arg->getArgNo()), *it, 0);
              found_callee = true;
              break;
            }
          }
        }
      
      if (!found_callee) {
        for (auto c : *callset) {
          if (!isa<CallInst>(c))
            continue;
          auto ci = dyn_cast<CallInst>(c);
          if (get_callee_function_direct(ci)==arg->getParent()) {
            worklist.push_back(ci->getArgOperand(arg->getArgNo()));
            copy_offset_safe(ci->getArgOperand(arg->getArgNo()), v, 0);
            found_callee = true;
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

    if (_is_err_ptr(ii))
      continue;
    int size = ii->getType()->isPointerTy() ? 64 
             : ii->getType()->getPrimitiveSizeInBits();
    if (size < 64)
      continue;
    if (is_alloc(ii)) {
        srcset->insert(v);
        continue;
    }

    switch(ii->getOpcode()) {
    case Instruction::Load: {
      srcset->insert(v);
      push_idx_safe(ii->getOperand(0), v, 0);
      if (recursive)
        worklist.push_back(ii->getOperand(0));
      break;
    }

    case Instruction::Call: {
      if (is_address_space_op(ii))
        break;
      if (is_builtin_container_of(ii)) {
        int op = 0;
        if (get_callee_function_name(ii) == "make_kuid")
          op = 1;
        if (get_callee_function_name(ii) == "__builtin_container_of" &&
            isa<ConstantInt>(ii->getOperand(1))) {
            copy_offset_safe(ii->getOperand(0), v, (-1)*cast<ConstantInt>(ii->getOperand(1))->getZExtValue());
        } else {
            copy_offset_safe(ii->getOperand(op), v, 0);
        }
        worklist.push_back(ii->getOperand(op));
        break;
      }

      FunctionSet funcs;
      get_call_dest(ii, funcs);
      for (auto callee : funcs) {
        if (is_skip_func(callee))
          continue;
        if (callee->getName() == "kstrdup") {
          copy_offset_safe(ii->getOperand(0), v, 0);
          worklist.push_back(ii->getOperand(0));
          break;
        }
        if (callset) {
          callset->insert(ii);
        }
        copy_offset_safe(callee->back().getTerminator(), v, 0);
        worklist.push_back(callee->back().getTerminator());
      }
      break;
    }
    case Instruction::Select:
      copy_offset_safe(ii->getOperand(1), v, 0);
      copy_offset_safe(ii->getOperand(2), v, 0);

      worklist.push_back(ii->getOperand(1));
      worklist.push_back(ii->getOperand(2));
        break;

    case Instruction::GetElementPtr: {
        int offset = gep2offset(ii);
        if (offset<0) offset = 0;
        copy_offset_safe(ii->getOperand(0), v, offset);

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
          copy_offset_safe(phi->getIncomingValue(i), v, 0);
          worklist.push_back(phi->getIncomingValue(i));
      }
      break;
    }
    case Instruction::BitCast:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::Trunc:
    //case Instruction::ZExt:
    //case Instruction::SExt:
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
        copy_offset_safe(ii->getOperand(i), v, 0);
        worklist.push_back(ii->getOperand(i));
      }
      break;

    default:
        break;
    } // switch
  } // while
}


// forward_load: find data loaded from user buffer.
void pta::forward_load(Value *ubuf, ValueSet *dset, ValueSet *callset, bool pcheck) {
  ValueList worklist, uselist;
  std::unordered_set<size_t> visited;
  std::set<size_t> _visited;
  std::set<std::pair<Value*,Value*>> udpair, retpair;

  Function *func = nullptr;
  if (isa<Argument>(ubuf))
      func = cast<Argument>(ubuf)->getParent();
  else if (isa<Instruction>(ubuf))
    func = cast<Instruction>(ubuf)->getFunction();


  //std::list<ValueSet*> dlist;
  llvm::hash_code hash = hash_value(std::make_pair(ubuf,val2off[ubuf]));
  hash = hash_value(std::make_pair(hash, ubuf));
  argset_ld.insert(hash);

  for (auto u : ubuf->users()) {
    udpair.clear();
    uselist.clear();
    uselist.push_back(ubuf);
    copy_offset(u, ubuf, 0);
    worklist.push_back(u);

  while (worklist.size()) {
    Value *vv = worklist.back();
    Value *prev = nullptr;
    bool is_udpair=false;

    worklist.pop_back();
    Instruction *ii = nullptr;
    if (isa<Instruction>(vv))
      ii = cast<Instruction>(vv);
    else if (isa<ConstantExpr>(vv)) {
      ii = cast<ConstantExpr>(vv)->getAsInstruction();
    } else if (isa<Argument>(vv))
      ;
    else
      continue;

    while(uselist.size()) {
      prev = uselist.back();
      auto pprev = *(--uselist.end());
      if (udpair.count(std::make_pair(vv, prev))) {
        is_udpair=true;
        break;
      }
      if (isa<User>(vv)) {
        if (is_use_def(cast<User>(vv), prev)) {
          if (isa<CallInst>(prev)) {
            auto fname = get_callee_function_name(cast<Instruction>(prev));
            if (!is_parse_func(fname) && !is_builtin_container_of(prev) &&
                !is_copy_func(fname) && !is_asm_user(prev) && !is_alloc(prev)) {
              uselist.pop_back();
              if (udpair.count(std::make_pair(prev, pprev)))
                udpair.erase(std::make_pair(prev, pprev));
              continue;
            }
          }
          break;
        }
      }
     if (isa<Argument>(prev)) {
       Value *callee = nullptr;
       if (uselist.front() != prev) {
         callee = *(++uselist.rbegin());
       }
     }

     if (udpair.count(std::make_pair(prev, pprev)))
       udpair.erase(std::make_pair(prev, pprev));
     uselist.pop_back();
    }

    if (std::find(uselist.begin(), uselist.end(), vv) != uselist.end())
      continue;

    if (is_skip_type(vv->getType()))
      continue;

    if (is_alloc(vv) && !is_udpair)
      continue;

    if (auto ii = dyn_cast<Instruction>(vv)) {
      if (ii->getFunction()->getName().contains("ioctl")) {
        // check the switch case context for ioctl
        if (invalid_switch_context(ii, &uselist)) {
          if (DEBUG)
            print_debug(ii, "invalid switch!");
          continue;
        }
      }  
    }

    // if vv is not inserting new element to the worklist,
    // should pop_back from the uselist.
    uselist.push_back(vv);

    Indices *idx_old=nullptr;
    if (val2off.count(vv))
      idx_old = val2off[vv];

    if (is_alloc(vv) || is_udpair) {
      if (!isa<StoreInst>(prev))
        copy_offset_safe(vv, prev, 0);
    } else
      copy_offset(vv, prev, 0);

    ValueSet useset;
    for (auto u : uselist) {
      useset.insert(u);
    }
    llvm::hash_code hash = hash_combine_range(useset.begin(), useset.end());
    if (visited.count(size_t(hash))) {
      uselist.pop_back();
      continue;
    } else {
      visited.insert(size_t(hash));
    }

    int level = 0;
    if (!from_alloca.count(vv)) {
      for (auto rit = uselist.rbegin(); rit != uselist.rend(); ++rit) {
        if (isa<CallInst>(*rit)) {
          auto fname = get_callee_function_name(cast<CallInst>(*rit));
          if (is_copy_func(fname))
            break;
          if (is_parse_func(fname))
            level++;
        } else if (isa<LoadInst>(*rit)) {
          //if (*rit == ubuf && level < 0)
          level++;
        } else if (isa<StoreInst>(*rit)) {
          level--;
        }
        if (isa<AllocaInst>(*rit)) {
          if (level == 0) {
            from_alloca.insert(vv);
            break;
          }
        }
      }
    }
    bool track=false;
    if (isa<Argument>(vv)) {
      Value *caller = vv;
      if (uselist.front() != vv)
        caller = prev;
      // if dset exists, use it.
      // otherwise, make a new dset.
      llvm::hash_code hash = hash_value(std::make_pair(vv, val2off[vv]));
      hash = hash_value(std::make_pair(hash, caller));
      if (argset_ld.count(hash)) {
        continue;
      }

      argset_ld.insert(hash);

      if (val2off[vv]->size() == 0) {
        priv_vals.insert(vv);
      }

      for (auto u : vv->users()) {
        //copy_offset(u, vv, 0);
        worklist.push_back(u);
        track |= true;
      }
      if (DEBUG) {
        if (DEBUG_USELIST)
          for (auto u : uselist){
            print_debug(u, "uselist");
          }
        print_debug(vv, "forward_load");
        if (val2off.count(vv)) {
          auto idx = val2off[vv];
          dump_indices(errs(), *idx);
        }
      }
      if (!track)
        uselist.pop_back();
      continue;
    }
    if (is_alloc(ii)) {
      for (auto u : ii->users()) {
        worklist.push_back(u);
        track |= true;
      }
    } else {     
    switch(ii->getOpcode()) {
    case Instruction::Load: {
      auto idx = val2off[vv];
      // nothing to load or mismatching offset
      if (idx->size() == 0 || !can_load(idx, &uselist)) {
        if (!idx_old)
          val2off.erase(vv);
        else {
          val2off[vv] = idx_old;
        }
        break;
      }

      // pop index
      pop_idx(vv);

      if (val2off[vv]->size() == 0) {
        priv_vals.insert(vv);
      }

      // populate dset if level==1
      if (idx->size() == 1) {
        dset->insert(vv);
        if (pcheck) pcheck_passed(vv, &uselist);
      }
      // proceed forward if level>2
      else {
        for (auto u : vv->users()) {
          if (auto ui = dyn_cast<Instruction>(u)) {
            worklist.push_back(u);
            track |= true;
          }
        }
      }
      break;

      }
    case Instruction::Store:
      // store the user data/ptr at a kobj
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        ValueSet _srcset;

        if (!is_list_struct(ii->getOperand(0)->getType())) {
          push_idx_safe(ii->getOperand(1), vv, 0);
        }
        else
          copy_offset_safe(ii->getOperand(1), vv);

        backward(ii->getOperand(1), &_visited, &_srcset, callset, &uselist);

        for (auto _s : _srcset) {
          if (!is_alloc(_s))
            continue;
          if (0 & DEBUG) {
            print_debug(_s, "store dst");
          }
          udpair.insert(std::make_pair(_s, vv));
          worklist.push_back(_s);
          track |= true;
          //for (auto _u : _s->users()) {
          //  copy_offset(_u, _s, 0);
          //  worklist.push_back(_u);
          //  track |= true;
          //}
          //if (track) {
          //  uselist.push_back(_s);
          //  udpair.insert(std::make_pair(_s, vv));
          //}
        }
      }
      // store a kptr at the user ptr
      else if (prev == ii->getOperand(1)) {
        //auto idx = val2off[vv];
        //if (idx->size() >= 1 && idx->back() == 0) {
        //  Value *v = ii->getOperand(0);
        //  ValueSet _srcset;
        //  Indices _idx = *idx;
        //  _idx.pop_back();
        //  val2off[v] = get_indices(_idx);
        //  worklist.push_back(v);
        //  track |= true;
        //  udpair.insert(std::make_pair(v, vv));
        //}
      }
      break;
    case Instruction::Call: {
      if (is_address_space_op(ii))
        break;
      auto fname = get_callee_function_name(ii);
      // NOTE: unlikely to call container_of
      if (is_builtin_container_of(ii)) {
        int op = 0;
        if (get_callee_function_name(ii) == "make_kuid")
          op = 1;
        auto argv = cast<CallInst>(ii)->getArgOperand(op);
        if (argv != prev && !retpair.count(std::make_pair(argv, prev)))
          break;
        for (auto u : vv->users()) {
          if (!is_udpair &&
              get_callee_function_name(ii) == "__builtin_container_of" &&
              isa<ConstantInt>(ii->getOperand(1)))
            copy_offset(vv, vv, cast<ConstantInt>(ii->getOperand(1))->getZExtValue());
          
          worklist.push_back(u);
          track |= true;
        }
      } else if (is_asm_user(ii)) {
        for (auto u : vv->users()) {
          //copy_offset(u, vv, 0);
          worklist.push_back(u);
          track |= true;
        }
      } else if (is_cmp_func(fname) || 
                is_parse_func(fname) ||
                is_proc_parse_func(fname)) {
            // NOTE: let's just skip offset check
            // NOTE: compare result can be treated as the data
            auto idx = val2off[vv];
            if (idx->size() == 0) {
              if (!idx_old)
                val2off.erase(vv);
              else {
                val2off[vv] = idx_old;
              }
              break;
            }
            Value *dst = vv;
            if (!is_proc_parse_func(fname)) {
              auto dop = get_parse_dst(ii);
              if (dop == -2)
                break;
              if (dop >= 0)
                dst = ii->getOperand(dop);
            }
            copy_offset(dst, vv, 0);
            if (!is_proc_parse_func(fname))
              pop_idx(dst);
            dset->insert(dst);
            if (pcheck) pcheck_passed(vv, &uselist);

        } else if (is_copy_func(get_callee_function_name(ii))) {
          int src_op, dst_op;
          std::vector<int> dst_ops;
          if (get_callee_function_name(ii).startswith("sscanf")) {
            src_op = 0;
            for (int op = 2; op < cast<CallInst>(ii)->arg_size(); ++op) {
              dst_ops.push_back(op);
            }
          } else {
            src_op = get_copy_src(ii);
            dst_ops.push_back(get_copy_dst(ii));
          }

          for (auto iter = dst_ops.begin(); iter != dst_ops.end(); ++iter) {
            dst_op = *iter;
            auto *idx = val2off[vv];
            int narg = cast<CallInst>(ii)->arg_size();
            if (src_op < 0 || dst_op < 0 || narg <= src_op || narg <= dst_op)
              break;
            Value *src = cast<CallInst>(ii)->getArgOperand(src_op);
            Value *dst = cast<CallInst>(ii)->getArgOperand(dst_op);
            if (prev != src && !retpair.count(std::make_pair(src, prev)))
              break;
            int offset = 0;
            if (idx->size()>0)
              offset= idx->back();
            if (!can_load(idx, &uselist))
              break;
            if (idx->size() <= 1) {
              if (!get_callee_function_name(ii).startswith("__arch_copy_")) {
                dset->insert(vv);
                if (pcheck) pcheck_passed(vv, &uselist);
              }
            }

            ValueSet _srcset;
            track |= true;
            udpair.insert(std::make_pair(dst, vv));
            copy_offset(dst, src, 0);
            backward(dst, &_visited, &_srcset, callset, &uselist);
            for (auto _s : _srcset) {
              if (DEBUG) {
                print_debug(_s, "memcpy ubuf");
              }
              if (!is_alloc(_s))
                continue;
              udpair.insert(std::make_pair(_s, vv));
              worklist.push_back(_s);
              track |= true;
            }
          }
        } else {
          FunctionSet funcs;
          get_call_dest(ii, funcs);
          for (auto callee : funcs) {
            if (is_skip_func(callee))
              continue;
            if (callee->isVarArg())
              continue;

            for (unsigned i=0; i<cast<CallInst>(ii)->arg_size(); ++i) {
              if (i == callee->arg_size())
                break;
              Value *argv = cast<CallInst>(ii)->getArgOperand(i);
              if (prev == argv || retpair.count(std::make_pair(argv, prev))) {
                Argument *arg = callee->getArg(i);
                //copy_offset(arg, vv, 0);
                worklist.push_back(arg);
                track |= true;
                udpair.insert(std::make_pair(arg, vv));
                callset->insert(vv);
                if (0 & DEBUG)
                  errs() << "indcall: " << callee->getName() << "-" << i << "\n";
              }
            }
          }
        }
        break;
    }
    case Instruction::Ret: {
      if (ii->getFunction()==func)
        break;
      for (auto c : *callset) {
        auto ci = dyn_cast<CallInst>(c);
        if (!ci)
          continue;
        FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
         if (is_skip_func(callee))
           continue;
         if (callee->isVarArg())
           continue;
         if (callee == ii->getFunction()) {
           for (auto u : ci->users()) {
             if (isa<Instruction>(u)) {
               if (val2off[vv]->size() == 0) {
                 priv_vals.insert(u);
               }
               worklist.push_back(u);
               udpair.insert(std::make_pair(u, vv));
               copy_offset_check(u, vv, 0);
               retpair.insert(std::make_pair(c, vv));
               track |= true;
             }
           }
         }
        }
      }
      break;
    }
    case Instruction::GetElementPtr:
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        int offset = gep2offset(ii);
        if (offset>0 && !is_udpair)
          copy_offset(vv, vv, (-1)*offset);
        else if (offset < 0){
          break;
        }


        for (auto u : vv->users()) {
          //int offset = gep2offset(ii);
          //if (offset < 0)
          //  copy_offset(u, vv, 0);
          //else
          //  copy_offset(u, vv, (-1)*offset);
          worklist.push_back(u);
          track |= true;
        }
      }
      break;
    case Instruction::Select:
      if (prev != ii->getOperand(0) &&
          !retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        for (auto u : vv->users()) {
          if (auto ui = dyn_cast<Instruction>(u)) {
            worklist.push_back(u);
            track |= true;
          }
        }
      }
      break;

    case Instruction::Add:
    case Instruction::Sub:
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        for (auto u : vv->users()) {
          if (auto ui = dyn_cast<Instruction>(u)) {
            //copy_offset(ui, vv, 0);
            worklist.push_back(ui);
            track |= true;
          }
        }
      }
      break;

    case Instruction::Trunc:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
      if (val2off[vv]->size() > 0)
        break;

    case Instruction::BitCast:
      if (_is_err_ptr(ii))
        break;

    case Instruction::And:
    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::Mul:
    case Instruction::UDiv:
    case Instruction::SDiv:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
    case Instruction::PHI:
      for (auto u : vv->users()) {
        if (auto ui = dyn_cast<Instruction>(u)) {
          //copy_offset(ui, vv, 0);
          worklist.push_back(ui);
          track |= true;
        }
      }
      break;

    // ignore
    //case Instruction::ICmp:
    default:
      break;
    } // switch
    } // else
    if (DEBUG) {
      if (DEBUG_USELIST)
        for (auto u : uselist){
          print_debug(u, "uselist");
        }
      print_debug(ii, "forward_load");
      if (val2off.count(vv)) {
        auto idx = val2off[vv];
        dump_indices(errs(), *idx);
      }
    }
    if (!track) {
      uselist.pop_back();
      continue;
    }
  } // while(worklist)

  } // for (ubuf->users())

  //while (dlist.size()) {
  //  ValueSet *prev = nullptr;
  //  ValueSet *curr = dlist.back();
  //  dlist.pop_back();
  //  if (dlist.size())
  //    prev = dlist.back();

  //  for (auto s : *curr) {
  //    if (prev)
  //      prev->insert(s);
  //    dset->insert(s);
  //  }
  //}
}

bool is_phi_false(PHINode *phi, BasicBlockSet *bbset) {
  if (phi->getType()->getPrimitiveSizeInBits() != 1)
      return false;
  for (unsigned i=0; i<phi->getNumIncomingValues(); ++i) {
    if (bbset->count(phi->getIncomingBlock(i))) {
      Value *val = phi->getIncomingValue(i);
      if (auto c = dyn_cast<Constant>(val)) {
        if (c->isZeroValue()) {
          return true;
        }
      }
    }
  }
  return false;
}

bool is_phi_true(PHINode *phi, BasicBlockSet *bbset) {
  if (phi->getType()->getPrimitiveSizeInBits() != 1)
      return false;
  for (unsigned i=0; i<phi->getNumIncomingValues(); ++i) {
    if (bbset->count(phi->getIncomingBlock(i))) {
      Value *val = phi->getIncomingValue(i);
      if (auto c = dyn_cast<Constant>(val)) {
        if (c->isOneValue()) {
          return true;
        }
      }
    }
  }
  return false;
}
bool pta::pcheck_passed(Value *v, ValueList *uselist) {
  bool res = false;
  static ValueSet cond_visited;
  for (auto u : *uselist) {
    if (auto i = dyn_cast<Instruction>(u)) {
      if (auto bb = i->getParent()) {
        if (normalBB.count(bb)) {
          //if (DEBUG) {
            errs() << "pcheck passed at: " << bb->getParent()->getName() << "\n";
            errs() << *bb << "\n";
            for (auto uu : *uselist) {
              print_debug(uu, "ulist");
            }
          //}
          res = true;

          auto iset = normalBB2Inst[bb];
          if (!iset)
            continue;
          for (auto err : *iset) {
            if (!cond_visited.count(err)) {
              find_cond_val(err, &pchk_cond);
              cond_visited.insert(err);
            }
          }
          break;
        }
      }
    }
  }
  // if (v && !res)
  //   unchecked.insert(v);
  
  if (v) {
    if (res)
      checked.insert(v);
    else
      unchecked.insert(v);
  }
  return res;
}

void pta::collect_normalBB(Value *err, ValueSet *_visited,
                           ValueSet *callset) {
  std::set<Use*> phiuseset;
  std::set<Use*> bruseset;
  ValueSet brset, brtmp;

  if (_visited->count(err))
    return;
  _visited->insert(err);
  ValueSet visited;
  ValueList worklist;

  for (auto u : err->users())
    worklist.push_back(u);

  while(worklist.size()) {
    Value *v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (!isa<Instruction>(v))
        continue;
    auto i = cast<Instruction>(v);
    switch(i->getOpcode()) {
        case Instruction::ICmp: {
          int errorBB = 1;
          auto icmp = cast<ICmpInst>(i);
          auto pred = icmp->getPredicate();
          if (pred == CmpInst::ICMP_EQ) {
            if (isa<Constant>(i->getOperand(1)))
              errorBB = 0;
            else
              errorBB = 1;
          } else if (pred == CmpInst::ICMP_SLT) {
            errorBB = 0;
          }
          for (auto u : i->users()) {
            if (isa<BranchInst>(u)) {
              brtmp.insert(u);
              bruseset.insert(&u->getOperandUse(errorBB+1));
            }
          }
          break;
        }
        case Instruction::Ret:
          for (auto c : *callset) {
            auto ci = dyn_cast<CallInst>(c);
            FunctionSet funcs;
            get_call_dest(ci, funcs);
            for (auto callee : funcs) {
              if (callee == i->getFunction()) {
                 collect_normalBB(c, _visited, callset);
              }             
            }
          }
          break;
        case Instruction::PHI:
          for (int n=0; n<cast<PHINode>(i)->getNumIncomingValues(); n++) {
            if (visited.count(cast<PHINode>(i)->getIncomingValue(n)))
              phiuseset.insert(&i->getOperandUse(n));
          }
        case Instruction::BitCast:
        case Instruction::IntToPtr:
        case Instruction::PtrToInt:
        case Instruction::ZExt:
        case Instruction::Trunc:
        case Instruction::SExt:
        case Instruction::Add:
        case Instruction::And:
        case Instruction::Sub:
            for (auto u : v->users()) 
                worklist.push_back(u);
            break;
        default:
            break;
    }
  }
  
  for (auto phiu : phiuseset) {
    auto phi = phiu->getUser();
    auto bb = cast<PHINode>(phi)->getIncomingBlock(phiu->getOperandNo());
    auto next = cast<Instruction>(phi)->getParent();

    while(true) {
      if (auto succ = bb->getSingleSuccessor()) {
        if (auto pred = bb->getSinglePredecessor()) {
          next = bb;
          bb = pred;
          continue;
        }
      }
      break;
    }
    auto term = bb->getTerminator();
    if (isa<BranchInst>(term)) {
      brtmp.insert(term);
      for (int i=1; i<term->getNumOperands(); i++) {
        if (term->getOperand(i) == next)
          bruseset.insert(&term->getOperandUse(i));
      }
    }
  }
 
  for (auto bru : bruseset) {
    auto br = bru->getUser();
    auto errBB = bru->get();
  }

  for ( auto b : brtmp) {
    bool drop=true;
    for (int i=1; i<cast<Instruction>(b)->getNumOperands(); ++i) {
      if (!bruseset.count(&cast<Instruction>(b)->getOperandUse(i)))
        drop=false;
    }
    if (!drop)
      brset.insert(b);
  }

  for (auto b : brset) {
    ValueSet trueset, falseset;
    ValueList worklist;
    //print_debug(b, "br final");
    trueset.insert(cast<Instruction>(b)->getParent());
    falseset.insert(cast<Instruction>(b)->getParent());
    for (int i=1; i<cast<Instruction>(b)->getNumOperands(); ++i) {
      ValueSet *bbset;
      if (bruseset.count(&cast<Instruction>(b)->getOperandUse(i))) {
        bbset = &falseset;
      } else {
        bbset = &trueset;
      }
      worklist.push_back(cast<Instruction>(b)->getOperand(i));
      while(worklist.size()) {
        auto bb = cast<BasicBlock>(worklist.back());
        worklist.pop_back();
        if (bbset->count(bb))
          continue;
        bbset->insert(bb);
        for (auto SI = llvm::succ_begin(bb); SI != llvm::succ_end(bb); ++SI) {
          worklist.push_back(*SI);
        }
      }
    } 
    for (auto b : trueset) {
      if (!falseset.count(b)) {
        normalBB.insert(cast<BasicBlock>(b));
        auto iset = normalBB2Inst[cast<BasicBlock>(b)];
        if (!iset) {
          iset = new InstructionSet;
          normalBB2Inst[cast<BasicBlock>(b)] = iset;
        }
        if (isa<LoadInst>(err))
          iset->insert(cast<Instruction>(err));
      }
    }
  }
}

void pta::collect_interesting_bb(BasicBlock* bb, BasicBlock *pred, 
        ValueSet *callset, BasicBlockSet* bbset, int op) {
  if (bbset->count(bb))
    return;
  bbset->insert(bb);
  //print_debug(bb, bb->getParent(), "collect_interesting_bb");
  if (auto succ = bb->getSingleSuccessor()) {
    collect_interesting_bb(succ, bb, callset, bbset, op);
  } else {
    auto termI = bb->getTerminator();
    if (auto br = dyn_cast<BranchInst>(termI)) {
      bool related=false;
      assert(br->isConditional());
      Value *cond = br->getCondition();
      auto trueBB = br->getSuccessor(0);
      auto falseBB = br->getSuccessor(1);

      // PHI - Branch
      // %phi = phi i1 [true, %pred0], [false, %pred1]
      // %br i1
      if (auto phi = dyn_cast<PHINode>(cond)) {
        if (is_phi_true(phi, bbset)) {
          collect_interesting_bb(trueBB, bb, callset, bbset, op);
          related=true; 
        } else if (is_phi_false(phi, bbset)) {
          collect_interesting_bb(falseBB, bb, callset, bbset, op);
          related=true;
        } 
      } else if (auto cmp = dyn_cast<CmpInst>(cond)) {
        // PHI - ICmp - Branch
        // %phi = phi i1 [true, %pred0], [false, %pred1]
        // %cval = icmp eq i1 %phi, 0
        if (auto c = dyn_cast<Constant>(cmp->getOperand(1))) {
          if (auto phi = dyn_cast<PHINode>(cmp->getOperand(0))) {
            if (c->isOneValue()) {
              if (is_phi_true(phi, bbset)) {
                collect_interesting_bb(trueBB, bb, callset, bbset, op);
                related=true;
              } else if (is_phi_false(phi, bbset)) {
                collect_interesting_bb(falseBB, bb, callset, bbset, op);
                related=true;
              }
            } else if (c->isZeroValue()) {
              if (is_phi_true(phi, bbset)) {
                collect_interesting_bb(falseBB, bb, callset, bbset, op);
                related=true;
              } else if (is_phi_false(phi, bbset)) {
                collect_interesting_bb(trueBB, bb, callset, bbset, op);
                related=true;
              }
            }
          }
        }
      }
      if (!related) {
          collect_interesting_bb(trueBB, bb, callset, bbset);
          collect_interesting_bb(falseBB, bb, callset, bbset);
      }

    } else if (auto ret = dyn_cast<ReturnInst>(termI)) {
        for (auto c : *callset) {
          auto ci = dyn_cast<CallInst>(c);
          if (auto f = get_callee_function_direct(ci)) {
            if (f == ret->getFunction())
              collect_interesting_bb(c, callset, bbset, nullptr, op); 
          }
        }
    } else if (auto callbr = dyn_cast<CallBrInst>(termI)) {
      collect_interesting_bb(callbr->getDefaultDest(), bb, callset, bbset);
    }
  }
}
void pta::collect_interesting_bb(Value* v, ValueSet *callset,
                                 BasicBlockSet *trueSet,
                                 BasicBlockSet *falseSet,
                                 int op) {

  ValueSet cmpset;

  int true_op;
  int false_op;

  if (op < 0) {
    true_op = 0;
    if (auto ci = dyn_cast<CallInst>(v)) {
      true_op = get_cmp_true(get_callee_function_direct(ci)->getName());
    }
  } else {
    true_op = op;
  }
  if (true_op<0)
    return;
  false_op = true_op^1;

	if (DEBUG) {
    print_debug(v, "collect_bb");
  }
  ValueList worklist;
  worklist.push_back(v);
  if (v->getType()->getPrimitiveSizeInBits()==1)
    cmpset.insert(v);
  for (auto u : v->users())
      worklist.push_back(u);
  while(worklist.size()) {
      Value *v = worklist.back();
      worklist.pop_back();
      if (!isa<Instruction>(v))
          continue;
      auto i = cast<Instruction>(v);
      switch(i->getOpcode()) {
          case Instruction::ICmp:
              cmpset.insert(i);
              break;
          case Instruction::BitCast:
          case Instruction::IntToPtr:
          case Instruction::PtrToInt:
          case Instruction::ZExt:
          case Instruction::Trunc:
          case Instruction::SExt:
          case Instruction::Add:
          case Instruction::And:
          case Instruction::Sub:
              for (auto u : v->users()) 
                  worklist.push_back(u);
              break;
          default:
              break;
      }
  }
  for (auto cmp : cmpset) {
    trueSet->insert(cast<Instruction>(cmp)->getParent());
    if (falseSet)
     falseSet->insert(cast<Instruction>(cmp)->getParent());

    for (auto u : cmp->users()) {
      if (auto br = dyn_cast<BranchInst>(u)) {
        auto trueBB = br->getSuccessor(true_op);
        auto falseBB = br->getSuccessor(false_op);
        collect_interesting_bb(trueBB, br->getParent(), callset,
                               trueSet, true_op);
        if (falseSet)
          collect_interesting_bb(falseBB, br->getParent(), callset,
                                 falseSet, false_op);
      }
    }
    trueSet->erase(cast<Instruction>(cmp)->getParent());
    if (falseSet)
     falseSet->erase(cast<Instruction>(cmp)->getParent());
  }
}
void pta::collect_store(BasicBlockSet* trueSet, BasicBlockSet *falseSet,
                        ValueSet *strset, ValueSet* callset, FunctionSet *visited) {
  for (auto B : *trueSet) {
    if (falseSet->count(B))
      continue;
    for (auto I = B->begin(), E = B->end(); I != E; ++I) {
      if (isa<StoreInst>(&*I)) {
        if (auto c = dyn_cast<Constant>(I->getOperand(0))) {
            continue;
          if (c->isZeroValue())
            continue;
        } else if (is_increment(&*I)) {
          continue;
        }
        if (DEBUG) {
          print_debug(&*I, "collect_store");
        }
        strset->insert(I->getOperand(1));
              
      } else if (is_asm_store(&*I)) {
        int asm_dst = get_asm_addr(&*I);
        if (asm_dst>=0) {
          if (DEBUG) {
            print_debug(&*I, "collect_store");
          }
          strset->insert(cast<CallInst>(&*I)->getArgOperand(asm_dst));
          continue;
        }
      }
    }
  }
}
void pta::collect_store(Function *func, FunctionSet *visited,
                        ValueSet *strset, ValueSet *callset) {
  if (visited->count(func))
    return;
  visited->insert(func);
  for (auto &B : *func) {
    for (auto I = B.begin(), E = B.end(); I != E; ++I) {
      if (isa<StoreInst>(&*I)) {
        if (auto c = dyn_cast<Constant>(I->getOperand(0))) {
            if (c->isZeroValue())
              continue;
        } else if (is_increment(&*I)) {
          continue;
        }

        if (DEBUG) {
          print_debug(&*I, "collect_store");
        }
        strset->insert(I->getOperand(1));
              
      }
      if (auto ci = dyn_cast<CallInst>(&*I)) {
        int asm_dst = get_asm_addr(&*I);
        if (asm_dst>=0) {
          if (DEBUG) {
            print_debug(&*I, "collect_store");
          }

          strset->insert(ci->getArgOperand(asm_dst));    
          continue;
        }

        // Don't collect store from another functions (for now)
        //FunctionSet funcs;
        //get_call_dest(ci, funcs);
        //for (auto callee : funcs) {
        //  if (is_skip_function(callee->getName().str()))
        //    continue;
        //  callset->insert(ci);
        //  //print_debug(ci, "call");
        //  collect_store(callee, visited, strset, callset);
        //  callset->erase(ci);
        //}
      }
    }
  }
}
Value *pta::get_object(ValueList *uselist) {
  // ignore the first elem (store instruction)
  auto rit=++uselist->rbegin();
  for (; rit != uselist->rend(); ++rit) {
    if (!isa<Instruction>(*rit))
      continue;
    auto ii = cast<Instruction>(*rit);
    if (isa<CallInst>(ii)) {
      if (is_alloc_function(get_callee_function_name(ii).str()))
        return *rit;
    } else if (isa<AllocaInst>(ii) || isa<StoreInst>(ii) || isa<LoadInst>(ii)) {
      break;
    }
  }
  return nullptr;
}


void pta::sarg_from_pobj(pfunc *pf, Value *sarg) {
  ValueSet callset;
  std::set<std::pair<Value*, ValueList*>> srcset, sptrset;
  forward_store_src(sarg, &srcset, &callset);
  if (!srcset.size()) {
      errs() << "no store src\n";
      return;
  }
  for (auto p : srcset) {
    auto s = p.first;
    auto ulist = p.second;
    if (DEBUG) {
      print_debug(s, "store");
    }
    if (auto si = dyn_cast<StoreInst>(s)) {
      // find where the stored value is loaded from.
      ValueSet visited, _srcset, ldset;
      backward_find_sty(si->getOperand(0), &visited, &_srcset,
                        &ldset, ulist, &callset, true /*isVal*/);
      for (auto ld : ldset)
        if (isa<LoadInst>(ld)) {
          sptrset.insert(std::make_pair(cast<Instruction>(ld)->getOperand(0), ulist));
        }
    } else if (auto ci = dyn_cast<CallInst>(s)) {
      auto fname = get_callee_function_name(ci);
      int src_op = -1;
      if (is_copy_func(fname, false /*write*/))
        src_op = get_copy_src(ci, false);
      if (src_op < 0)
        continue;

      sptrset.insert(std::make_pair(ci->getArgOperand(src_op), ulist));
    }
  }

  for (auto p : sptrset) {
    print_debug(p.first, "sptr");
    find_ptypes(pf, p.first, p.second, &callset, true /*pcheck*/,
                false /*isptr*/);
  }

  // free the memory
  for (auto p : srcset) {
    delete p.second;
  }
}

void pta::sret_from_pobj(pfunc *pf) {
  ValueSet callset;
  ValueSet visited, _srcset, ldset;
  std::set<std::pair<Value*, ValueList*>> sptrset;
  std::map<Value*, ValueList*> ld2ulist;
  Value *ret = pf->write->back().getTerminator();
  print_debug(ret, "ret");
  backward_find_sty(ret, &visited, &_srcset,
                    &ldset, nullptr, &callset, 
                    true /*isVal*/, &ld2ulist);
  for (auto ld : ldset)
    if (isa<LoadInst>(ld)) {
      sptrset.insert(std::make_pair(cast<Instruction>(ld)->getOperand(0), ld2ulist[ld]));
    } 
  for (auto p : sptrset) {
    print_debug(p.first, "sptr");
    find_ptypes(pf, p.first, p.second, &callset, true /*pcheck*/,
                false /*isptr*/);
  }
  // free the memory
  for (auto p : ld2ulist) {
    delete p.second;
  }
}


void pta::forward_store_src(Value *dst,
                            std::set<std::pair<Value*, ValueList*>> *result, 
                            ValueSet *callset) {
  ValueList worklist;
  ValueSet visited;
  std::set<std::pair<Value*,Value*>> udpair;
  ValueList uselist;
  worklist.push_back(dst);

  while (worklist.size()) {
    Value *v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (DEBUG) {
      print_debug(v, "forward_src");
    }

    while (uselist.size()) {
      auto prev = uselist.back();
      if (udpair.count(std::make_pair(v, prev)))
        break;
      if (isa<User>(v))
        if (is_use_def(cast<User>(v), prev))
          break;
      uselist.pop_back();
    }
    uselist.push_back(v);

    bool track = false;
    if (isa<Argument>(v)) {
      track = true;
    }
    if (isa<Instruction>(v)) {
      auto ii = cast<Instruction>(v);
      if (ii->getFunction()->getName().contains("ioctl")) {
        // check the switch case context for ioctl
        if (invalid_switch_context(ii, &uselist)) {
          if (DEBUG)
            print_debug(ii, "invalid switch!");
          continue;
        }
      }    
      switch(ii->getOpcode()) {
        case Instruction::Call: {
          auto fname = get_callee_function_name(ii);
          if (is_proc_parse_func(fname)) {
            // proc_doxxx(..., int write=0, void *buffer, ...)
            if (auto c = dyn_cast<ConstantInt>(ii->getOperand(1))) {
              if (c->getZExtValue() == 1)
                break;
            }
            if (visited.count(cast<CallInst>(v)->getArgOperand(2))) {
              // find ctl_table->data
              auto ctl_data = get_ctl_data(cast<CallInst>(v)->getArgOperand(0));
              if (!ctl_data)
                break;
              result->insert(std::make_pair(ctl_data, new ValueList(uselist)));

              std::set<size_t> _visited;
              ValueSet _srcset;
              backward(ctl_data, &_visited, &_srcset, callset, nullptr, false /*recusive*/);
              for (auto _s : _srcset) {
                if (!is_alloc(_s))
                  continue;
                for (auto u : _s->users()) {
                  udpair.insert(std::make_pair(u, v));
                  worklist.push_back(u);
                  visited.insert(_s);
                }
              }
            }  
            break;
          }
          if (is_copy_func(fname, false /*write*/)) {
            int dst_op = get_copy_dst(ii, false /*write*/);
            int src_op = get_copy_src(ii, false /*write*/);
            if (dst_op < 0 || src_op < 0)
              continue;
            if (!visited.count(cast<CallInst>(v)->getArgOperand(dst_op)))
              continue;  
            result->insert(std::make_pair(v, new ValueList(uselist)));

            Value *src = cast<CallInst>(v)->getArgOperand(src_op);
            std::set<size_t> _visited;
            ValueSet _srcset;
            backward(src, &_visited, &_srcset, callset, nullptr, false /*recusive*/);
            for (auto _s : _srcset) {
              if (!is_alloc(_s))
                continue;
              for (auto u : _s->users()) {
                udpair.insert(std::make_pair(u, v));
                worklist.push_back(u);
                visited.insert(_s);
              }
            }
            break;
          }

          if (fname.startswith("seq_printf") ||
              fname.startswith("seq_puts")) {
            auto ci = dyn_cast<CallInst>(v);
            if (!visited.count(ci->getArgOperand(0)))
              continue;
            result->insert(std::make_pair(v, new ValueList(uselist)));
            ValueSet ldset;
            for (int i=2; i < ci->arg_size(); ++i) {
              std::set<size_t> _visited;
              ValueSet _srcset;
              backward(ci->getArgOperand(i), &_visited, &_srcset, callset, nullptr, false /*recursive*/);
              for (auto _s : _srcset) {
                if (isa<LoadInst>(_s))
                  ldset.insert(_s);
              }
            }
            for (auto ld : ldset) {
              std::set<size_t> _visited;
              ValueSet _srcset;
              backward(cast<Instruction>(ld)->getOperand(0), 
                      &_visited, &_srcset, callset, nullptr, false /*recursive*/);
              for (auto _s : _srcset) {
                if (!is_alloc(_s))
                  continue;
                for (auto u : _s->users()){
                  udpair.insert(std::make_pair(u, v));
                  worklist.push_back(u);
                  visited.insert(_s);
                }
              }
            }
            
            break;
          }        

          // normal function call
          FunctionSet funcs;
          get_call_dest(ii, funcs);
          Indices idx;
          for (int i=0; i < cast<CallInst>(v)->arg_size(); ++i)
            if (visited.count(cast<CallInst>(v)->getArgOperand(i)))
              idx.push_back(i);
          for (auto callee : funcs) {
            if (is_skip_func(callee))
              continue;
            
            for (auto i : idx) {
              if (callee->arg_size() <= i)
                continue;
              udpair.insert(std::make_pair(callee->getArg(i), v));
              worklist.push_back(callee->getArg(i));
              callset->insert(v);
            }
          }
          break;
        }
        case Instruction::Store:
          // return the stored value.
          // Find where the value is loaded from later.

          if (visited.count(ii->getOperand(1)))
            result->insert(std::make_pair(v, new ValueList(uselist)));
          break;
          
        case Instruction::Alloca:
        case Instruction::BitCast:
        case Instruction::PtrToInt:
        case Instruction::IntToPtr:
        case Instruction::GetElementPtr:
        case Instruction::PHI:
          track = true;
          break;
        
        case Instruction::Load:
          if (v == dst)
            track = true;
          break;
        default:
          break;
      }
    }

    if (track) {
      for (auto u : v->users())
        worklist.push_back(u);
    }
  }
}


// Read flow in Pseudo Filesystems
void pta::ubuf_from_pobj(pfunc *pf, Function *read, Value *ubuf) {
  Value *data = pf->helper;
  Value *sysctl_data = nullptr;
  Function *proc_open = nullptr;
  ValueSet callset;

  if (data) {
    if (!isa<Function>(data)) {
      sysctl_data = data;
    } else {
      proc_open = cast<Function>(data);
    }
  }
  if (sysctl_data) {
    pf->gpobj->insert(sysctl_data);
    if (auto sty = get_pstr_type(m, sysctl_data->getType())) {
      if (sty->hasName())
        pf->pobj->insert(sty);
      else {
        if (sty = find_gv_cast(sysctl_data))
          pf->pobj->insert(sty);
      }
    }
  }
  if (is_proc_parse_func(read->getName())) {
    return;
  }

  pf->sysctl_data = sysctl_data;

  std::set<std::pair<Value*, ValueList*>> srcset, sptrset;
  forward_store_src(ubuf, &srcset, &callset);

  if (!srcset.size()) {
    errs() << "no store src\n";
    return;
  }

  for (auto p : srcset) {
    auto s = p.first;
    auto ulist = p.second;
    print_debug(s, "store");
    if (auto si = dyn_cast<StoreInst>(s)) {
      // find where the stored value is loaded from.
      ValueSet visited, _srcset, ldset;
      backward_find_sty(si->getOperand(0), &visited, &_srcset,
                        &ldset, ulist, &callset, true /*isVal*/);
      for (auto ld : ldset)
        if (isa<LoadInst>(ld)) {
          sptrset.insert(std::make_pair(cast<Instruction>(ld)->getOperand(0), ulist));
        }
    } else if (auto ci = dyn_cast<CallInst>(s)) {
      auto fname = get_callee_function_name(ci);
      int src_op = -1;
      if (fname.startswith("seq_printf") ||
          fname.startswith("seq_puts")) {
        ValueSet visited, _srcset, ldset;
        for (int i=2; i < ci->arg_size(); ++i) {
          backward_find_sty(ci->getArgOperand(i), &visited,
                            &_srcset, &ldset, ulist, &callset);
        }
        for (auto ld : ldset)
          if (isa<LoadInst>(ld))
            sptrset.insert(std::make_pair(cast<Instruction>(ld)->getOperand(0), ulist));
        continue;
      }
      
      if (is_copy_func(fname, false /*write*/))
        src_op = get_copy_src(ci, false);
      //else if (is_proc_parse_func(fname)) {
      //  continue;
      //}
      if (src_op < 0)
        continue;
      sptrset.insert(std::make_pair(ci->getArgOperand(src_op), ulist));
    }
  }

  for (auto p : sptrset) {
    print_debug(p.first, "sptr");
    find_ptypes(pf, p.first, p.second, &callset, false /*pcheck*/,
                false /*isptr*/);
  }

  // free the memory
  for (auto p : srcset) {
    delete p.second;
  }
}

// Write flow in Pseudo File systems
void pta::ubuf_to_pobj(pfunc *pf, Value *ubuf) {
  Value *data = pf->helper;
  ValueSet dset;
  ValueSet callset;
  ValueSet strdst;
  Value *sysctl_data = nullptr;
  Function *proc_open = nullptr;
  std::map<Value*, Indices*> _val2off;
  if (data) {
    if (!isa<Function>(data)) {
      sysctl_data = data;
    } else {
      proc_open = cast<Function>(data);
    }
  }
  if (sysctl_data) {
    pf->gpobj->insert(sysctl_data);
    if (auto sty = get_pstr_type(m, sysctl_data->getType())) {
      if (sty->hasName())
        pf->pobj->insert(sty);
      else {
        if (sty = find_gv_cast(sysctl_data))
          pf->pobj->insert(sty);
      }
    }
  }
  if (is_proc_parse_func(pf->write->getName())) {
    return;
  }

  pf->sysctl_data = sysctl_data;

  // 1. find the data loaded from ubuf
  val2off.clear();
  val2off[ubuf] = get_indices({0});
  forward_load(ubuf, &dset, &callset, false);

  for (auto dat : dset)
    if (val2off.count(dat))
      _val2off[dat] = val2off[dat];
      
  // 2. find the object affected by the data
  // store, branch
  for (auto dat : dset) {
    if (!_val2off.count(dat))
      continue;

    print_debug(dat, "dat");

    val2off.clear();
    val2off[dat] = _val2off[dat];
    strdst.clear();
    if (auto ci = dyn_cast<CallInst>(dat)) {
      auto fname = get_callee_function_name(ci);
      if (is_parse_func(fname)) {
        val2off[dat] = get_indices({});
      } else if (is_proc_parse_func(fname)) {
        if (sysctl_data)
          continue;
      } else if (is_copy_func(fname)) {
        int dst_op = get_copy_dst(cast<Instruction>(dat));
        if (dst_op<0)
          continue;
        Value *dst = cast<CallInst>(dat)->getArgOperand(dst_op);
        strdst.insert(dst);
        find_ptypes(pf, dst, nullptr, &callset, false, false);
        continue;
      } else if (is_cmp_func(fname)) {
        // collect interesting BB
        BasicBlockSet trueSet, falseSet;
        FunctionSet visited;
        collect_interesting_bb(dat, &callset, &trueSet, &falseSet, false);
        collect_store(&trueSet, &falseSet, &strdst, &callset, &visited);
        continue;
      }
    }
    forward_store(pf, dat, &strdst, &callset, sysctl_data, false);
  } // dset
  if (dset.size() == 0) {
    print_error("no dat");
  }
}

void pta::find_pchk(Function *func, ValueSet *errset, ValueSet *visited,
                    ValueSet *callset) {
  //static ValueSet cond_visited;
  if (visited->count(func))
    return;
  visited->insert(func);
  for (auto &B : *func) {
    for (auto I = B.begin(), E = B.end(); I != E; ++I) {
      auto i = &*I;
      if (isa<LoadInst>(i)) {
        if (isa<PHINode>(i->getOperand(0))) {
          i = cast<Instruction>(i->getOperand(0));
        }
        if (!pta_err.count(i->getOperand(0)))
          continue;
        errset->insert(i);
        //if (!cond_visited.count(i)) {
        //  find_cond_val(i, condset);
        //  cond_visited.insert(i);
        //}

        collect_normalBB(i, visited, callset);
      }
      else if (isa<CallInst>(&*I)) {
        if (is_builtin_container_of(&*I))
            continue;
        auto ci = dyn_cast<CallInst>(&*I);
        FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
          if (is_skip_func(callee))
              continue;
          callset->insert(&*I);
          find_pchk(callee, errset, visited, callset);
          callset->erase(&*I);
        }
      }
    }
  }
}

void pta::sarg_to_pobj(pfunc *pf, Value *sarg) {
  auto sty = get_pstr_type(m, sarg->getType());
  bool is_ioctl_arg = false;
  bool is_ptr=false;

  if (!sty) {
    if (isa<PointerType>(sarg->getType()))
      is_ptr=true;
    else {
      for (auto u : sarg->users()) {
        if (isa<CastInst>(u) && isa<PointerType>(u->getType())) {
          is_ptr=true;
          break;
        }
        //if (auto ci = dyn_cast<CallInst>(u)) {
        //  auto fname = get_callee_function_name(ci);
        //  if (fname == "do_vfs_ioctl" && ci->getArgOperand(3)==sarg) {
        //    is_ioctl_arg = true;
        //  }
        //}
      }
    }
    if (is_ptr) {
      _sarg_to_pobj(pf, sarg, get_indices({0}));
    }
    else if (is_ioctl_arg) {
      print_debug(sarg, "ioctl_arg");
      _sarg_to_pobj(pf, sarg, get_indices({}));
      _sarg_to_pobj(pf, sarg, get_indices({0}));
    }
    else {
      _sarg_to_pobj(pf, sarg, get_indices({}));
    }
  } else {
    for (int i=0; i<sty->getNumElements(); ++i) {
      std::vector<Value*> offset_vec;
      offset_vec.push_back(ConstantInt::get(Type::getInt64Ty(*ctx), 0));
      offset_vec.push_back(ConstantInt::get(Type::getInt32Ty(*ctx), i));
      int offset = DL->getIndexedOffsetInType(sty,
                                  llvm::ArrayRef<Value*>(offset_vec));
      _sarg_to_pobj(pf, sarg, get_indices({offset}));

    }
  }
}

void pta::_sarg_to_pobj(pfunc *pf, Value *sarg, Indices *idx) {
  ICmpInst *icmp = nullptr;
  BranchInst *br = nullptr;
  BasicBlockSet trueSet;
  ValueSet callset, strdst, dset;
  ValueSet visited;
  std::map<Value*, Indices*> _val2off;
  pf->sysctl_data = nullptr;

  // 1. find the data loaded from sarg
  val2off.clear();
  val2off[sarg] = idx;

  forward_load(sarg, &dset, &callset, true);
  dset.insert(sarg);
  for (auto dat : dset) {
    if (val2off.count(dat))
      _val2off[dat] = val2off[dat];
  }
  // 2. Find the object affected by the data + not on falseBB
  for (auto dat : dset) {
    ValueSet cur_callset = callset;
    if (!_val2off.count(dat))
      continue;
    bool pcheck = !checked.count(dat);
    if (pcheck)
      print_debug(dat, "dat-unck");
    else
      print_debug(dat, "dat-ck");
    //val2off.clear();
    val2off[dat] = _val2off[dat];

    if (isa<CallInst>(dat)) {
      if (is_parse_func(get_callee_function_name(cast<Instruction>(dat))))
        val2off[dat] = get_indices({});
        //val2off[dat] = get_indices({0});
    }

    if (auto ci = dyn_cast<CallInst>(dat)) {
      auto fname = get_callee_function_name(ci);
      if (is_copy_func(fname)) {
        int dst_op = get_copy_dst(cast<Instruction>(dat));
        if (dst_op<0)
          continue;
        Value *dst = cast<CallInst>(dat)->getArgOperand(dst_op);
        find_ptypes(pf, dst, nullptr, &cur_callset, pcheck, false);
        //strdst.insert(dst);
        continue;
      }
    }


    forward_store(pf, dat, &strdst, &cur_callset, nullptr, pcheck);

  } // dset
  if (strdst.size() == 0) {
    print_error("no str");
  }
}

Value *pta::get_ctl_data(Value *table) {
  Value *gep = nullptr;
  Value *store = nullptr;
  Value *data = nullptr;

  for (auto u : table->users()) {
    if (auto g = dyn_cast<GetElementPtrInst>(u)) {
      if (g->getNumOperands() == 3) {
        if (auto ci = dyn_cast<ConstantInt>(g->getOperand(2))) {
          if (ci->getZExtValue()==1) {
            gep = g;
            break;
          }
        }
      }
    }
  }

  if (!gep)
    return nullptr;
    
  while(gep) {
    for (auto u : gep->users()) {
      if (isa<StoreInst>(u)) {
        if (cast<Instruction>(u)->getOperand(1) == gep) {
          store = cast<Instruction>(u)->getOperand(0);
          break;
        }
      } else if (isa<CastInst>(u)) {
        gep = u;
        goto retry;
      }
    } 
    gep = nullptr;
    if (store)
      break;
retry:
    continue;
  }

  if (!store)
    return nullptr;

  return store;
}


// forward_store: find address that dat is stored to.
void pta::forward_store(pfunc *pf, Value *dat, ValueSet *strset, ValueSet *callset,
                        Value *data, bool pcheck) {
  Function *func = nullptr;

  if (isa<Argument>(dat))
      func = cast<Argument>(dat)->getParent();
  else if (isa<Instruction>(dat))
    func = cast<Instruction>(dat)->getFunction();

  ValueList worklist, uselist;
  std::unordered_set<size_t> visited;
  std::set<std::pair<Value*,Value*>> udpair, retpair;
  std::set<size_t> _visited;

  if (isa<CallInst>(dat)) {
    if (is_proc_parse_func(get_callee_function_name(cast<Instruction>(dat)))) {
      auto ctl_dat = get_ctl_data(cast<CallInst>(dat)->getArgOperand(0));
      
      if (!ctl_dat) return;

      if (isa<AllocaInst>(ctl_dat)) {
        val2off[ctl_dat] = get_indices({0});
        dat = ctl_dat;
      } else {
        ValueSet srcset;
        uselist.push_back(ctl_dat);
        find_ptypes(pf, ctl_dat, &uselist, callset, pcheck, false);
        val2off[ctl_dat] = get_indices({0});
        backward(ctl_dat, &_visited, &srcset, callset, &uselist);

        for (auto _s : srcset) {
          if (!is_alloc(_s)) 
            continue;
          if (DEBUG) {
            print_debug(_s, "store dst");
            if (val2off.count(_s)) {
              auto idx = val2off[_s];
              dump_indices(errs(), *idx);
            }
          }
          dat = _s;
          break;
        }
      }
    }
  }
  bool is_ptr = val2off[dat]->size() > 0 ? 1 : 0;
  int size = dat->getType()->isPointerTy() ? 64 : dat->getType()->getPrimitiveSizeInBits();
  llvm::hash_code hash = hash_value(std::make_pair(dat, val2off[dat]));
  hash = hash_value(std::make_pair(hash, dat));

  argset_st.insert(hash);

  for (auto u : dat->users()) {
    ValueSet cur_callset = *callset;

    udpair.clear();
    uselist.clear();
    uselist.push_back(dat);
    worklist.push_back(u);

  while (worklist.size()) {
    Value *vv = worklist.back();
    Value *prev = nullptr;
    bool is_udpair = false;

    worklist.pop_back();
    Instruction *ii=nullptr;

    if (isa<Instruction>(vv)) {
      ii = cast<Instruction>(vv);
    }
    else if (isa<ConstantExpr>(vv)) {
      ii = cast<ConstantExpr>(vv)->getAsInstruction();
    } else if (isa<Argument>(vv)) {
      ;
    } else
      continue;

    while(uselist.size()) {
      prev = uselist.back();
      auto pprev = *(--uselist.end());
      if (udpair.count(std::make_pair(vv, prev))) {
        is_udpair=true;
        break;
      }
      if (isa<User>(vv)) {
        if (is_use_def(cast<User>(vv), prev)) {
          if (isa<CallInst>(prev)) {
            auto fname = get_callee_function_name(cast<Instruction>(prev));
            if (!is_parse_func(fname) && !is_builtin_container_of(prev) &&
                !is_copy_func(fname) && !is_asm_user(prev) && !is_alloc(prev)) {
              uselist.pop_back();
              if (udpair.count(std::make_pair(prev, pprev)))
                udpair.erase(std::make_pair(prev, pprev));
              continue;
            }
          }
          break;
        }
      }
      if (isa<Argument>(prev)) {
        Value *caller = nullptr;
        if (uselist.front() != prev) {
          caller = *(++uselist.rbegin());
        }
      }
      if (udpair.count(std::make_pair(prev, pprev)))
        udpair.erase(std::make_pair(prev, pprev));
      uselist.pop_back();
    }

    if (std::find(uselist.begin(), uselist.end(), vv) != uselist.end()) {
      continue;
    }

    if (is_skip_type(vv->getType())) {
      continue;
    }
    if (auto ii = dyn_cast<Instruction>(vv)) {
      if (ii->getFunction()->getName().contains("ioctl")) {
        // check the switch case context for ioctl
        if (invalid_switch_context(ii, &uselist)) {
          if (DEBUG)
            print_debug(ii, "invalid switch!");
          continue;
        }
      }  
    }

    // ignore value -> struct pointer type casts
    if (val2off.count(prev)) {
      if (val2off[prev]->size()==0 &&
          !isa<StoreInst>(prev) && !is_asm_store(prev)) {
        if (auto sty = get_pstr_type(m, vv->getType())) {
          continue;
        }
        if (auto sty = get_pstr_type(m, prev->getType()))
          continue;
      }
    }
    if (is_alloc(vv) && !is_udpair) {
      if (DEBUG) {
        print_debug(vv, "skip this alloc");
        for (auto u : uselist){
            print_debug(u, "uselist");
        }
      }
      continue;
    }

    // Copy offset from prev
    uselist.push_back(vv);

    Indices *idx_old=nullptr;
    if (val2off.count(vv))
      idx_old = val2off[vv];

    if (is_alloc(vv) || is_udpair) {
      if (!isa<StoreInst>(prev) && !is_asm_store(prev)) {
        copy_offset_safe(vv, prev, 0);
      }
    } else {
      copy_offset(vv, prev, 0);
    }
    ValueSet useset;
    for (auto u : uselist) {
        useset.insert(u);
    }
    llvm::hash_code hash = hash_combine_range(useset.begin(), useset.end());
    if (visited.count(size_t(hash))) {
      uselist.pop_back();
      continue;
    } else
      visited.insert(size_t(hash));


    bool track = false;
    if (isa<Argument>(vv)) {
      Value *caller = vv;
      if (uselist.front() != vv)
        caller = prev;
      llvm::hash_code hash = hash_value(std::make_pair(vv, val2off[vv]));
      hash = hash_value(std::make_pair(hash, caller));
      if (argset_st.count(hash)) {
        uselist.pop_back();
        continue;
      }

      argset_st.insert(hash);
      
      if (val2off[vv]->size() == 0) {
        priv_vals.insert(vv);
      }

      for (auto u : vv->users()) {
        //copy_offset(u, vv, 0);
        worklist.push_back(u);
        track |= true;
      }
      if (DEBUG) {
        //if (DEBUG_USELIST)
        //  for (auto u : uselist){
        //    print_debug(u, "uselist");
        //  }
        print_debug(vv, "forward_store");
        if (val2off.count(vv)) {
          auto idx = val2off[vv];
          dump_indices(errs(), *idx);
        }
      }
      if (!track)
        uselist.pop_back();
      continue;
    }
    if (is_alloc(ii)) {
      for (auto u : ii->users()) {
          worklist.push_back(u);
          track |= true;
      }
    } else {
    switch(ii->getOpcode()) {
    case Instruction::Load: {
      auto idx = val2off[vv];
      // nothing to load or mismatching offset
      if (idx->size() == 0 || !can_load(idx, &uselist)) {
        if (!idx_old)
          val2off.erase(vv);
        else {
          val2off[vv] = idx_old;
        }
        break;
      }

      pop_idx(vv);
      
      if (val2off[vv]->size() == 0) {
        priv_vals.insert(vv);
      }

      for (auto u : vv->users()) {
        if (auto ui = dyn_cast<Instruction>(u)) {
          //val2off[u] = get_indices(_idx);
          worklist.push_back(u);
          track |= true;
        }
      }
      break;
      }
    case Instruction::Store:
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        Indices *idx = val2off[vv];
        ValueSet _srcset;
        // store dat/ptr at a kobj.
        // backward find the ptr store destination and track them forward.
        // store holds the destination offset
 
        // store dat at a kobj.
        bool can_store_ptr = false;
        if (is_ptr && idx->size()==1 && idx->back() == 0) {
          if (func->getName().startswith("__arm64_"))
            can_store_ptr = true;
        }
        
        find_ptypes(pf, ii->getOperand(1), &uselist, &cur_callset, pcheck, idx->size()>0);

        // log heap object store
        if (auto obj = get_object(&uselist)) {
          auto strdst = obj2strdst[obj];
          if (!strdst) {
            strdst = new ValueSet;
            obj2strdst[obj] = strdst;
          }
          strdst->insert(ii->getOperand(1));
        }

        if (!is_list_struct(ii->getOperand(0)->getType()))
          push_idx_safe(ii->getOperand(1), vv, 0);
        else
          copy_offset_safe(ii->getOperand(1), vv);

        backward(ii->getOperand(1), &_visited, &_srcset, &cur_callset, &uselist);

        for (auto _s : _srcset) {
          // sysctl defined data
          if (data && (isa<Argument>(_s))) {
            if (cast<Argument>(_s)->getParent() == func) {
              find_ptypes(pf, data, &uselist, &cur_callset, pcheck, false);
            }
          }
          if (!is_alloc(_s)) 
            continue;
          if (DEBUG) {
            print_debug(_s, "store dst");
            if (val2off.count(_s)) {
              auto idx = val2off[_s];
              dump_indices(errs(), *idx);
            }
          }
          udpair.insert(std::make_pair(_s, vv));
          worklist.push_back(_s);
          track |= true;
        }
      }
      break;
    case Instruction::Call:
      if (is_address_space_op(ii))
        break;
      if (is_asm(ii)) {
        if (is_asm_user(ii)) {
          for (auto u : vv->users()) {
            //copy_offset(u, vv, 0);
            worklist.push_back(u);
            track |= true;
          }
        } else if (is_asm_store(ii)) {
          int vop = get_asm_stval(ii);
          int aop = get_asm_addr(ii);
          if (vop < 0 || aop < 0)
            break;
          if (prev == ii->getOperand(vop) || retpair.count(std::make_pair(ii->getOperand(vop), prev))) {
            Indices *idx = val2off[vv];
            // store dat/ptr at a kobj.
            // backward find the ptr store destination and track them forward.
            // store holds the destination offset
            ValueSet _srcset;

            // store dat at a kobj.
            bool can_store_ptr = false;
            if (is_ptr && idx->size()==1 && idx->back() == 0) {
              if (func->getName().startswith("__arm64_"))
                can_store_ptr = true;
            }
            //if (idx->size() == 0 || can_store_ptr) {
              find_ptypes(pf, ii->getOperand(aop), &uselist,
                          &cur_callset, pcheck, idx->size()>0);
            //}

            // log heap object store
            if (auto obj = get_object(&uselist)) {
              auto strdst = obj2strdst[obj];
              if (!strdst) {
                strdst = new ValueSet;
                obj2strdst[obj] = strdst;
              }
              strdst->insert(ii->getOperand(aop));
            }

            if (!is_list_struct(ii->getOperand(vop)->getType()))
              push_idx_safe(ii->getOperand(aop), vv, 0);
            else
              copy_offset_safe(ii->getOperand(aop), vv);

            backward(ii->getOperand(aop), &_visited, &_srcset, &cur_callset, &uselist);

            for (auto _s : _srcset) {
              if (!is_alloc(_s))
                continue;
              if (DEBUG) {
                print_debug(_s, "store dst");
                if (val2off.count(_s)) {
                  auto idx = val2off[_s];
                  dump_indices(errs(), *idx);
                }
              }
              udpair.insert(std::make_pair(_s, vv));
              worklist.push_back(_s);
              track |= true;
            }
          }
        }
        break;
      } // is_asm
      else if (is_builtin_container_of(ii)) {
        int op = 0;
        if (get_callee_function_name(ii) == "make_kuid")
          op = 1;
        auto argv = cast<CallInst>(ii)->getArgOperand(op);
          if (argv != prev && !retpair.count(std::make_pair(argv, prev)))
            break;
        for (auto u : vv->users()) {
          //if (isa<ConstantInt>(ii->getOperand(1)))
          //  copy_offset(u, vv, cast<ConstantInt>(ii->getOperand(1))->getZExtValue());
          //else
          //  copy_offset(u, vv, 0);

          if (!is_udpair &&
              get_callee_function_name(ii) == "__builtin_container_of" &&
              isa<ConstantInt>(ii->getOperand(1)))
            copy_offset(vv, vv, cast<ConstantInt>(ii->getOperand(1))->getZExtValue());

          worklist.push_back(u);
          track |= true;
        }
      }  else if (is_parse_func(get_callee_function_name(ii))) {
        auto idx = val2off[vv];
        if (idx->size() != 1) {
          if (!idx_old)
            val2off.erase(vv);
          else {
            val2off[vv] = idx_old;
          }
          break;
        }

        pop_idx(vv);

        for (auto u : vv->users()) {
          //copy_offset(u, vv, 0);
          worklist.push_back(u);
          track |= true;
        }
      } else if (is_copy_func(get_callee_function_name(ii))) {
        Indices *idx = val2off[vv];
        // user can pass a user pointer
        //if (idx->size() == 0)
        //  break;
        int src_op = get_copy_src(ii);
        int dst_op = get_copy_dst(ii);
        int narg = cast<CallInst>(ii)->arg_size();
        if (src_op < 0 || dst_op < 0 || narg <= src_op || narg <= dst_op)
          break;
        Value *src = cast<CallInst>(ii)->getArgOperand(src_op);
        Value *dst = cast<CallInst>(ii)->getArgOperand(dst_op);
        if (prev != src && !retpair.count(std::make_pair(src, prev)))
            break;
        if (!can_load(idx, &uselist))
          break;
        // FIXME: idx->size()==1?
        if (idx->size() <= 1) {
          if (!is_from_alloca(dst, &cur_callset, &uselist)) {
            find_ptypes(pf, dst, &uselist, &cur_callset, pcheck, false);
          }
        }
        ValueSet _srcset;
        std::set<size_t> _visited;
        track |= true;
        udpair.insert(std::make_pair(dst, src));
        copy_offset(dst, src, 0);
        backward(dst, &_visited, &_srcset, &cur_callset, &uselist);
        for (auto _s : _srcset) {
          if (data && isa<Argument>(_s)) {
            if (cast<Argument>(_s)->getParent() == func) {
              find_ptypes(pf, data, &uselist, &cur_callset, pcheck, false);
            }
          }
          if (!is_alloc(_s))
              continue;
          
          if (DEBUG) {
            print_debug(_s, "memcpy ubuf");
          }
          udpair.insert(std::make_pair(_s, vv));
          worklist.push_back(_s);
          track |= true;
          //uselist.push_back(_s);
          //udpair.insert(std::make_pair(_s, vv));
          //for (auto _u : _s->users()) {
          //  //copy_offset(_u, _s, 0);
          //  worklist.push_back(_u);
          //  track |= true;
          //}
        }
        break;
      } else {
        if (!idx_old)
          val2off.erase(vv);
        else {
          val2off[vv] = idx_old;
        }

        FunctionSet funcs;
        get_call_dest(ii, funcs);
        for (auto callee : funcs) {
         if (is_skip_func(callee))
           continue;
         if (callee->isVarArg())
           continue;
         for (unsigned i=0; i<cast<CallInst>(ii)->arg_size(); ++i) {
           if (i == callee->arg_size())
             break;
           Value *argv = cast<CallInst>(ii)->getArgOperand(i);
           if (prev == argv || retpair.count(std::make_pair(argv, prev))) {
             Argument *arg = callee->getArg(i);
             worklist.push_back(arg);
             track |= true;
             //udpair.insert(std::make_pair(arg, vv));
             udpair.insert(std::make_pair(arg, prev));
             cur_callset.insert(vv);
           }
         }
       }
     }
     break;
    case Instruction::Ret: {
      if (ii->getFunction()==func)
        break;
      for (auto c : cur_callset) {
        auto ci = dyn_cast<CallInst>(c);
        if (!ci)
          continue;
        FunctionSet funcs;
        get_call_dest(ci, funcs);
        for (auto callee : funcs) {
         if (is_skip_func(callee))
           continue;
         if (callee->isVarArg())
           continue;
         if (callee == ii->getFunction()) {
           for (auto u : ci->users()) {
             if (isa<Instruction>(u)) {
               if (val2off[vv]->size() == 0) {
                 priv_vals.insert(u);
               }
               worklist.push_back(u);
               udpair.insert(std::make_pair(u, vv));
               copy_offset_check(u, vv, 0);
               retpair.insert(std::make_pair(c, vv));
               track |= true;
             }
           }
         }
        }
      }
      break;
    }

    case Instruction::GetElementPtr:
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        int offset = gep2offset(ii);
        if (offset>0 && !is_udpair)
          copy_offset(vv, vv, (-1)*offset);
        else if (offset < 0){
          break;
        }

        for (auto u : vv->users()) {
          worklist.push_back(u);
          track |= true;
        }
      }
      break;
    case Instruction::ICmp: {
      //if (pcheck && !pcheck_passed(nullptr, &uselist))
      //  continue;
      //BasicBlockSet *trueSet = new BasicBlockSet;
      //BasicBlockSet *falseSet = new BasicBlockSet;
      //FunctionSet visited_funcs;
      //ValueSet icmp_strset;
      //collect_interesting_bb(vv, callset, trueSet, falseSet, false);
      //collect_store(trueSet, falseSet, _strset, callset, &visited_funcs);
      break;
    }
    case Instruction::Add:
    case Instruction::Sub:
      if (prev == ii->getOperand(0) ||
          retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        for (auto u : vv->users()) {
          if (auto ui = dyn_cast<Instruction>(u)) {
            //copy_offset(ui, vv, 0);
            worklist.push_back(ui);
            track |= true;
          }
        }
      }
      break;
    case Instruction::Select:
      if (prev != ii->getOperand(0) &&
          !retpair.count(std::make_pair(ii->getOperand(0), prev))) {
        for (auto u : vv->users()) {
          if (auto ui = dyn_cast<Instruction>(u)) {
            worklist.push_back(u);
            track |= true;
          }
        }
      }
      break;

    case Instruction::Trunc:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
      if (val2off[vv]->size() > 0)
        break;

    case Instruction::BitCast:
      if (_is_err_ptr(ii))
        break;

    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::Mul:
    case Instruction::UDiv:
    case Instruction::SDiv:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
    case Instruction::PHI:
      for (auto u : vv->users()) {
        if (auto ui = dyn_cast<Instruction>(u)) {
          //copy_offset(ui, vv, 0);
          worklist.push_back(ui);
          track |= true;
        }
      }
      break;


    // ignore
    //case Instruction::ICmp:
    default:
      break;

    } // switch (ii->getOpcode())
    } // else 

    if (DEBUG) {
      //if (DEBUG_USELIST)
      //  for (auto u : uselist) {
      //    print_debug(u, "uselist");
      //  }
      print_debug(vv, "forward_store");
      if (val2off.count(vv)) {
        auto idx = val2off[vv];
        dump_indices(errs(), *idx);
      }
    }
    if (!track) {
      uselist.pop_back();
      continue;
    }

  } // while (worklist)
  } // for (ubuf->users())

  return;
}

void pta::collect_pid_entry(GlobalVariable *table, StringRef path)
{
    Constant *base = table->getInitializer();
    unsigned num = 0;
    SmallString<256> tmp;

    if (isa<StructType>(base->getType()))
        num = base->getType()->getStructNumElements();
    if (isa<ArrayType>(base->getType()))
        num = base->getType()->getArrayNumElements();
    for (unsigned i=0; i<num; ++i) {
        Constant *entry = base->getAggregateElement(i);
        unsigned idx = 0;
        if (!entry)
            continue;

        Constant *namec = entry->getAggregateElement(idx++);
        StringRef name;
        get_string(namec, &name);
        idx++; // len
        int mode = cast<ConstantInt>(entry->getAggregateElement(idx++))->getZExtValue();
        auto iop = entry->getAggregateElement(idx++)->stripPointerCasts();
        auto fop = entry->getAggregateElement(idx++)->stripPointerCasts();
        auto op = entry->getAggregateElement(idx++)->stripPointerCasts();
        bool is_read_protected = ((mode & S_IRUSR) && !(mode & S_IROTH));
        bool is_write_protected = ((mode & S_IWUSR) && !(mode & S_IWOTH));

        if (is_read_protected || is_write_protected) {
            //errs() << "name: " << name << "\n";
            //errs() << "mode: " << format("%o", mode) << "\n";
            //errs() << "iop : " << (iop->isZeroValue() ? "NULL" : iop->getName()) << "\n";
            //errs() << "fop : " << (fop->isZeroValue() ? "NULL" : fop->getName()) << "\n";
            //errs() << "op  : " << (op->isZeroValue() ? "NULL" : op->getName()) << "\n";
            if (fop) {
              bool show = fop->getName() == "proc_single_file_operations";
              if (isa<GlobalVariable>(fop))
                fop = cast<GlobalVariable>(fop)->getInitializer();
              auto read = is_read_protected ?
                show ? op->getAggregateElement(unsigned(0))->stripPointerCasts()
                : fop->getAggregateElement(unsigned(2))->stripPointerCasts()
                : nullptr;
              auto write = is_write_protected ?
                fop->getAggregateElement(unsigned(3))->stripPointerCasts()
                : nullptr;
              auto open = fop->getAggregateElement(unsigned(14))->stripPointerCasts();
              if (write) {
                write = write->stripPointerCasts();
                if (!isa<Function>(write))
                  write = nullptr;
              }
              if (read) {
                read = read->stripPointerCasts();
                if (!isa<Function>(read))
                  read = nullptr;
              }
              if (!write && !read)
                continue;

              auto pf = new pfunc;
              auto str = new std::string((path+"/"+name).str());
              pf->name = *str;
              pf->type = PROC;
              pf->mode = mode;
              pf->write = write ? cast<Function>(write) : nullptr;
              pf->read = (read && !show) ? cast<Function>(read) : nullptr;
              pf->show = (read && show) ? cast<Function>(read) : nullptr;
              pf->helper = open;
              pf->pptr = new TypeSet;
              pf->pobj = new TypeSet;
              pf->gpptr = new ValueSet;
              pf->gpobj = new ValueSet;
              pf->pobj2inst = new Type2ChkInst;
              pf->gpobj2inst = new Value2ChkInst;
              pf->palloca = new InstructionSet;
              proc_funcs.insert(pf);
            }
        }
    }
}

void pta::collect_sysctl_entry(GlobalVariable *table, StringRef path)
{
    Constant *base = table->getInitializer();
    unsigned num = 0;
    SmallString<256> tmp;
    errs() << "collect sysctl - " << table->getName() << " - " << path << "\n";
    if (isa<StructType>(base->getType()))
        num = base->getType()->getStructNumElements();
    if (isa<ArrayType>(base->getType()))
        num = base->getType()->getArrayNumElements();
    for (unsigned i=0; i<num; ++i) {
        Constant *entry = base->getAggregateElement(i);
        unsigned idx = 3;
        if (!entry)
            continue;
        int mode = cast<ConstantInt>(entry->getAggregateElement(unsigned(3)))->getZExtValue();
        auto namec = entry->getAggregateElement(unsigned(0));
        StringRef name;
        get_string(namec, &name);
        // dir
        if (mode == 0555) {
            auto child = entry->getAggregateElement(unsigned(4))->stripPointerCasts();
            if (auto ce = dyn_cast<ConstantExpr>(child)) {
                if (ce->getOpcode() == Instruction::GetElementPtr)
                    child = ce->getOperand(0)->stripPointerCasts();
            }

            if (isa<GlobalVariable>(child)) {
                auto child_path = new std::string((path+"/"+name).str());
                collect_sysctl_entry(cast<GlobalVariable>(child),
                                     *child_path);
            }
            continue;
        }

        bool is_read_protected = ((mode & S_IRUSR) && !(mode & S_IROTH));
        bool is_write_protected = ((mode & S_IWUSR) && !(mode & S_IWOTH));
        if (is_read_protected || is_write_protected) {
            auto handler = entry->getAggregateElement(unsigned(5))->stripPointerCasts();
            auto data = entry->getAggregateElement(unsigned(1))->stripPointerCasts();

            if (handler && isa<Function>(handler)) {
                auto pf = new pfunc;
                auto str = new std::string((path+"/"+name).str());
                pf->name = *str;
                pf->type = SYSFS;
                pf->mode = mode;
                pf->read = is_read_protected ? cast<Function>(handler) : nullptr;
                pf->write = is_write_protected ? cast<Function>(handler) : nullptr;
                pf->show = nullptr;
                pf->helper = nullptr;
                pf->pptr = new TypeSet;
                pf->pobj = new TypeSet;
                pf->gpptr = new ValueSet;
                pf->gpobj = new ValueSet;
                pf->pobj2inst = new Type2ChkInst;
                pf->gpobj2inst = new Value2ChkInst;
                pf->palloca = new InstructionSet;
                if (data->hasName())
                    pf->helper = data;
                else if (auto ce = dyn_cast<ConstantExpr>(data)) {
                  if (ce->getOpcode() == Instruction::GetElementPtr) {
                      if (ce->getOperand(0)->stripPointerCasts()->hasName())
                          pf->helper = ce->getOperand(0)->stripPointerCasts();
                  }
                }
                //else { // dynamic initialization
                //    pf->helper = find_sysctl_data(cast<Function>(handler));
                //}
                sysfs_funcs.insert(pf);
            }
        }
    }
}
bool pta::collect_interface_handlers()
{
    // 1. /proc: `tid_base_stuff`
    // 2. /proc/sys/: `kern_table`, `vm_table`, `fs_table`, `dbg_table`
    // 3. syscall: __arm64_sys_xxx


    // proc
    GlobalVariable *tid_base_stuff
        = dyn_cast<GlobalVariable>(m->getNamedValue("tid_base_stuff"));
    GlobalVariable *tgid_base_stuff
        = dyn_cast<GlobalVariable>(m->getNamedValue("tgid_base_stuff"));
    if (!tid_base_stuff) {
        print_error("No tid_base_stuff!\n");
        return false;
    }

    collect_pid_entry(tid_base_stuff, "/proc/self");
    collect_pid_entry(tgid_base_stuff, "/proc/self");

    // sysfs
    GlobalVariable *sysctl_base_table = nullptr;
    if (auto gv = m->getNamedValue("sysctl_base_table"))
      sysctl_base_table = dyn_cast<GlobalVariable>(gv);
    if (!sysctl_base_table) {
      print_error("No sysctl base table!\n");
      return false;
    }
    collect_sysctl_entry(sysctl_base_table, "/proc/sys");

    auto net_sysctl_func = m->getFunction("register_net_sysctl");
    ValueSet callset;
    if (net_sysctl_func) {
      for (auto u : net_sysctl_func->users()) {
        if (isa<CallInst>(u))
          callset.insert(u);
        if (isa<ConstantExpr>(u)) {
          for (auto uu : u->users()) {
            if (isa<CallInst>(uu))
              callset.insert(uu);
          }
        }
      }
      for (auto u : callset) {

        auto ci = cast<CallInst>(u);
        auto tbl = ci->getArgOperand(2)->stripPointerCasts();
        if (auto phi = dyn_cast<PHINode>(tbl)) {
          for (int i=0; i < phi->getNumIncomingValues(); ++i) {
            auto v = phi->getIncomingValue(i)->stripPointerCasts();
            if (auto ce = dyn_cast<ConstantExpr>(v)) {
              tbl = ce->getOperand(0);
              break;
            } else if (isa<GlobalVariable>(v)) {
              tbl = v;
            } else if (auto ci = dyn_cast<CallInst>(v)) {
              auto func = get_callee_function_direct(ci);
              if (func->getName() == "kmemdup") {
                tbl = ci->getArgOperand(0);
              }
            }
          }
        }
        if (isa<ConstantExpr>(tbl))
          tbl = cast<ConstantExpr>(tbl)->getOperand(0);
        if (isa<GlobalVariable>(tbl)) {
          auto path = ci->getArgOperand(1);
          StringRef name="";
          StringRef dir = "/proc/sys/";
          get_string(path, &name);
          collect_sysctl_entry(cast<GlobalVariable>(tbl), *new std::string((dir+name).str()));
        }
      }
    }

    // syscall
    for (Module::iterator fi = m->begin(), fe = m->end();
            fi != fe; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        if (!func)
            continue;
        if (is_skip_func(func))
            continue;

        auto fname = get_func_name(func->getName());

        if (fname.startswith("__arm64") && !fname.contains("compat")) {
            auto pf = new pfunc;
            pf->name = fname;
            pf->type = SYSCALL;
            pf->write = func;
            pf->pptr = new TypeSet;
            pf->pobj = new TypeSet;
            pf->gpptr = new ValueSet;
            pf->gpobj = new ValueSet;
            pf->pobj2inst = new Type2ChkInst;
            pf->gpobj2inst = new Value2ChkInst;
            pf->palloca = new InstructionSet;
            syscall_funcs.insert(pf);
        }
    }
    return true;
}
void pta::clear_caches(int level) {
  if (level>0) {
    for (auto p : arg2dset) {
      delete p.second;
    }
    arg2dset.clear();
    for(auto p : arg2sset) {
      delete p.second;
    }
    arg2sset.clear();

    for (auto p : obj2strdst) {
      delete p.second;
    }
  }
  obj2strdst.clear();
  from_alloca.clear();
  normalBB.clear();
  for (auto m : normalBB2Inst) {
    if (m.second)
      delete m.second;
  }
  normalBB2Inst.clear();
  normalBB2Inst.clear();
  unchecked.clear();
  checked.clear();
  argset_ld.clear();
  argset_st.clear();
}


void pta::dump_pf(pfunc *pf) {
  if (pf->pobj->size()) {
    errs() << "pobj\n";
    for (auto obj : *pf->pobj) {
      errs() << obj->getStructName() << "\n";
      if (!pf->pobj2inst->count(obj))
        continue;
      auto iset = (*pf->pobj2inst)[obj];
      for (auto i : *iset) {
        if (i->isCast())
          continue;
        if (i->getParent())
          errs() << " > " << i->getFunction()->getName() << ": " << *i << "\n";
        else
          errs() << " > " << "nofunc" << ": " << *i << "\n";
      }
    }
  } else {
    errs() << "no pobj\n";
  }
  if (pf->gpobj->size()) {
    errs() << "gpobj\n";
    for (auto obj : *pf->gpobj) {
      if (obj->getName()=="")
        errs() << *obj << "\n";
      else
        errs() << obj->getName() << "\n";

      if (!pf->gpobj2inst->count(obj))
        continue;
      auto iset = (*pf->gpobj2inst)[obj];
      for (auto i : *iset) {
        if (i->isCast())
          continue;
        if (i->getParent())
          errs() << " > " << i->getFunction()->getName() << ": " << *i << "\n";
        else
          errs() << " > " << "nofunc" << ": " << *i << "\n";
      }

    }
  } else {
    errs() << "no gpobj\n";
  }

  if (pf->pptr->size()) {
    errs() << "pptr\n";
    for (auto ptr : *pf->pptr)
      errs() << ptr->getStructName() << "\n";
  } else {
    errs() << "no pptr\n";
  }
  if (pf->gpptr->size()) {
    errs() << "gpptr\n";
    for (auto ptr : *pf->gpptr)
      errs() << ptr->getName() << "\n";
  } else {
    errs() << "no gpptr\n";
  }
  if (pf->palloca->size()) {
    errs() << "palloca\n";
    for (auto alloca : *pf->palloca)
      print_debug(alloca);
  }

}

void pta::add_idx(Sty2Idxes &pobj2idx, StructType *o, InstructionSet *iset)
{

  for (auto i : *iset) {
    if (isa<GetElementPtrInst>(i)) {
      Indices _idx;
      if (i->getNumOperands() < 3)
        continue;
      for (int op=2; op < i->getNumOperands(); ++op) {
        if (auto c = dyn_cast<ConstantInt>(i->getOperand(op))) {
          _idx.push_back(c->getZExtValue());
        } else {
          _idx.push_back(-1);
        }
      }
      auto idx = get_indices(_idx);
      auto idxset = pobj2idx[o];
      if (!idxset) {
        idxset = new IdxSet;
        pobj2idx[o] = idxset;
      }
      idxset->insert(idx);
    }
  }
}

void pta::collect_privilege_checks()
{
  errs() << "proc   : " << proc_funcs.size() << "\n";
  errs() << "sysfs  : " << sysfs_funcs.size() << "\n";
  errs() << "syscall: " << syscall_funcs.size() << "\n";

  if (!std::getenv("SKIP_PSEUDOFS")&&!std::getenv("SYSCALL_TEST")) {
  print_debug("proc funcs");
  for (auto pf : proc_funcs) {
    errs() << "name    : " << pf->name <<  "\n";
    errs() << "mode    : " << format("%o", pf->mode) <<  "\n";
    if (pf->read)
      errs() << "read    : " << pf->read->getName() << "\n";
    if (pf->write)
      errs() << "write   : " << pf->write->getName() << "\n";
    errs() << "\n";

    if (pf->read) {
      Value *ubuf = pf->read->getArg(1);
      ubuf_from_pobj(pf, pf->read, ubuf);
    } else if (pf->show) {
       Value *ubuf = pf->show->getArg(0);
       ubuf_from_pobj(pf, pf->show, ubuf);      
    }

    if (pf->write) {
      Value *ubuf = pf->write->getArg(1);
      ubuf_to_pobj(pf, ubuf);
    }
    dump_pf(pf);
    clear_caches(1);
  }

  print_debug("sysfs funcs");
  for (auto pf : sysfs_funcs) {
    errs() << "name    : " << pf->name <<  "\n";
    errs() << "mode    : " << format("%o", pf->mode) <<  "\n";
    errs() << "handler : " << pf->write->getName() << "\n";
    if (pf->helper)
      errs() << "data    : " << pf->helper->getName() << "\n";
    errs() << "\n";
    // track the 3rd argument (%2) of the write handler.

    if (pf->read) {
      Value *ubuf = pf->read->getArg(2);
      ubuf_from_pobj(pf, pf->read, ubuf);
    }
    if (pf->write) {
      Value *ubuf = pf->write->getArg(2);
      ubuf_to_pobj(pf, ubuf);
    }
    dump_pf(pf);
    clear_caches(1);
  }
  }

  if (!std::getenv("SKIP_SYSCALL")) {
  print_debug("syscall funcs");
  for (auto pf : syscall_funcs) {
    if (auto sfunc = std::getenv("SYSCALL_TEST"))
      if (pf->write->getName() != sfunc)
        continue;
    if (auto sfunc = std::getenv("SYSCALL_SKIP"))
      if (pf->write->getName() == sfunc)
        continue;
      errs() << "name    : " << pf->name <<  "\n";
      errs() << "handler : " << pf->write->getName() << "\n";
      errs() << "\n";
      ValueSet visited;
      ValueSet callset;
      ValueSet args;
      ValueSet errset;
      find_pchk(pf->write, &errset, &callset, &visited);
      callset.clear();
      pchk_cond.clear();
      if (errset.size() == 0) {
        errs() << "no chk\n";
        continue;
      }
      find_syscall_args(pf->write, &args);
      if (args.size()==0)
        errs() << "no args\n";
      for (auto arg : args) {
        print_debug(arg, "syscall arg read");
        sarg_from_pobj(pf, arg);
      }
      sret_from_pobj(pf);
      for (auto arg : args) {
        print_debug(arg, "syscall arg write");
        arg_cnt++;
        sarg_to_pobj(pf, arg);
      }

      for (auto cond : pchk_cond) {
        ValueSet objset, gobjset, ptrset;

        if (isa<PointerType>(cond->getType()))
          continue;
        if (isa<CmpInst>(cond)) {
          auto v = cast<CmpInst>(cond)->getOperand(0);
          if (isa<PointerType>(v->getType()))
            continue;
          v = v->stripPointerCasts();
          if (isa<PointerType>(v->getType()))
            continue;
        }

        find_pchk_obj(cond, &objset, &gobjset, &ptrset);

        if (objset.size() == 0 && gobjset.size() == 0)
          continue;
        print_debug(cond, "pchk_cond");
        for (auto obj : objset) {
          auto sty = get_pstr_type(m, cast<User>(obj)->getOperand(0)->getType());
          if (!sty)
            continue;
          if (!is_object_type(sty))
            continue;
          if (is_list_struct(sty))
            continue;
          print_debug(obj, "pchk_obj");
          pchk_type.insert(sty);
        }

        for (auto gobj : gobjset) {
          print_debug(gobj, "pchk_gobj");
          pchk_gobj.insert(gobj);
        }
        for (auto ptr : ptrset) {
          if (isa<GlobalVariable>(ptr)) {
            pchk_gptr.insert(ptr);
          } else {
            auto sty = get_pstr_type(m, cast<User>(ptr)->getOperand(0)->getType());
            if (!sty)
              continue;
            if (!is_object_type(sty))
              continue;
            if (is_list_struct(sty))
              continue;
            pchk_ptr_type.insert(sty);
          }
        }
      }

      dump_pf(pf);
      clear_caches(1);
  }
  }

  TypeSet pobj, pptr;
  ValueSet gpobj, gpptr;
  InstructionSet palloca;
  Sty2Idxes pobj2idx;

  for (auto pf : proc_funcs) {
    auto s = pf->pobj2inst;
    for (auto o : *pf->pobj) {
      pobj.insert(o);
      if (isa<StructType>(o) && s->count(o)) {
        add_idx(pobj2idx, cast<StructType>(o), (*s)[o]);
      }
    }
    for (auto p : *pf->pptr) {
      pptr.insert(p);
    }
    for (auto o : *pf->gpobj) {
      gpobj.insert(o);
    }
    for (auto p : *pf->gpptr) {
      gpptr.insert(p);
    }
    for (auto v : *pf->palloca) {
      palloca.insert(v);
    }
  }

  for (auto pf : sysfs_funcs) {
    auto s = pf->pobj2inst;
    for (auto o : *pf->pobj) {
      pobj.insert(o);
      if (isa<StructType>(o) && s->count(o)) {
        add_idx(pobj2idx, cast<StructType>(o), (*s)[o]);
      }
    }
    for (auto p : *pf->pptr) {
      pptr.insert(p);
    }
    for (auto o : *pf->gpobj) {
      gpobj.insert(o);
    }
    for (auto p : *pf->gpptr) {
      gpptr.insert(p);
    }
    for (auto v : *pf->palloca) {
      palloca.insert(v);
    }
  }
  for (auto pf : syscall_funcs) {
    auto s = pf->pobj2inst;
    for (auto o : *pf->pobj) {
      pobj.insert(o);
      if (isa<StructType>(o) && s->count(o)) {
        add_idx(pobj2idx, cast<StructType>(o), (*s)[o]);
      }
    }
    for (auto p : *pf->pptr) {
      pptr.insert(p);
    }
    for (auto o : *pf->gpobj) {
      gpobj.insert(o);
    }
    for (auto p : *pf->gpptr) {
      gpptr.insert(p);
    }
    for (auto v : *pf->palloca) {
      palloca.insert(v);
    }
  }

  // credential analysis
  for (auto obj : pchk_type) {
    pobj.insert(obj);
  }
  for (auto ptr : pchk_ptr_type) {
    pptr.insert(ptr);
  }
  for (auto gobj : pchk_gobj) {
     gpobj.insert(gobj);
  }
  for (auto gptr : pchk_gptr) {
    gpptr.insert(gptr);
  }

  // false negatives
  pobj.insert(StructType::getTypeByName(*ctx, "struct.dentry"));
  gpptr.insert(m->getGlobalVariable("dentry_hashtable"));
  gpobj.insert(m->getGlobalVariable("mmap_min_addr"));

  errs() << "\nDump pobj (" << pobj.size() <<")\n";
  for (auto sty : pobj) {
    if (isa<StructType>(sty)) {
      errs() << "- " << sty->getStructName() << "\n";
      if (pobj2idx.count(cast<StructType>(sty))) {
        auto idxset = pobj2idx[cast<StructType>(sty)];
        for (auto idx : *idxset) {
          errs() << " >> ";
          dump_indices(errs(), *idx);
        }
      }
    } else {
      errs() << *sty << "\n";
    }
  }
  errs() << "\nDump pptr (" << pptr.size() <<")\n";
  for (auto sty : pptr) {
    if (isa<StructType>(sty)) {
      errs() << "- " << sty->getStructName() << "\n";
    } else {
      errs() << *sty << "\n";
    }
  }
  errs() << "\nDump gpobj (" << gpobj.size() << ")\n";
  for (auto obj : gpobj) {
    if (!obj)
      continue;
    if (obj->hasName()) {
      errs() << "- " << obj->getName() << "\n";
    } else {
      errs() << *obj << "\n";
    }
  }

  errs() << "\nDump gpptr (" << gpptr.size() << ")\n";
  for (auto obj : gpptr) {
    if (!obj)
      continue;
    if (obj->hasName()) {
      errs() << "- " << obj->getName() << "\n";
    } else {
      errs() << *obj << "\n";
    }
  }
  errs() << "\nDump palloca (" << palloca.size() << ")\n";
  for (auto val : palloca) {
    if (!val)
      continue;
    print_debug(val);
  }

  if (knob_obj_list != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_obj_list, EC);
    for (auto sty : pobj)
      out << sty->getStructName() << "\n";
  }
  if (knob_ptr_list != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_ptr_list, EC);
    for (auto sty : pptr)
      out << sty->getStructName() << "\n";
  }
  if (knob_gobj_list != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_gobj_list, EC);
    for (auto gv : gpobj) {
      if (!gv)
        continue;
      if (gv->hasName())
        out << gv->getName() << "\n";
    }
  }
  if (knob_gptr_list != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_gptr_list, EC);
    for (auto gv : gpptr) {
      if (!gv)
        continue;
      if (gv->hasName())
        out << gv->getName() << "\n";
    }
  }
  if (knob_alloca_list != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_alloca_list, EC);

    while (palloca.size()) {
      auto it = palloca.begin();
      Function *func = (*it)->getFunction();
      dump_func(out, func);
      while (it != palloca.end()) {
        if (is_same_func((*it)->getFunction(), func)) {
          dump_inst(out, *it);
          it = palloca.erase(it);
        } else {
          ++it;
        }
      }
      out << "\n";
    }
  }

  //find_priv_stack_func();


}

void pta::find_syscall_args(Function *syscall, ValueSet *args)
{
  ValueList worklist;
  Argument *sarg = syscall->getArg(0);
  for (auto u : sarg->users())
    worklist.push_back(u);
  while(worklist.size()) {
    Value *v = worklist.front();
    worklist.pop_front();
    if (isa<CastInst>(v) || isa<GetElementPtrInst>(v)) {
      for (auto u : v->users())
        worklist.push_back(u);
    } else if (isa<LoadInst>(v)) {
      args->insert(v);
    }
  }
}

void pta::find_priv_stack_func() 
{
  errs() << "find_priv_stack_func\n";
  FunctionSet priv_stack_funcs;
  for (auto v : priv_vals) {
    InstructionSet callset, useset;
    BasicBlock *bb;
    ValueList worklist;
    ValueSet visited;
    
    // populate callset
    if (isa<Argument>(v)) {
      bb = &*cast<Argument>(v)->getParent()->begin();
      worklist.push_back(bb);
    } else if (isa<Instruction>(v)) {
      bb = cast<Instruction>(v)->getParent();
      auto iter = bb->begin();
      for (; iter != bb->end(); ++iter)
        if (&*iter == v) break;
      iter++;
      for (; iter != bb->end(); ++iter) {
        auto I = &*iter;
        if (!isa<CallInst>(I)) continue;
        auto func = get_callee_function_direct(I);
        if (!func) continue;
        if (is_skip_func(func)) continue;
        if (func->onlyReadsMemory()) continue;
        callset.insert(I);
      }
      visited.insert(bb);
      for (auto iter = llvm::succ_begin(bb); iter != llvm::succ_end(bb); ++iter) {
        worklist.push_back(*iter);
      }
    } else 
      continue;

    while (worklist.size()) {
      auto v = worklist.back();
      worklist.pop_back();
      if (!isa<BasicBlock>(v))
        continue;
      BasicBlock *bb = cast<BasicBlock>(v);
      if (visited.count(bb))
        continue;
      visited.insert(bb);
      for (auto iter = bb->begin(); iter != bb->end(); ++iter) {
        auto I = &*iter;
        if (!isa<CallInst>(I)) continue;
        auto func = get_callee_function_direct(I);
        if (!func) continue;
        if (is_skip_func(func)) continue;
        if (func->onlyReadsMemory()) continue;
        callset.insert(I);
      }
      for (auto iter = llvm::succ_begin(bb); iter != llvm::succ_end(bb); ++iter) {
        worklist.push_back(*iter);
      }
    }
    
    if (callset.size()==0)
      continue;

    // populate useset
    if (isa<Argument>(v)) {
      for (auto u : v->users())
        if (isa<Instruction>(u))
          worklist.push_back(u);
    } else 
      worklist.push_back(v); 
    while (worklist.size()) {
      auto v = worklist.back();
      worklist.pop_back();
      if (!isa<Instruction>(v))
        continue;
      Instruction *i = cast<Instruction>(v); 
      if (useset.count(i))
        continue;
      useset.insert(i);
      
      for (auto u : i->users()) {
        if (isa<CastInst>(u) || isa<BinaryOperator>(u) ||
            isa<UnaryOperator>(u) || isa<PHINode>(u))
          worklist.push_back(u); 
      }
    }

    // for each call, find any use that comes after the call
    // val -> call -> use
    for (auto c : callset) {
      bool found=false;

      for (auto u : useset) {
        if (c->getParent()==u->getParent()) {
          auto bb = c->getParent();
          int cnt_c=0;
          int cnt_u=0;
          for (auto iter=bb->begin(); iter != bb->end(); ++iter, ++cnt_c)
            if (&*iter == c) break;
          for (auto iter=bb->begin(); iter != bb->end(); ++iter, ++cnt_u)
            if (&*iter == u) break;
          if (cnt_c < cnt_u)
            found=true;
        } else { 
          // is call's bb reachable to use's bb?
          auto bb_c = c->getParent();
          auto bb_u = u->getParent();
          ValueSet visited;
          ValueList worklist;
          worklist.push_back(bb_c);
          while (worklist.size()) {
            auto bb = cast<BasicBlock>(worklist.back());
            worklist.pop_back();
            if (visited.count(bb))
              continue;
            visited.insert(bb);
            if (bb == bb_u) {
              found=true;
              break;
            }
            for (auto iter = llvm::succ_begin(bb); iter != llvm::succ_end(bb); ++iter) {
              worklist.push_back(*iter);
            }
          }
        }
        if (found)
          break;
      }
      if (found)  {
        print_debug(c, "priv stack call");
        priv_stack_funcs.insert(get_callee_function_direct(c));
      }
    }
  }

  errs() << "# of priv stack funcs: " << priv_stack_funcs.size() << "\n";
  for (auto f : priv_stack_funcs) 
    errs() << " - " << f->getName() << "\n";
}


void pta::process_pta_old(Module &module, int op)
{
    //  1. find privilege error return vlaues {EPERM, EACCES, EROFS},
    //  2. collect dependent types for each return values
    errs() << "\n [ 1. Find interesting return values ] \n";
    for (Module::iterator fi = module.begin(), fe = module.end();
            fi != fe; ++fi)
    {
        Function *func = dyn_cast<Function>(fi);
        bool is_cand = false;
        if (is_skip_function(fi->getName().str()))
            continue;
        if (!func)
            continue;
        if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
            continue;
        //if (!is_perm_func(func, op)) {
        //    if (is_perm_func_cand(func, op))
        //        is_cand = true;
        //    else
        //        continue;
        //}

        if (!isInterestingFunc(func))
            continue;

        BasicBlockSet *bbset = findErrorBB(func, op);
        if (!bbset)
            continue;
        for (auto B : *bbset) {
            bool is_ptr = true; // or is_obj;
            Type *pTy = findPrivType(B, &is_ptr);
            if (!pTy){
                //errs() << "ptype: null\n";
                continue;
            }
            else{
                TypeSet *tys = f2ty[func];
                if (!tys) {
                    tys = new TypeSet;
                    f2ty[func] = tys;
                }
                tys->insert(pTy);
                if (is_cand) {
                    if (is_ptr){
                        print_debug(pTy, func, "ptr_cand");
                        //pptr_cand.insert(get_type(m, pTy));
                    }
                    else {
                        print_debug(pTy, func, "obj_cand");
                        pobj_cand[op]->insert(get_type(m, pTy));
                    }
                }
                else {
                    if (is_ptr) {
                        print_debug(pTy, func, "ptr");
                        //pptr.insert(get_type(m, pTy));
                    }
                    else {
                        print_debug(pTy, func, "obj");
                        pobj[op]->insert(get_type(m, pTy));
                    }
                }
            }
        }
    }
}

void pta::dump_pta()
{
    for (auto m : f2ty) {
        Function *func = m.first;
        TypeSet *tys = m.second;
    }
}


bool pta::is_file_line(std::string line) {
    const char *token = "\x0c";
    if (line.find(token) != std::string::npos) {
        return true;
    } else {
        return false;
    }
}

// Collect heap-allocated object typess
bool pta::collect_object_types(Module &module) {
  StructTypeSet objs;
  // global object types
  for (auto &gv : m->globals()) {
    if (!isa<StructType>(gv.getType()))
      continue;
    if (is_skip_type(gv.getType()))
      continue;
    StructType *sty = cast<StructType>(get_type(m, gv.getType()));
    if (sty->getName() == "struct.atomic_64")
      continue;
    objs.insert(sty);
  }
  // heap object types
  for (Module::iterator fi = m->begin(), fe = m->end();
       fi != fe; ++fi) {
    Function *func = dyn_cast<Function>(fi);
    if (!func)
      continue;
    if (func->isDeclaration() || func->isIntrinsic() || (!func->hasName()))
      continue;
    if (is_skip_function(func->getName().str()))
      continue;
    if (is_alloc_function(func->getName().str()))
      continue;

    collect_object_types(func, &objs);
  }
  errs() << "Objects: " << objs.size() << "\n";

  for (auto sty : objs) {
    errs() << sty->getName() << "\n";
  }
  if (knob_dump_path != "") {
    std::error_code EC;
    raw_fd_ostream out(knob_dump_path, EC);
    for (auto sty : objs)
      out << sty->getName() << "\n";
  }
  return false;
}

void pta::collect_object_types(Function *func, StructTypeSet *objs) {
  for (auto &B : *func) {
    for (auto I = B.begin(), E = B.end(); I != E; ++I) {
      if (!isa<CallInst>(&*I))
        continue;
      if (!is_alloc_function(get_callee_function_name(&*I).str()))
        continue;
      collect_object_types(&*I, objs);
    }
  }
}

void pta::collect_object_types(Value *val, StructTypeSet *objs) {
  ValueSet visited;
  ValueList worklist;
  StructTypeSet typeset;
  bool isUniversal=false;
  worklist.push_back(val);

  while (worklist.size())  {
    auto v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (auto sty = get_pstr_type(m, v->getType())) {
      if (is_list_struct(sty))
        continue;
      if (sty->getName() == "struct.atomic64_t")
        continue;
      if (sty->getName().startswith("struct.anon") ||
          sty->getName().startswith("union.anon"))
        continue;
      typeset.insert(sty);
    }
    for (auto u : v->users()) {
      if (is_builtin_container_of(u)) {
        worklist.push_back(u);
      } else if (isa<SelectInst>(u)) {
        if (cast<User>(u)->getOperand(0) == v)
          worklist.push_back(u);
      } else if (isa<PHINode>(u)) {
        worklist.push_back(u);
      } else if (isa<CastInst>(u)) {
        if (isa<TruncInst>(u))
          continue;
        if (_is_err_ptr(u))
          continue;
        auto lsty = get_pstr_type(m, v->getType());
        auto rsty = get_pstr_type(m, u->getType());
        if (lsty && !lsty->isOpaque() && rsty && !rsty->isOpaque()) {
          auto lsize = DL->getTypeStoreSizeInBits(lsty);
          auto rsize = DL->getTypeStoreSizeInBits(rsty);
          if (rsize < lsize)
            continue;
        }
        worklist.push_back(u);
      } else if (isa<StoreInst>(u)) {
        if (cast<User>(u)->getOperand(0) != v)
          continue;
        auto dst = cast<User>(u)->getOperand(1);
        if (auto ci = dyn_cast<CastInst>(dst)) {
          if (isa<PointerType>(ci->getOperand(0)->getType())) {
            if (auto sty = get_pstr_type(m, ci->getOperand(0)
                                         ->getType()->getPointerElementType()))
              if (!is_list_struct(sty) &&
                  sty->getName() != "struct.atomic64_t" &&
                  !sty->getName().startswith("struct.anon") &&
                  !sty->getName().startswith("union.anon"))
                typeset.insert(sty);
          }
        }
      } else if (isa<BinaryOperator>(u)) {
        auto op = cast<User>(u)->getOperand(1);
        if (!isa<ConstantInt>(op))
          continue;
        if (cast<ConstantInt>(op)->getSExtValue() < 32) {
          worklist.push_back(u);
          isUniversal |= true;
        }
      } else if (isa<GetElementPtrInst>(u)) {
        // pointer addition
        if (u->getNumOperands()==2) {
          worklist.push_back(u);
          isUniversal |= true;
        }
      } else if (auto ret = dyn_cast<ReturnInst>(u)) {
        if (auto func = ret->getFunction()) {
          for (auto _u : func->users()) {
            if (isa<Instruction>(_u)) {
              worklist.push_back(_u);
              isUniversal |= true;
            } else if (isa<ConstantExpr>(_u)) {
              for (auto __u : _u->users())
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

  TypeSet nested;
  TypeList typelist;
  for (auto sty : typeset) {
    for (int i=0; i<sty->getNumElements(); ++i) {
      auto ety = sty->getElementType(i);
      typelist.push_back(get_type(m, ety));
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
        typelist.push_back(get_type(m, ety));
      }
    } else if (auto arr = dyn_cast<ArrayType>(ty)) {
      typelist.push_back(get_type(m, arr->getElementType()));
    }
  }

  StructType *allocTy = nullptr;
  bool multiple=false;
  for (auto ty : typeset) {
    if (ty->isOpaque()) {
      print_error(ty, nullptr, "opaque");
      continue;
    }
    else if (!nested.count(ty)) {
      if (!allocTy)
        allocTy = ty;
      else {
        multiple=true;
        if (DL->getTypeStoreSizeInBits(allocTy) <
            DL->getTypeStoreSizeInBits(ty)) {
          allocTy = ty;
        }
      }
    }
  }

  if (!allocTy) {
    print_debug(val, "no alloc type");
  } else {
    if (multiple && isUniversal) {
      // multiple alloc types on universal allocator
      for (auto ty : typeset) {
        if (!objs->count(ty)) {
          print_debug(val, "val");
          errs() << "found " << ty->getStructName() << "\n";
        }
        objs->insert(ty);
      }
    } else {
      if (!objs->count(allocTy)) {
        print_debug(val, "val");
        errs() << "found " << allocTy->getStructName() << "\n";
      }
      objs->insert(allocTy);
    }
  }
}


// find the conditional value that lead to err (load).
void pta::find_cond_val(Value *err, ValueSet *condset) {
  ValueSet exclude_bb;
  ValueSet visited;
  ValueList worklist;
  InstructionSet brset;

  BasicBlock *uncond_bb = nullptr;


  auto bb = cast<Instruction>(err)->getParent();
  auto term = bb->getTerminator();
  if (!isa<BranchInst>(term))
    return;

  auto br = cast<BranchInst>(term);

  // cond value is in the previous block
  if (br->isUnconditional()) {
    worklist.push_back(br->getParent());
    while (worklist.size()) {
      BasicBlock *b = cast<BasicBlock>(worklist.back());
      worklist.pop_back();
      if (visited.count(b))
        continue;
      visited.insert(b);

      exclude_bb.insert(b);
      for (auto it = succ_begin(b); it != succ_end(b); ++it) {
        exclude_bb.insert(*it);
        worklist.push_back(*it);
      }
    }
    visited.clear();
    worklist.push_back(bb);

    if (auto pred = bb->getSinglePredecessor()) {
      auto term = pred->getTerminator();
      if (auto br = dyn_cast<BranchInst>(term)) {
        if (!br->isUnconditional()) {
          brset.insert(br);
          worklist.push_back(pred);
        }
      }
    }

    while(worklist.size()) {
      BasicBlock *b = cast<BasicBlock>(worklist.back());
      worklist.pop_back();
      if (visited.count(b))
        continue;
      visited.insert(b);

      auto pred = b->getSinglePredecessor();
      if (!pred)
        continue;

      auto term = pred->getTerminator();
      if (!isa<BranchInst>(term) && !isa<SwitchInst>(term))
        continue;

      if (isa<BranchInst>(term)) {
        // exclude diamond shape branch
        auto br = cast<BranchInst>(term);
        if (!br->isUnconditional()) {
          bool exclude = true;

          for (int i=1; i < br->getNumOperands(); ++i) {
            BasicBlockSet _visited;
            BasicBlockList _worklist;
            if (isa<BasicBlock>(br->getOperand(i))) {
              auto succ_bb = cast<BasicBlock>(br->getOperand(i));
              _worklist.push_back(succ_bb);
            }
            while (_worklist.size()) {
              auto _bb = _worklist.back();
              _worklist.pop_back();
              if (_visited.count(_bb))
                continue;
              _visited.insert(_bb);
              for (auto it = succ_begin(_bb); it != succ_end(_bb); ++it) {
                bool end = false;
                auto succ_bb = *it;
                for (auto ii = succ_bb->begin(); ii != succ_bb->end(); ++ii) {
                  if (!isa<PHINode>(ii))
                    continue;
                  auto phi = dyn_cast<PHINode>(ii);
                  for (unsigned n = 0; n < phi->getNumIncomingValues(); ++n) {
                    if (exclude_bb.count(phi->getIncomingBlock(n))) {
                      end = true;
                      break;
                    }
                  }
                }
                if (end)
                  continue;
                _worklist.push_back(*it);

              }
            }
            bool has_exclude = false;
            for (auto _bb : _visited) {
              if (exclude_bb.count(_bb)) {
                has_exclude = true;
                break;
              }
            }
            if (!has_exclude)
              exclude = false;
          }
          if (exclude)
            continue;
        }
      }

      brset.insert(term);
      worklist.push_back(pred);
    }
  }
  else { // cond value is in the current block
    brset.insert(br);
  }

  if (brset.size() > 0) {
    print_debug(err, "err");
  }
  for (auto b : brset) {
    condset->insert(b->getOperand(0));
    print_debug(b->getOperand(0), "cond");

  }
}


// Collect pchk conditional Data
void pta::find_pchk_cond(Module &m, ValueSet *pchk_cond) {
  for (Module::iterator fi = m.begin(), fe = m.end();
            fi != fe; ++fi)
    {
      if (fi->isDeclaration())
        continue;

      Function *func = &*fi;
      if (func->getName() == "tipc_nl_compat_recv")
        continue;

      for (auto &B : *func) {
        for (auto I = B.begin(), E = B.end(); I != E; ++I) {
          if (!isa<LoadInst>(&*I))
            continue;
          auto li = cast<LoadInst>(&*I);
          // check if the loaded value is a permission error code
          if (!isa<GlobalVariable>(li->getOperand(0)))
            continue;
          auto gv = cast<GlobalVariable>(li->getOperand(0));
          if (!pta_err.count(gv))
            continue;

          find_cond_val(li, pchk_cond);

        }
      }
    }
}


void pta::find_pchk_ld(Value *data, ValueSet *ldset, bool isVal) {
  ValueList worklist;
  ValueSet visited;
  worklist.push_back(data);
  // First, find the load instructions that load the cond value.
  while(worklist.size()) {
    auto v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);

    if (isVal && isa<PointerType>(v->getType())) {
      continue;
    }
    if (debug)
      print_debug(v);

    if (isa<Argument>(v)) {
      auto arg = cast<Argument>(v);
      auto argno = arg->getArgNo();
      auto func = arg->getParent();
      for (auto u : func->users()) {
        if (!isa<CallInst>(u))
          continue;
        if (cast<CallInst>(u)->getCalledFunction() != func)
          continue;
        if (cast<CallInst>(u)->arg_size() <= argno)
          continue;
        worklist.push_back(cast<CallInst>(u)->getArgOperand(argno));
      }
      continue;
    }

    if (!isa<Instruction>(v))
      continue;

    auto ii = cast<Instruction>(v);

    switch(ii->getOpcode()) {
      case Instruction::Load:
        // we don't collect pointer type data
        if (isVal && isa<PointerType>(ii->getType()))
          continue;
        ldset->insert(ii);
        break;
      case Instruction::Call: {
        FunctionSet funcs;
        get_call_dest(ii, funcs);
        for (auto callee : funcs) {
          if (callee->isDeclaration())
            continue;
          if (is_skip_func(callee))
            continue;
          if (!callee->back().getTerminator())
            continue;
          worklist.push_back(callee->back().getTerminator());
        }
        break;
      }
      case Instruction::Select:
        worklist.push_back(ii->getOperand(1));
        worklist.push_back(ii->getOperand(2));
        break;
      case Instruction::Trunc:
      case Instruction::ICmp:
      case Instruction::Add:
      case Instruction::And:
      case Instruction::Xor:
      case Instruction::Or:
      case Instruction::Sub:
      case Instruction::Shl:
      case Instruction::LShr:
      case Instruction::AShr:
        if (!isVal)
          break;
      case Instruction::PHI:
      case Instruction::BitCast:
      case Instruction::IntToPtr:
      case Instruction::PtrToInt:
      case Instruction::ZExt:
      case Instruction::SExt:
      case Instruction::Ret:
        for (int i=0; i<ii->getNumOperands(); i++) {
          worklist.push_back(ii->getOperand(i));
        }
        break;
      default:
        break;
    }
  }
}
void pta::find_pchk_gep(Value *data, ValueSet *objset, ValueSet *gobjset, bool isVal) {
  ValueSet visited;
  ValueList worklist;
  worklist.push_back(data);
  while (worklist.size()) {
    auto v = worklist.back();
    worklist.pop_back();
    if (visited.count(v))
      continue;
    visited.insert(v);
    if (debug)
      print_debug(v);
    if (isa<Argument>(v)) {
      auto arg = cast<Argument>(v);
      auto argno = arg->getArgNo();
      auto func = arg->getParent();
      for (auto u : func->users()) {
        if (!isa<CallInst>(u))
          continue;
        if (cast<CallInst>(u)->getCalledFunction() != func)
          continue;
        if (cast<CallInst>(u)->arg_size() <= argno)
          continue;
        worklist.push_back(cast<CallInst>(u)->getArgOperand(argno));

        worklist.push_back(cast<CallInst>(u)->getArgOperand(argno));
      continue;
      }
    }

    if (isa<ConstantExpr>(v)) {
      auto ce = cast<ConstantExpr>(v);
      for (int i=0; i<ce->getNumOperands(); i++) {
        worklist.push_back(ce->getOperand(i));
      }
      continue;
    }

    if (isa<GlobalVariable>(v)) {
      auto gv = cast<GlobalVariable>(v);
      if (pta_err.count(gv) || gv->getName().startswith("ebadf"))
        continue;
      if (gv->hasSection())
        if (gv->getSection().contains(".ro_after_init"))
          continue;
      gobjset->insert(gv);
      continue;
    }

    if (!isa<Instruction>(v))
      continue;

    auto ii = cast<Instruction>(v);

    switch(ii->getOpcode()) {

      // collect getelementptr only if the 0th operand is a struct type
      // and the referenced data type is a non-pointer type
      case Instruction::GetElementPtr:
        if (isa<StructType>(ii->getOperand(0)->getType()->getPointerElementType())) {
          if (!isVal || !isa<PointerType>(ii->getType()->getPointerElementType())) {
            objset->insert(ii);
          }
        }
        worklist.push_back(ii->getOperand(0));
        break;

      case Instruction::BitCast:
      case Instruction::IntToPtr:
      case Instruction::PtrToInt:
        worklist.push_back(ii->getOperand(0));
        break;
      default:
        break;
    }
  }

}

// Collect pchecked object types from conditional value
// Backward-track the cond value to find the pchecked object
// The pchecked object can be identified from the struct pointer of
// the getelementptr's 0th operand.
void pta::find_pchk_obj(Value *cond, ValueSet *pchk_obj, ValueSet *pchk_gobj, ValueSet *pchk_ptr) {
  ValueSet ldset, visited;
  ValueSet objset, ptrset, gptrset;
  Value *v;
  bool debug = false;

  // 1. Find load
  find_pchk_ld(cond, &ldset, true);

  // 2. Find gep
  for (auto ld : ldset) {
    find_pchk_gep(cast<Instruction>(ld)->getOperand(0), pchk_obj, pchk_gobj, true);
  }

  for (auto obj : *pchk_obj) {
    objset.insert(obj);
  }

  while (objset.size()) {
    // 3. Find pointer load
    ldset.clear();
    for(auto obj : objset) {
      if (visited.count(obj))
        continue;
      visited.insert(obj);
      if (isa<GetElementPtrInst>(obj)) {
        find_pchk_ld(cast<Instruction>(obj)->getOperand(0), &ldset, false);
      }
    }
    // 4. Find pointer gep
    for (auto ld : ldset) {
      if (visited.count(ld))
        continue;
      visited.insert(ld);
      find_pchk_gep(cast<Instruction>(ld)->getOperand(0), &ptrset, &gptrset, false);
    }
    for (auto ptr : ptrset)
      pchk_ptr->insert(ptr);
    for (auto ptr : gptrset)
      pchk_ptr->insert(ptr);
    objset.clear();
    for (auto ptr : ptrset) {
      objset.insert(ptr);
    }
    ptrset.clear();
  }
}

// Collect pchecked object types
bool pta::collect_cred_object(Module &module) {

  int gv_cnt = 0;
  // get number of global variables
  for (auto &gv : m->globals()) {
    if (!gv.hasName())
      continue;
    if (gv.getName().startswith("__param"))
      continue;
    if (gv.getName().startswith(".compound"))
      continue;
    if (isa<Function>(&gv))
      continue;
    if (pta_err.count(&gv))
      continue;
    if (gv.hasSection()) {
      if (gv.getSection().contains(".ro_after_init"))
        continue;
    }
    gv_cnt++;
  }

  errs() << "# of gvs: " << gv_cnt << "\n";


  find_pchk_cond(module, &pchk_cond);

  for (auto cond : pchk_cond) {
    ValueSet objset, gobjset, ptrset;

    if (isa<PointerType>(cond->getType()))
      continue;
    if (isa<CmpInst>(cond)) {
      auto v = cast<CmpInst>(cond)->getOperand(0);
      if (isa<PointerType>(v->getType()))
        continue;
      v = v->stripPointerCasts();
      if (isa<PointerType>(v->getType()))
        continue;
    }

    find_pchk_obj(cond, &objset, &gobjset, &ptrset);

    if (objset.size() == 0 && gobjset.size() == 0)
      continue;
    print_debug(cond, "pchk_cond");
    for (auto obj : objset) {
      auto sty = get_pstr_type(&module, cast<User>(obj)->getOperand(0)->getType());
      if (!sty)
        continue;
      if (!is_object_type(sty))
        continue;
      if (is_list_struct(sty))
        continue;
      print_debug(obj, "pchk_obj");
      pchk_type.insert(sty);
    }

    for (auto gobj : gobjset) {
      print_debug(gobj, "pchk_gobj");
      pchk_gobj.insert(gobj);
    }
    for (auto ptr : ptrset) {
      if (isa<GlobalVariable>(ptr)) {
        pchk_gptr.insert(ptr);
      } else {
        auto sty = get_pstr_type(&module, cast<User>(ptr)->getOperand(0)->getType());
        if (!sty)
          continue;
        if (!is_object_type(sty))
          continue;
        if (is_list_struct(sty))
          continue;
        pchk_ptr_type.insert(sty);
      }
    }
  }

  errs() << "pchk_type size: " << pchk_type.size() << "\n";
  for (auto sty : pchk_type) {
    errs() << "pchk_type: " << sty->getName() << "\n";
  }
  errs() << "pchk_gobj size: " << pchk_gobj.size() << "\n";
  for (auto gobj : pchk_gobj) {
    errs() << "pchk_gobj: " << gobj->getName() << "\n";
  }

  errs() << "pchk_ptr_type size: " << pchk_ptr_type.size() << "\n";
  for (auto sty : pchk_ptr_type) {
    errs() << "pchk_ptr : " << sty->getName() << "\n";
  }
  errs() << "pchk_gobj size: " << pchk_gobj.size() << "\n";
  for (auto gptr : pchk_gptr) {
    errs() << "pchk_gptr: " << gptr->getName() << "\n";
  }

}


bool pta::ptaPass(Module &module)
{
    // 1. Collect write handlers for kernel interfaces (i.e., proc, sysfs, syscall)
    // For each write handlers,
    // 2. Collect privilege checks (i.e., Capability, DAC)
    // 3. Collect privilege data types
    //    - data being updated after the privilege checks
    //    - data being updated by the user provided data
    // 4. Collect privilege pointer types
    //    - pointers that locate the privilege data types

    //errs() << "\n [ 0. Collect credential data ] \n";
    // collect_cred_object(module);
    // return true;

    errs() << "\n [ 1. Collect interface handlers ] \n";
    collect_interface_handlers();

    if (knob_mode == "interface") {
      errs() << "\n [ 2. Collect interface functions ] \n";
      FunctionSet interface_funcs;
      for (auto pf : proc_funcs) {
        if (pf->read)
          interface_funcs.insert(pf->read);
        if (pf->write)
          interface_funcs.insert(pf->write);
        if (pf->show)
          interface_funcs.insert(pf->show);
      }
      for (auto pf : sysfs_funcs) {
        if (pf->read)
          interface_funcs.insert(pf->read);
        if (pf->write)
          interface_funcs.insert(pf->write);
      }
      for (auto pf : syscall_funcs) {
        interface_funcs.insert(pf->write);
      }
      // Dump
      std::error_code EC;
      std::string path = "interface.func";
      raw_fd_ostream out(path, EC);

      errs() << "Interface Functions [" << interface_funcs.size() << "]\n";
      for (auto s : interface_funcs) {
        out << s->getName() << "\n";
      }
      return true;
    }
    errs() << "\n [ 2. Find privilege checks ] \n";
    collect_privilege_checks();


    return true;
}
bool pta::doInitialization(Module &module)
{
    m = &module;
    ctx = &module.getContext();
    DL = &m->getDataLayout();

    initialize_list_struct("");
    initialize_skip_func(knob_skip_func_list, "");
    initialize_function_code(module, knob_func_code_list);
    initialize_alloc_func(knob_alloc_func_list);


    //for (int i=NUM_START; i<NUM_OP; i++) {
    //    errs() << "perm_funcs" << i << "\n";
    //    for (auto s : *perm_funcs[i]) {
    //        errs() << s << "\n";
    //    }
    //    errs() <<"\n";
    //}

    pta_err.insert(m->getGlobalVariable("eperm"));
    pta_err.insert(m->getGlobalVariable("eacces"));
    pta_err.insert(m->getGlobalVariable("erofs"));
    //pta_err.insert(m->getGlobalVariable("ebadf"));

    credTy = StructType::getTypeByName(*ctx,"struct.cred");
    inodeTy = StructType::getTypeByName(*ctx,"struct.inode");
    taskTy = StructType::getTypeByName(*ctx,"struct.task_struct");
    nsTy = StructType::getTypeByName(*ctx,"struct.user_namespace");
    smack_hooks = module.getNamedValue("smack_hooks");

    cmp_funcs.insert("strcmp");
    cmp_funcs.insert("strncmp");
    cmp_funcs.insert("bcmp");

    //copy_funcs.insert("__arch_copy_to_user");
    copy_funcs.insert("__arch_copy_from_user");
    copy_funcs.insert("_copy_to_user");
    copy_funcs.insert("_copy_from_user");
    copy_funcs.insert("memcpy");
    copy_funcs.insert("strlcpy");
    copy_funcs.insert("strcpy");
    copy_funcs.insert("strncpy");
    copy_funcs.insert("strncpy_from_user");
    copy_funcs.insert("proc_get_long");
    copy_funcs.insert("__do_proc_dointvec");
    copy_funcs.insert("do_proc_doulongvec_minmax");
    copy_funcs.insert("do_proc_douintvec");
    copy_funcs.insert("kstrtoint");
    copy_funcs.insert("kstrtouint_from_user");
    copy_funcs.insert("sscanf");

    parse_funcs.insert("simple_strtoul");
    
    proc_parse_funcs.insert("proc_dostring");
    proc_parse_funcs.insert("proc_dointvec");
    proc_parse_funcs.insert("proc_douintvec");
    proc_parse_funcs.insert("proc_dointvec_minmax");
    proc_parse_funcs.insert("proc_douintvec_minmax");
    proc_parse_funcs.insert("proc_doulongvec_minmax");
    proc_parse_funcs.insert("proc_dointvec_jiffies");
    proc_parse_funcs.insert("proc_dointvec_minmax_sysadmin");
    proc_parse_funcs.insert("proc_do_large_bitmap");

    perm_funcs.insert("__fdget");
    perm_funcs.insert("__fdget_raw");
    perm_funcs.insert("fget");
    perm_funcs.insert("capable");
    perm_funcs.insert("ns_capable");
    perm_funcs.insert("ns_capable_setid");
    perm_funcs.insert("cap_capable");
    perm_funcs.insert("inode_owner_or_capable");
    perm_funcs.insert("inode_permission");
    perm_funcs.insert("generic_permission");
    perm_funcs.insert("key_task_permission");
    perm_funcs.insert("file_ns_capable");

    int count = 0;
    auto list = load_list(knob_object_list);
    for (auto sname : *list){
        StructType *sty = StructType::getTypeByName(*ctx,sname);
        objs.insert(sty);
        count++;
    }
    errs() << "Kernel Objects : " << count << "\n";
    return false;
}

bool pta::doFinalization(Module &module)
{
    //delete_metadata();
    return false;
}
bool pta::runOnModule(Module &module)
{

    bool res;
    if (knob_object)
      res = collect_object_types(module);
    else
      res = ptaPass(module);
    return 0;
}

static RegisterPass<pta>
XXX("pta", "pta Pass");
