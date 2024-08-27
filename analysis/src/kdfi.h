#ifndef  __KDFI_H_
#define  __KDFI_H_
#include "llvm/Pass.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionAliasAnalysis.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/MemorySSA.h"
#include "commontypes.h"
#include "simple_set.h"
#include "internal.h"
#include "utility.h"
#include "knobs.h"
#include <regex>

#define DEBUG_TYPE "kdfi"

enum TYPES {
  NON,
  MTE,
  PAC,
  FUL,
};
typedef std::unordered_map<StructType*, TYPES> StructTypesMap;
typedef std::unordered_map<GlobalVariable*, TYPES> GVTypesMap;
typedef std::unordered_map<Value*, StructType*> Val2Struct;
typedef std::map<Value*, FunctionSet*> Val2FuncSet;

class kdfi : public ModulePass
{
 private:
    virtual bool runOnModule(Module&) override;
    virtual bool doInitialization(Module&) override;
    virtual bool doFinalization(Module&) override;

    Type *get_type(Type*);
    int gep2offset(StructType *, Indices*);
    GlobalVariable *get_global(Value *v, int*);
    int gep2offset(Instruction*);
    Indices *i8gep2idx(StructType *, int);
    bool is_i8gep(User*);
    bool is_list_type(Type *);
    StructType *get_list_type(Type*);
    bool is_private_type(Type *);
    bool is_pte_type(Type*);
    bool is_pstr_type(Type*);
    bool is_pstr_type(Value*);
    bool is_nested_pobj(Type*);
    MDNode *get_arg_md(Argument*);
    StructType *get_pstr_type_md(Value*);
    StructType *get_pstr_type(Type*);
    StructType *get_pstr_type(Value*);
    StructType *get_cast_pstr_type(Value*);
    bool is_pptr_type(Type*);
    bool is_pptr_type(Type*, StructType*);
    bool is_priv_type(Type*);
    bool is_from_implicit_pptr(Value*, StructType*);
    StructType *get_container_srcty(Instruction *);
    bool collect_skip_maccess(Function*, Value*);
    void collect_access_func();
    void collect_pptr_access();
    void get_equiv_geps(Instruction*, InstructionSet*, int);
    void get_load(Value*, InstructionSet*, ValueSet*, bool/*direct (pac)*/, bool/*collision*/, bool pac_sign = false);
    bool is_cpu_ptr(Value*);
    bool is_per_cpu(Function*, Instruction*);
    bool has_pptr_field(StructType*, int size = INT_MAX);
    bool has_pptr_field(ConstantStruct*, TypeSet&);
    Indices *get_pptr_field(StructType*);
    Indices* get_indices(Indices, StructType *srcty = nullptr);

    void print(Indices *id)
    {
            for (auto i : *id) {
                    errs() << i << " ";
            }
            errs() << "\n";
    }

    bool is_pac_skip(Value *v) {
      if (auto ci = dyn_cast<CallInst>(v)) {
        if (get_callee_function_name(ci) == "ppac_skip") {
            return true;
        }
      }
      return false;
    }

    bool is_anon_type(StringRef sname) {
        if (sname.startswith("union.anon") || sname.startswith("struct.anon"))
            return true;
        return false;
    }
    bool is_void_type(Type* ty) {
      if (ty->isPointerTy()) {
        auto elem = ty->getPointerElementType();
        if (elem->isIntegerTy())
          return true;
        if (is_list_type(elem)) 
          return true;
      }
      return false;
    }

    bool is_skip_type(StringRef sname) {
        if (sname.startswith("struct.module")) // difficult to track section/module pointer operations  
            return true;
        return false;
    }


    /////////////////////////////

    void get_union_elements(StructType*, TypeSet*);
    void collect_nested_type();
    void collect_safe_type();
    bool is_parent_type(StructType*);
    void collect_parent_type();
    void check_gv_initializer();
    StructType *get_alloc_types(Instruction*, StructTypeSet*);
    StructType *get_free_type(Instruction*);
    StructType *get_lookup_type(CallInst *);
    StructType *get_i8gep_type(User *gep); 
    void collect_alloc();
    Instruction *get_list_store_pair(Instruction*);
    void get_pstr_from_pptr(Instruction*, ValueSet*);
    void collect_implicit_pval();
    
    void find_pstack_funcs();
    void get_gpfield(GlobalVariable*, Constant*, int);
    void get_listfield(GlobalVariable*, Constant*, int);
    void collect_listfield(Module &m);
    void collect_listcopy(Module &m);


    void collect_gref();
    void collect_gref_use();
    void collect_ptr();
    void collect_ptr_access();
    void collect_pptr_ref();
    void collect_pptr_copy();

    void dump_alloc_inst(raw_fd_ostream&);
    void dump_listfield();

    void preprocess();
    void process();
    void dump();
    void dump_inst_sty(raw_fd_ostream &out, Instruction *i, StructType *sty);
    void initialize_rt();
    void initialize_kdfi_struct();
    
    bool kdfiPass(Module&);

    void find_cmp(Value*, std::set<Use*> *);
    bool is_phys_addr(Value*);
    void collect_pointer_ldst();
    void collect(Value*, unsigned, unsigned, std::set<unsigned>*, ValueSet*,
             UseSet *visited=nullptr);

    bool is_variable_64(Value*);
    void analyze_oob(Module &);
    void analyze_oob2(Module &, ValueSet *, ValueSet *, ValueSet *);

    void analyze_list(Module &);


    void collect_reachable_funcs();
    void collect_reachable_funcs(Function*);


 public:
    static char ID;
    kdfi() : ModulePass(ID) {};

    virtual StringRef getPassName() const override
    {
        return "kdfi";
    }
private:
    LLVMContext *ctx;
    Module *m;
    const DataLayout  *DL;
    Type *int8ty, *int32ty;
    StructType *taskTy;

    ConstantInt *PAC_MASK_CONST;
    InstFuncMap dummyCE;
    std::set<Indices*> ind_keys;
    FunctionSet funcs, noaccess;

    //FunctionIntMap func2carg_mte, func2carg_pac;
    ArgumentSet carg_mte, carg_pac;
    ArgumentSet parg_mte, parg_pac;
    FunctionSet cret_mte, cret_pac;
    FunctionSet pret_mte, pret_pac;
    InstructionSet priv_alloc;
    InstructionSet priv_free,normal_free;
    Val2Struct cache2sty;
    Val2Struct alloc2sty;
    Val2Struct free2sty;
    InstructionSet pac_skip_gep;

    InstructionSet normal_alloc;
    InstructionSet mte_priv_inst;
    InstructionSet mte_skip_inst;

    FunctionSet pstack_func;

    InstructionSet pac_strip_inst;
    InstructionSet pac_skip_sign;
    InstructionSet pac_convert_inst;
    FunctionSet pac_collision_funcs;
    InstructionSet pac_sign_inst;
    InstructionSet pac_auth_inst;

    InstructionSet pac_callset;
    InstructionSet pac_ldset;

    int iteration;
    ValueSet updates;

    /////////////////////////////
    FunctionCallee createPACFunc;
    FunctionCallee checkPACFunc;
    FunctionCallee convertPACFunc;
    FunctionCallee stripPACFunc;
    IntFunctionMap funcCode;
    Ty2TySet pnestset;
    Ty2TySet nnestset;
    FunctionSet mte_skip_func;
    FunctionSet notcma;
    StringSet skip_access_funcs;
    std::unordered_map<Function*, FunctionSet*> f2caller, f2callee;
    const char *const createPACFuncName = "__ppac_create_pac";
    const char *const checkPACFuncName = "__ppac_check_pac";
    const char *const convertPACFuncName = "__ppac_convert_pac";
    const char *const stripPACFuncName = "__ppac_strip_pac";

    // kopguard
    // InstructionSet ptr_access, ptr_load, ptr_cmp, pte_load;
    int total_access;
    InstructionSet pptr_load, pptr_store, skip_load, skip_store;
    

    ValueSet gref, gref_gv, priv_ptr, safe_ptr, unsafe_ptr, parent_ptr, gpptr;
    ValueSet pptr_ref, skip_ref, stack_ref;
    ValueSet inter_safe_ptr, inter_unsafe_ptr, inter_parent_ptr;
    std::set<std::pair<StructType*, unsigned>> gref_fields, priv_fields;
    std::set<std::pair<GlobalVariable*, unsigned>> gref_gvfields;
    ValueSet safe_access, unsafe_access, both_access, unprotected_load, unprotected_store, stack_access, priv_load, priv_store;
    ValueSet variable_access;
    InstructionSet ptr_load;
    ValueSet intra_safe_access, intra_unsafe_access;
    InstructionSet inter_safe_access, inter_unsafe_access;
    InstructionSet ptr_copy;
    TypeSet pobj,pptr, container_pobj, nested_pobj, priv_reftype;
    TypeSet parent_type, priv_ref;
    StructTypeSet safe_type, unsafe_type;
    std::map<StructType*, Indices*> parent2off;
    ValueSet safe_arg, unsafe_arg;
    ValueSet priv_gobj, priv_gptr, all_gv;
    ValueSet priv_gobj_use;
    std::set<std::pair<GlobalVariable*, int>> gpfields, list_fields;
    Val2Type copy2sty;
    std::map<Value*, int> copy2base;
    FunctionSet reachable_funcs;

};

#endif //  __KDFI_H_
