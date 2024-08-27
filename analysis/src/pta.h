#ifndef __PTA_H_
#define __PTA_H_
#include "llvm/Pass.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
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
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "commontypes.h"
#include "simple_set.h"
#include "internal.h"
#include "utility.h"
#include "knobs.h"
#define DEBUG_TYPE "pta"

enum PTYPE {
  PROC,
  SYSFS,
  SYSCALL,
};
typedef struct pfunc {
    StringRef name;
    PTYPE type;
    int mode;
    Value *sysctl_data;
    Function *write;
    Function *read;
    Function *show;
    Value *helper;
    TypeSet *pptr;
    TypeSet *pobj;
    Type2ChkInst *pobj2inst;
    ValueSet *gpptr;
    ValueSet *gpobj;
    Value2ChkInst *gpobj2inst;
    InstructionSet *palloca;
} pfunc;

class pta : public ModulePass
{
    private:
        virtual bool runOnModule(Module&) override;
        virtual bool doInitialization(Module&) override;
        virtual bool doFinalization(Module&) override;
        bool ptaPass(Module&);
        bool is_skip_func(Function *);
        bool is_asm_user(Value *v);
        bool is_skip_type(Type *ty);
        bool get_string(Value *v, StringRef *str);
        StringRef get_func_name(StringRef fname);
        Indices *get_indices(Indices idx);
        Type *findCondType(Instruction*, bool*);
        Type *findPrivType(Value*);
        Type *findPrivType(BasicBlock*, bool*);
        BasicBlockSet *findErrorBB(Function *func, int op);
        bool isInterestingFunc(Function *func);

        bool is_file_line(std::string line);
        bool is_perm_func(StringRef);
        bool is_object_type(Type*);

        //void initialize_perm_func(std::string, int);

        void process_pta_old(Module &module, int);
        void dump_pta();


        // new pta
        bool collect_interface_handlers();
        void collect_privilege_checks();

        // object types
        bool collect_object_types(Module &);
        void collect_object_types(Function*, StructTypeSet *);
        void collect_object_types(Value*, StructTypeSet *);

        // analysis
        void find_ptypes(pfunc*, Value *, ValueList*, ValueSet*,
                         bool, bool isPtr);
        void backward_find_sty(Value*, ValueSet*, ValueSet*,
                               ValueSet *ldset,
                               ValueList *uselist,
                               ValueSet *callset, 
                               bool isVal=false,
                               std::map<Value*, ValueList*> *ld2ulist=nullptr);
        void backward(Value*, std::set<size_t>*, ValueSet*, ValueSet*, 
                    ValueList *uselist=nullptr, bool recursive=true);
        void forward_load(Value *ubuf, ValueSet *ldset, ValueSet *callset, bool pcheck);
        void forward_store(pfunc*, Value *dat, ValueSet *dstset,
                           ValueSet *callset, Value *data, bool pcheck);
        void sarg_to_pobj(pfunc*, Value*);
        void _sarg_to_pobj(pfunc*, Value*, Indices*);
        void sarg_from_pobj(pfunc *pf, Value *sarg);
        void sret_from_pobj(pfunc *pf);
        StructType *find_gv_cast(Value *gv);
        void find_pchk(Function*, ValueSet*, ValueSet*, ValueSet*);


        bool collect_cred_object(Module &);
        void find_cond_val(Value *, ValueSet *);
        void find_pchk_cond(Module &, ValueSet*);
        void find_pchk_gep(Value*, ValueSet*, ValueSet*, bool);
        void find_pchk_ld(Value*, ValueSet*, bool);
        void find_pchk_obj(Value*, ValueSet*, ValueSet*, ValueSet*);

        Value *get_ctl_data(Value *table); 
        void ubuf_to_pobj(pfunc*, Value*);
        void ubuf_from_pobj(pfunc*, Function *, Value *);
        void forward_store_src(Value *dst, std::set<std::pair<Value*, ValueList*>> *result, ValueSet *callset);
        void find_syscall_args(Function*, ValueSet*);
        void find_priv_stack_func();
        void syscall_to_pobj(Function *func);
        void collect_pid_entry(GlobalVariable*, StringRef);
        void collect_sysctl_entry(GlobalVariable*, StringRef);
        void collect_normalBB(Value*, ValueSet *, ValueSet*);
        void collect_interesting_bb(Value*, ValueSet*,
                                    BasicBlockSet*, BasicBlockSet*falseSet=nullptr, int op=-1);
        void collect_interesting_bb(BasicBlock*, BasicBlock *, ValueSet*, BasicBlockSet*, int op=-1);
        void collect_store(BasicBlockSet*, BasicBlockSet*,
                           ValueSet*, ValueSet*, FunctionSet*);
        void collect_store(Function*, FunctionSet*, ValueSet*,
                           ValueSet*);
        bool pcheck_passed(Value*, ValueList*);


        // util
        bool check_visited(Value*, ValueSet*, ValueList*);
        bool check_visited(Value*, ValueList*, ValueList*);
        void copy_offset(Value*, Indices*);
        void copy_offset(Value*, Value*, int);
        void copy_offset_check(Value*, Value*, int);
        void copy_offset_safe(Value*, Value*);
        void copy_offset_safe(Value*, Value*, int);

        bool has_shift(ValueList *);
        bool can_load(Indices*, ValueList*);
        void push_idx(Value*, int);
        void push_idx(Value *dst, Value *src, int val);
        void push_idx_safe(Value*, Value*, int);
        void pop_idx(Value*);
        //StructType *get_pstr_type(Type*);
        int gep2offset(Instruction*);
        int i8gep2idx(StructType*, int);
        bool is_i8gep(User*);
        void get_global(Instruction *i, TypeSet *, ValueSet* pobj, Type2ChkInst*, Value2ChkInst*);
        bool is_global(Instruction *i);
        bool is_address_space_op(Value*);
        bool is_builtin_container_of(Value*);
        bool is_cmp_func(StringRef);
        bool is_copy_func(StringRef, bool write=true);
        bool is_parse_func(StringRef);
        bool is_proc_parse_func(StringRef);
        //bool is_alloc_func(StringRef);
        bool is_from_alloca(Value*, ValueSet*, ValueList* uselist=nullptr);
        int get_copy_src(Instruction*, bool write=true);
        int get_copy_dst(Instruction*, bool write=true);
        int get_parse_src(Instruction*);
        int get_parse_dst(Instruction*);
        int get_cmp_true(StringRef);
        void dump_backward_sty(ValueSet*, TypeSet*, ValueSet*,
                               InstructionSet *palloca=nullptr,
                               Type2ChkInst *pobj2inst=nullptr, Value2ChkInst *gpobj2inst=nullptr);
         void clear_caches(int);
        void dump_pf(pfunc*);
        int get_copy_size(CallInst*);
        Value *get_object(ValueList*);
        void add_idx(Sty2Idxes &pobj2idx, StructType *o, InstructionSet *iset);

    public:
        static char ID;
        pta() : ModulePass(ID) {};
        virtual StringRef getPassName() const override
        {
                return "pta";
        }
    private:
        LLVMContext *ctx;
        Module *m;
        const DataLayout *DL;

        StructType *taskTy;
        StructType *credTy;
        StructType *inodeTy;
        StructType *nsTy;
        GlobalValue *smack_hooks;
        std::set<Indices*> ind_keys;

        Function2Type f2ty;
        //TypeSet pptr, pobj, pptr_cand, pobj_cand;
        TypeSet pobj1, pobj2, pobj3, pobj_cand1, pobj_cand2, pobj_cand3;
        //StringSet *perm_files[3] = {&perm_file1, &perm_file2, &perm_file3};
        TypeSet *pobj[3] = {&pobj1, &pobj2, &pobj3};
        TypeSet *pobj_cand[3] = {&pobj_cand1, &pobj_cand2, &pobj_cand3};
        StringSet cmp_funcs, copy_funcs, parse_funcs, alloc_funcs, 
                  proc_parse_funcs, perm_funcs;


        // pta
        std::unordered_set<pfunc*> proc_funcs, sysfs_funcs, syscall_funcs;
        std::map<Value*, Indices*> val2off;
        ValueSet pta_err;
        bool debug=false;

        BasicBlockSet normalBB;
        std::map<BasicBlock*, InstructionSet*> normalBB2Inst;
        std::map<size_t, ValueSet*> arg2dset, arg2sset;
        std::set<size_t> argset_ld, argset_st;
        ValueSet checked, unchecked, from_alloca;
        StructTypeSet objs;
        std::map<Value*, ValueSet*> obj2strdst;
        ValueSet priv_vals;

        StructTypeSet pchk_type, pchk_ptr_type;
        ValueSet pchk_gobj, pchk_gptr;
        ValueSet pchk_cond;
        
};

#endif // __PTA_H_
