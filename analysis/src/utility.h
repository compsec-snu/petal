/*
 * utilities to make your life easier
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#ifndef _UTILITY_
#define _UTILITY_

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "commontypes.h"
#include "simple_set.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

int use_parent_func_arg_deep(Value* v, Function* f);
Instruction* GetNextInstruction(Instruction* i);
Instruction* GetNextNonPHIInstruction(Instruction* i);
Function* get_callee_function_direct(Instruction* i);
StringRef get_callee_function_name(Instruction* i);
InstructionSet get_user_instruction(Value*);
StructType* find_assignment_to_struct_type(Value*, Indices&, ValueSet&, InstructionSet&);
void get_callsite_inst(Value*, CallInstSet&);
bool has_function_pointer_type(Type*);

StructType* identify_ld_bcst_struct(Value*);

InstructionSet get_load_from_gep(Value*, InstFuncMap&);

void get_gep_indicies(GetElementPtrInst*, Indices&);
Value* get_value_from_composit(Value*, Indices&);

void add_function_to_dmi(Function*, StructType*, Indices&, DMInterface&);
FunctionSet* dmi_exists(StructType*, Indices&, DMInterface&);
bool dmi_type_exists(StructType*, DMInterface&);

bool function_has_gv_initcall_use(Function*);
void str_truncate_dot_number(std::string&);

//bool is_skip_struct(StringRef);
bool is_using_function_ptr(Function*);
bool is_address_taken(Function* f);
bool is_tracepoint_func(Value*, InstructionSet& dummyCE);
bool is_container_of(Value*, InstFuncMap&);
Type *stripPointerType(Type*);

extern Instruction* x_dbg_ins;
extern std::list<int> x_dbg_idx;

void dump_callstack(InstructionList&);
void dump_dbgstk(InstructionList&);
void dump_gdblst(ValueList&);
/*
 * dump a path consisted of Instructions in the list
 */
void dump_a_path(InstructionList&);

////////////////////////////////////////////////////////////////////////////////
//some interesting list is also defined as global
extern SimpleSet* skip_vars;
extern SimpleSet* crit_syms;
extern SimpleSet* kernel_api;

extern SimpleSet* crit_structs;
extern SimpleSet *link_structs;
extern SimpleSet* alloc_funcs;
extern SimpleSet* free_funcs;
extern SimpleSet* skip_funcs;
extern SimpleSet* mte_skip_funcs;
extern SimpleSet *list_structs;
extern SimpleSet *kernel_files;
SimpleSet *load_list(StringRef knob_list);
void initialize_crit_struct(StringRef knob_crit_sturct_list);
void initialize_link_struct(StringRef knob_link_sturct_list);
void initialize_alloc_func(StringRef knob_alloc_func_list);
void initialize_free_func(StringRef knob_free_func_list);
void initialize_skip_func(StringRef knob_skip_func_list, StringRef knob_mte_skip_func_list);
void initialize_skip_funcset(Module&, FunctionSet*);
void initialize_list_struct(StringRef knob_list_struct_list);
void initialize_function_code(Module&, StringRef);
void initialize_struct_size(Module&, StringRef);
void initialize_skip_func_indcall(Module &);
void initialize_kernel_files(StringRef knob_kernel_file_list);
bool get_indirect_call_dest(Instruction *ii, FunctionSet &funcs);
bool is_same_func(Function*, Function*);
bool is_same_struct(StructType *, StructType *);
bool is_same_struct_ptr(Type *, Type *);
bool is_same_type(Type*,Type*);
bool is_list_ptr(Type*);
bool is_alloc_inst(Value*);
bool is_alloc_inst(Value*, ValueSet*);
bool has_type(TypeSet* ts, Type *ty);
bool is_same_uselist(ValueList*, ValueList*);
bool is_redundant(VLSet*, ValueList*);
Type *get_element_type(StructType*, Indices*);
Function* get_func_from_code(int);
int get_struct_size(StructType *);
int get_inst_count(Function*, Instruction*);
void dump_func(raw_fd_ostream &out, Function *func);
void dump_inst(raw_fd_ostream &out, Instruction *i);
int get_op_count(Function* func, Instruction* ii, unsigned opNum = 0);
InstructionSet *get_inst(Value*, bool = false, Function* = nullptr);
InstructionSet *detach_constant_expr(ConstantExpr*, Function*, CE2FISet&);
bool detach_constant_expr_recur(ConstantExpr*, Value*, Instruction*, CE2FISet&);
bool bb_can_reach(BasicBlock *s, BasicBlock *d);
bool bb_can_reach(BasicBlock *s, BasicBlock *d, BasicBlockSet *visited);
bool is_asm(Value*);
bool is_asm_get_current(Value*);
bool is_asm_load(Value*, int op=-1);
bool is_asm_store(Value*, int op=-1);
bool is_asm_access(Value*, int);
int get_asm_addr(Value*);
int get_asm_ldval(Value*);
int get_asm_stval(Value*);
bool is_use_def(User*, Value*);
bool is_use_def_recur(User*, Value*, ValueSet*);
std::string get_func_name(std::string);
std::string get_struct_name(std::string);
void dump_uselist(Function *func, ValueList &list, InstFuncMap&);
void dump_list(Function *, ValueList&);
void dump_use(llvm::raw_fd_ostream&, Value*);
void dump_uselist(llvm::raw_fd_ostream&, ValueList*);
void dump_indices(llvm::raw_fd_ostream&, Indices&);
void print_error(StringRef, Function* = nullptr, StringRef = "");
void print_report(StringRef, Function* = nullptr, StringRef = "");
void print_debug(StringRef, Function* = nullptr, StringRef = "");
void print_error(Value*, Function* = nullptr, StringRef = "");
void print_report(Value*, Function* = nullptr, StringRef = "");
void print_debug(Value*, StringRef);
void print_debug(Value*, Function* = nullptr, StringRef = "");
void print_error(Type*, Function* = nullptr, StringRef = "");
void print_error(Value*, StringRef);
void print_report(Type*, Function* = nullptr, StringRef = "");
void print_debug(Type*, Function* = nullptr, StringRef = "");

bool is_err_check(Value *v);
ICmpInst *get_err_check(Value *ii);
bool is_err_bb(BasicBlock *prev, BasicBlock *cur);
bool is_err_phi(Value *op, BasicBlock *dst);


bool is_alloc(Value *v);
bool is_builtin_container_of(Instruction *);

StructType *get_pstr_type(Module*, Type*);
Type *get_type(Module*, Type*);
bool is_list_struct(Type *ty);
void backward_find_sty(Value *_v, ValueSet *visited,
                            ValueSet *srcset, ValueSet *ldset=nullptr,
                            ValueSet *callset=nullptr);
void backward(Value *_v, ValueSet *visited, ValueSet *srcset,
              ValueSet *callset=nullptr, ValueList *uselist=nullptr, bool (*skip_func)(Value*) = nullptr);
bool is_err_ptr(Value *v);
bool is_global(Value *v, ValueSet *gvset);
bool is_global(Value *v, ValueSet *gvset, std::set<unsigned> *skipset);
bool has_ops_call(Value *v);
void collect_forward(Value*, unsigned, int, std::set<unsigned>*, ValueSet*,
             UseSet *visited=nullptr, std::set<StringRef> *prefixes=nullptr);
int collect_backward(Value*, unsigned, std::set<unsigned>*, ValueSet*,
             UseSet *visited=nullptr);
void get_call_dest(Value*, FunctionSet &);
void try_get_security_hook(Instruction *, FunctionSet* );
void try_get_notifier_call(Instruction*, FunctionSet*);

inline bool is_alloc_function(const std::string& str)
{
    return alloc_funcs->exists_ignore_dot_number(str);
}
inline bool is_free_function(const std::string& str)
{
    return free_funcs->exists_ignore_dot_number(str);
}
inline bool is_skip_function(const std::string& str)
{
    if (str.find("llvm.") == 0)
        return true;

    return skip_funcs->exists_ignore_dot_number(str);
}
inline bool is_mte_skip_function(const std::string& str)
{
    return mte_skip_funcs->exists_ignore_dot_number(str);
}

inline bool is_init(Value *v) {
    if (isa<Function>(v)) {
        if (auto prefix = cast<Function>(v)->getSectionPrefix())
            if (prefix->startswith(".init"))
                return true;
        return false;
    }
    if (!isa<Instruction>(v))
        return false;
    if (auto fi = cast<Instruction>(v)->getFunction()) {
        if (auto prefix = fi->getSectionPrefix()) {
            if (prefix->startswith(".init"))
                return true;
        }
    }
    return false;
}

#endif //_UTILITY_
