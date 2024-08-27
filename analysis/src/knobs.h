#ifndef __KNOBS_H_
#define __KNOBS_H_
#include "llvm/Support/CommandLine.h"
using namespace llvm;

extern cl::opt<std::string> knob_alloc_func_list;
extern cl::opt<std::string> knob_free_func_list;
extern cl::opt<std::string> knob_ptr_list;
extern cl::opt<std::string> knob_obj_list;
extern cl::opt<std::string> knob_gobj_list;
extern cl::opt<std::string> knob_gptr_list;
extern cl::opt<std::string> knob_alloca_list;
extern cl::opt<std::string> knob_pstack_list;
extern cl::opt<std::string> knob_mode;


extern cl::opt<std::string> knob_dump_path;
extern cl::opt<bool> knob_private_link;
extern cl::opt<bool> knob_dump;
extern cl::opt<bool> knob_debug;
extern cl::opt<bool> knob_object;
extern cl::opt<bool> knob_cred;
extern cl::opt<bool> knob_dump_pptr;

extern cl::opt<std::string> knob_object_list;
extern cl::opt<std::string> knob_skip_func_list;
extern cl::opt<std::string> knob_mte_skip_func_list;
extern cl::opt<bool> knob_mte;
extern cl::opt<bool> knob_internal;
extern cl::opt<bool> knob_test;

extern cl::opt<std::string> knob_kernel_file_list;

extern cl::opt<bool> knob_indcall_kinit;

extern cl::opt<bool> knob_indcall_nkinit;

extern cl::opt<bool> knob_indcall_kmi;

extern cl::opt<bool> knob_indcall_dkmi;

extern cl::opt<bool> knob_indcall_cvf;

/*extern cl::opt<string> knob_skip_func_list("skipfun",
        cl::desc("non-critical function list"),
        cl::init("skip.fun"));
*/

extern cl::opt<std::string> knob_func_code_list;

extern cl::opt<std::string> knob_skip_var_list;

extern cl::opt<std::string> knob_cap_function_list;

extern cl::opt<std::string> knob_lsm_function_list;

extern cl::opt<std::string> knob_crit_symbol;

extern cl::opt<std::string> knob_kernel_api;

extern cl::opt<bool> knob_dump_good_path;

extern cl::opt<bool> knob_dump_bad_path;

extern cl::opt<bool> knob_dump_ignore_path;

extern cl::opt<bool> knob_warn_indcall_during_kinit;

extern cl::opt<unsigned int> knob_fwd_depth;

extern cl::opt<unsigned int> knob_bwd_depth;

extern cl::opt<unsigned int> knob_mt;

extern cl::opt<std::string> knob_metaspec;

#endif // __KNOBS_H_
