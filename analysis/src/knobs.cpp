#include "knobs.h"

cl::opt<std::string> knob_alloc_func_list("alloclist",
    cl::desc("Allocation function list for usage analysis"),
    cl::init("alloc.func"));
cl::opt<std::string> knob_free_func_list("freelist",
    cl::desc("Free function list for usage analysis"),
    cl::init("free.func"));
cl::opt<std::string> knob_obj_list("objlist",
                                   cl::desc("KDFI Object List"),
                                   cl::init("crit.obj"));
cl::opt<std::string> knob_ptr_list("ptrlist",
                                   cl::desc("KDFI Pointer List"),
                                   cl::init("crit.ptr"));
cl::opt<std::string> knob_gobj_list("gobjlist",
                                     cl::desc("KDFI Global Object List"),
                                     cl::init("crit.gobj"));

cl::opt<std::string> knob_gptr_list("gptrlist",
                                     cl::desc("KDFI Global Pointer List"),
                                     cl::init("crit.gptr"));
cl::opt<std::string> knob_alloca_list("allocalist",
                                     cl::desc("KDFI Palloca List"),
                                     cl::init("crit.alloca"));
cl::opt<std::string> knob_pstack_list("pstacklist",
                                     cl::desc("KDFI Priv Stack Function List"),
                                     cl::init("pstack.func"));
cl::opt<std::string> knob_mode("mode",
                                cl::desc("KDFI analysis mode"),
                                cl::init(""));
cl::opt<bool> knob_object("object",
                        cl::desc("Collect kernel object types"),
                        cl::init(false));

cl::opt<bool> knob_cred("cred",
                        cl::desc("Collect cred objects based on permission check"),
                        cl::init(false));

cl::opt<bool> knob_dump_pptr("pptr",
                        cl::desc("Dump pointer access"),
                        cl::init(false));

cl::opt<std::string> knob_object_list("kobjlist",
    cl::desc("Kernel Object List"),
    cl::init("obj.struct"));

cl::opt<std::string> knob_dump_path("dump",
    cl::desc("dump file path"),
    cl::init(""));
cl::opt<bool> knob_private_link("private",
                                cl::desc("private"),
                                cl::init(false));

cl::opt<bool> knob_dump("may_dump",
                         cl::desc("Dump"),
                         cl::init(true));
cl::opt<bool> knob_debug("debug",
                         cl::desc("Debug"),
                         cl::init(false));
cl::opt<std::string> knob_skip_func_list("skiplist",
                                           cl::desc("Function to skip analysis"),
                                           cl::init("skip.func.ppac"));

cl::opt<std::string> knob_mte_skip_func_list("mteskiplist",
                                           cl::desc("Function to skip analysis"),
                                           cl::init(""));
cl::opt<bool> knob_mte("mte",
                        cl::desc("mte analysis only"),
                        cl::init(false));
cl::opt<bool> knob_internal("internal",
                        cl::desc("internal function dump only"),
                        cl::init(false));

cl::opt<bool> knob_test("test",
                        cl::desc("test (no embedded child for now)"),
                        cl::init(false));

cl::opt<std::string> knob_kernel_file_list("kernel_file",
                                           cl::desc("kernel files to find types"),
                                           cl::init(""));


cl::opt<bool> knob_indcall_kinit("kinit",
        cl::desc("print kernel init functions - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_indcall_nkinit("nkinit",
        cl::desc("print kernel non init functions - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_indcall_kmi("kmi",
        cl::desc("print kernel interface - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_indcall_dkmi("dkmi",
        cl::desc("print dkmi result - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_indcall_cvf("cvf",
        cl::desc("complex value flow analysis - disabled by default"),
        cl::init(false));

/*cl::opt<std::string> knob_skip_func_list("skipfun",
        cl::desc("non-critical function list"),
        cl::init("skip.fun"));
*/
cl::opt<std::string> knob_func_code_list("funccode",
        cl::desc("function code generated from indirect call analysis\n"),
        cl::init("func.code"));

cl::opt<std::string> knob_skip_var_list("skipvar",
        cl::desc("non-critical variable name list"),
        cl::init("skip.var"));

cl::opt<std::string> knob_cap_function_list("capfunc",
        cl::desc("capability check function name list"),
        cl::init("cap.func"));

cl::opt<std::string> knob_lsm_function_list("lsmhook",
        cl::desc("lsm hook function name list"),
        cl::init("lsm.hook"));

cl::opt<std::string> knob_crit_symbol("critsym",
        cl::desc("list of symbols to be treated as critical and ignore others"),
        cl::init("crit.sym"));

cl::opt<std::string> knob_kernel_api("kapi",
        cl::desc("kernel api function list"),
        cl::init("kernel.api"));

cl::opt<bool> knob_dump_good_path("prt-good",
        cl::desc("print good path - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_dump_bad_path("prt-bad",
        cl::desc("print bad path - enabled by default"),
        cl::init(true));

cl::opt<bool> knob_dump_ignore_path("prt-ign",
        cl::desc("print ignored path - disabled by default"),
        cl::init(false));

cl::opt<bool> knob_warn_indcall_during_kinit("wcapchk-kinit",
        cl::desc("warn capability check during kernel boot process - disabled by default"),
        cl::init(false));

cl::opt<unsigned int> knob_fwd_depth("fwd-depth",
        cl::desc("forward search max depth - default 100"),
        cl::init(100));

cl::opt<unsigned int> knob_bwd_depth("bwd-depth",
        cl::desc("backward search max depth - default 100"),
        cl::init(100));

cl::opt<unsigned int> knob_mt("mt",
        cl::desc("Multi-threading, number of threads - default 1"),
        cl::init(1));

// metaspec
cl::opt<std::string> knob_metaspec("metainput",
                                   cl::desc("metaspec input"),
                                   cl::init("cap.metaspec"));
