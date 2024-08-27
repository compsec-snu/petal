/*
 * this file is part of cap checker
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */
#ifndef _CAPCHK_INTERNAL_H_
#define _CAPCHK_INTERNAL_H_

[[maybe_unused]]
static const char *_builtin_crit_struct [] =
{
    "struct.task_struct",
    "struct.cred",
};

#define BUILTIN_CHILD_LIST_SIZE 10
[[maybe_unused]]
static const char *_builtin_child_struct [2][10] =
{
{"struct.thread_info",
 "struct.sched_entity",
 "struct.sched_rt_entity",
 "struct.sched_dl_entity",
 "struct.seccomp",
 "struct.wake_q_node",
 "struct.thread_struct",
 "struct.ptrauth_keys",
 "struct.restart_block",
 "struct.user_fpsimd_state",

 //"struct.fpu",
 //"union.fpregs_state",
 //"struct.xregs_state",
 //"struct.xstate_header",
},
{},
};

#define MAX_EQUIVALENT_STRUCT 12
[[maybe_unused]]
static const char* _builtin_equivalent_src[] =
{
"struct.k_itimer",
"struct.k_itimer",
"struct.kiocb",
"struct.ww_mutex",
"struct.task_struct",
"struct.css_set",
"struct.pid",
"struct.rcu_node",
"struct.rt_rq",
"struct.rq",
"struct.bdi_writeback",
"struct.completion",
};

#define MAX_IDX_NUM 10
#define END_IDX -2
[[maybe_unused]]
static const int _builtin_equivalent_idx[][MAX_IDX_NUM] =
{
{0, 15, 0, 0, 1, 0, 0, 1, END_IDX},
{0, 13, END_IDX},
{0, END_IDX},
{0, END_IDX},
{0, 28, END_IDX},
{0, 5, END_IDX}, /* tasks (5) mg_tasks (6) dying_tasks (7) */
{0, 2, -1, END_IDX},
{0, 19, END_IDX},
{0, 0, 1, -1, 1, END_IDX},
{0, 14, 7, END_IDX},
{0, 4, END_IDX}, // bdi_writeback->b_io
{0, 1, 1, END_IDX},
};

[[maybe_unused]]
static const char *_builtin_equivalent_dest[] =
{
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.inode",
"struct.wait_queue_entry",
};

#define MAX_IGNORE_FIELD 37
[[maybe_unused]]
static const char *_builtin_ignore_src[] = {
"struct.bio",
//"struct.task_struct",
//"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
//"struct.task_struct",
//"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
"struct.task_struct",
//"struct.pid",
"struct.perf_event",
"struct.perf_event",
"struct.futex_pi_state",
"struct.futex_pi_state",
"struct.sigqueue",
"struct.sigqueue",
"struct.task_struct",
"struct.task_struct",
"union.acpi_operand_object",
"union.acpi_object",
"union.acpi_object",
"struct.acpi_object_mutex",
"struct.acpi_object_region_field",
"struct.sigaltstack",

"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.seq_file",
};

[[maybe_unused]]
static const int _builtin_ignore_idx[][MAX_IDX_NUM] =
{
{0, 11, END_IDX},
//{0, 69, -1, END_IDX}, // pid_links
//{0, 69, -1, 1, END_IDX},
{0, 93, 0, END_IDX}, // sysvshm.shm_clist
{0, 93, 1, END_IDX}, 
{0, 102, END_IDX}, // pending.list
{0, 102, 0, 1, END_IDX},
{0, 102, 1, 0, 1, END_IDX}, // pending.signal.sig
//{0, 137, END_IDX}, // cg_list
//{0, 137, 1, END_IDX}, // cg_list
{0, 140, END_IDX}, // pi_state_list
{0, 140, 1, END_IDX}, //pi_state_list
{0, 146, END_IDX}, // perf_event_list
{0, 146, 1, END_IDX},
//{0, 2, -1, END_IDX}, // pid.tasks
{0, 36, END_IDX}, // perf_event.owner_entry
{0, 36, 1, END_IDX},
{0, 0, 0, END_IDX}, // futex_pi_state.list
{0, 0, 1, END_IDX},
{0, 0, 0, END_IDX}, // sigqueue.list
{0, 0, 1, END_IDX},
{0, 3, 0, END_IDX}, // thread_node
{0, 3, 1, END_IDX},
{0, 0, 8, END_IDX}, // acpi_operand_object
{0, 0, 1, END_IDX},
{0, 0, 2, END_IDX},
{0, 8, END_IDX},
{0, 14, END_IDX},
{0, 2, END_IDX},// sigaltstack->ss_size

{0, 45, END_IDX}, // inode->i_devices
{0, 45, 1, END_IDX},
{0, 28, END_IDX}, // inode->i_io_list
{0, 28, 1, END_IDX},
{0, 35, END_IDX}, // inode->i_wb_list
{0, 35, 1, END_IDX},
{0, 33, END_IDX}, // inode->i_lru
{0, 33, 1, END_IDX},
{0, 44, 13, END_IDX}, // inode->i_data.private_list
{0, 44, 13, 1, END_IDX},
{0, 34, END_IDX}, // inode->i_sb_list
{0, 34, 1, END_IDX},
{0, 12, END_IDX}, // seq_file->private

};
// {0, 59, END_IDX} // sb->s_inodes_wb
// {0, 57, END_IDX} // sb->inodes
// {0, 3, END_IDX} // bdi_writeback->b_dirty
// {0, 5, END_IDX} // bdi_writeback->more_io
// {0, 6, END_IDX} // bdi_writeback->b_dirty_time
// {0, 13, END_IDX} // address_space->private_list
// {0, 14, END_IDX} // address_space->private_data
//

#define LINK_STRUCT_SIZE 2
static const char *_builtin_link_struct[] {
    "struct.wait_queue_head",
    "struct.wait_queue_entry",
};

#define MAX_VOID_ARG 1
[[maybe_unused]]
static const char *_builtin_void_type[] = {
"struct.task_struct",
"struct.task_struct",
};

[[maybe_unused]]
static const char *_builtin_void_func[] =
{
"child_wait_callback",
};

[[maybe_unused]]
static const int _builtin_void_arg[] =
{
3,
};


[[maybe_unused]]
static const char *_builtin_void_field [] =
{
    "struct.inode-46"
};
[[maybe_unused]]
static const char *_builtin_alloc_function [] =
{
    "kmem_cache_alloc",
    "kmem_cache_alloc_node",

};
[[maybe_unused]]
static const char *_builtin_free_function [] =
{
    "kfree",
    "kmem_cache_free",
    "devm_kfree",
    //"free_percpu",
};
[[maybe_unused]]
static const char *_builtin_skip_function [] =
{
    "llvm.memcpy",
    "llvm.memset",
    "malloc",
    "free",
    "kmem_cache_free"
};

#define BUILTIN_NOSKIP_SIZE 2
[[maybe_unused]]
static const char *_builtin_noskip_function [] = 
{
"rb_insert_color",
"call_rcu",
};
[[maybe_unused]]
static const int _builtin_noskip_argument [] = 
{
0,
0,
};

#define BUILTIN_LIST_STRUCTURE_SIZE 18
[[maybe_unused]]
static const char *_builtin_list_struct [] =
{
    "struct.list_head", // 0, 1
    "struct.hlist_node", // 0, 1
    "struct.hlist_head",
    "struct.llist_node", // 0
    "struct.rb_node", // 1, 2
    "struct.rb_root_cached", //0,1
    "struct.wake_q_node", // 0
    "struct.plist_node", // 1, 2
    "struct.sysv_shm", // 0, 1
    "struct.llist_head", // 0
    "struct.callback_head",
    "struct.rb_root",
    "struct.hlist_bl_node",
    "struct.list_lru_one",
    "struct.list_lru_memcg",
    "struct.list_lru_node",
    "struct.list_lru",
    "struct.__call_single_data",
};

/*
[[maybe_unused]]
static const char *_builtin_mte_struct [] =
{
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
"struct.inode",
};
static const int _builtin_mte_idx[][MAX_IDX_NUM] =
{
{0, 0, END_IDX},
{0, 1, END_IDX},
{0, 2, END_IDX},
{0, 3, END_IDX},
{0, 4, END_IDX},
}

*/
/*
 * check functions
 */

struct str2int
{
    std::string k;
    int v;
};

#define BUILTIN_CAP_FUNC_LIST_SIZE 2
[[maybe_unused]]
static const struct str2int _builtin_cap_functions [] = 
{
    {"capable", 0},
    {"ns_capable", 1}
};

/*
 * kernel start function
 */
[[maybe_unused]]
static const char* _builtin_kernel_start_functions [] = 
{
    "start_kernel",
    "x86_64_start_kernel",
};


/*
 * syscall prefix
 */
[[maybe_unused]]
static const char* _builtin_syscall_prefix [] =
{
    "compat_SyS_",
    "compat_sys_",
    "SyS_",
    "sys_",
    "__x64_sys",
    "__x32_compat_sys_",
    "__ia32_sys_",
    "__ia32_compat_sys_"
};


/*
 * builtin list of skip variables
 */
[[maybe_unused]]
static const char* _builtin_skip_var [] = 
{
    "jiffies",
    "nr_cpu_ids",
    "nr_irqs",
    "nr_threads",
    "vmemmap_base",
    "page_offset_base",
};

/*
 * builtin list of skip functions
 */
[[maybe_unused]]
static const char* _builtin_skip_functions [] = 
{
    //may operate on wrong source?
    "add_taint",
    "__mutex_init",
    "mutex_lock",
    "mutex_unlock",
    "schedule",
    "_cond_resched",
    "printk",
    "__kmalloc",
    "_copy_to_user",
    "_do_fork",
    "__memcpy",
    "strncmp",
    "strlen",
    "strim",
    "strchr",
    "strcmp",
    "strcpy",
    "strncat",
    "strlcpy",
    "strscpy",
    "strsep",
    "strndup_user",
    "strnlen_user",
    "sscanf",
    "snprintf",
    "scnprintf",
    "sort",
    "prandom_u32",
    "memchr",
    "memcmp",
    "memset",
    "memmove",
    "skip_spaces",
    "kfree",
    "kmalloc",
    "kstrdup",
    "kstrtoull",
    "kstrtouint",
    "kstrtoint",
    "kstrtobool",
    "strncpy_from_user",
    "kstrtoul_from_user",
    "__msecs_to_jiffies",
    "drm_printk",
    "cpumask_next_and",
    "cpumask_next",
    "dump_stack",//break KASLR here?
    "___ratelimit",
    "simple_strtoull",
    "simple_strtoul",
    "dec_ucount",
    "inc_ucount",
    "jiffies_to_msecs",
    "__warn_printk",//break KASLR here?
    "arch_release_task_struct",
    "do_syscall_64",//syscall entry point
    "do_fast_syscall_32",
    "do_int80_syscall_32",
    "complete",
    "__wake_up",
    "mutex_trylock",
    "finish_wait",
    "__init_waitqueue_head",
    "complete",
    "mutex_lock_interruptible",
    "up_write",
    "up_read",
    "down_write_trylock",
    "down_write",
    "down_read",
    "find_vma",
    "vzalloc",
    "vmalloc",
    "vfree",
    "vmalloc_to_page",
    "__vmalloc",
    "kfree_call_rcu",
    "kvfree",
    "krealloc",
    "_copy_from_user",
    "__free_pages",
    "__put_page",
    "kvmalloc_node",
    "free_percpu",
    "__alloc_percpu",
    "get_user_pages",
    "__mm_populate",
    "dput",
    "d_path",
    "iput",
    "inode_dio_wait",
    "current_time",
    "is_bad_inode",
    "__fdget",
    "mntput",
    "mntget",
    "seq_puts",
    "seq_putc",
    "seq_printf",
    "blkdev_put",
    "blkdev_get",
    "bdget",
    "bdput",
    "bdgrab",
    "thaw_bdev",
    "__brelse",
    "nla_parse",
    "dev_warn",
    "dev_printk",
    "dev_notice",
    "dev_alert",
    "__put_task_struct",
    "__set_current_blocked",
    "copy_siginfo_to_user",
    "fpu__clear",
    "fpu__alloc_mathframe",
    "copy_fpstate_to_sigframe",
    "ia32_setup_frame",
    "ia32_setup_rt_frame",
    "mmput",
    "setup_sigcontext",
    "queue_work_on",
    "__request_module",
    "__module_put_and_exit",
    "__get_free_pages",
    "__put_page",
    "__wake_up",
    "__init_waitqueue_head",
    "_raw_write_unlock_bh",
    "_raw_write_lock_irqsave",
    "_raw_write_lock_irq",
    "_raw_write_lock_bh",
    "_raw_write_lock",
    "_raw_spin_unlock_irqrestore",
    "_raw_spin_unlock_bh",
    "_raw_spin_lock_irqsave",
    "_raw_spin_lock_irq",
    "_raw_spin_lock_bh",
    "_raw_spin_lock",
    "_raw_read_unlock_irqrestore",
    "_raw_read_lock_irqsave",
    "__put_task_struct"
};

/*
 * builtin list of interesting keywords
 */
[[maybe_unused]]
static const char* interesting_keyword [] = 
{
    "SyS",
    "sys",
    "open",
    "release",
    "lseek",
    "read",
    "write",
    "sync",
    "ioctl",
};

/*
 * sysfs stuff
 */
#define BUILTIN_INTERESTING_TYPE_WORD_LIST_SIZE 64
[[maybe_unused]]
static const char* _builtin_interesting_type_word [] = 
{
    "struct.file_operations",
    "struct.net_proto_family",
    "struct.sysfs_ops",
    "struct.device_attribute",
    "struct.bus_attribute",
    "struct.driver_attribute",
    "struct.class_attribute",
    "struct.bin_attribute",
    "struct.efivar_attribute",
    "struct.kobj_attribute",
    "struct.brport_attribute",
    "struct.slave_attribute",
    "struct.batadv_attribute",
    "struct.configfs_attribute",
    "struct.configfs_bin_attribute",
    "struct.ctl_info_attribute",
    "struct.edac_dev_sysfs_attribute",
    "struct.edac_dev_sysfs_block_attribute",
    "struct.edac_pci_dev_attribute",
    "struct.edd_attribute",
    "struct.instance_attribute",
    "struct.module_attribute",
    "struct.pci_slot_attribute",
    "struct.psmouse_attribute",
    "struct.sde_attribute",
    "struct.display_attribute",
    "struct.dmi_sysfs_mapped_attribute",
    "struct.dump_attribute",
    "struct.elog_attribute",
    "struct.ep_attribute",
    "struct.esre_attribute",
    "struct.fw_cfg_sysfs_attribute",
    "struct.gb_audio_manager_module_attribute",
    "struct.hw_stats_attribute",
    "struct.instance_attribute",
    "struct.iommu_group_attribute",
    "struct.manager_attribute",
    "struct.map_attribute",
    "struct.mdev_type_attribute",
    "struct.memmap_attribute",
    "struct.netdev_queue_attribute",
    "struct.overlay_attribute",
    "struct.pdcspath_attribute",
    "struct.port_attribute",
    "struct.qpn_attribute",
    "struct.rx_queue_attribute",
    "struct.slab_attribute",
    "struct.vmbus_chan_attribute",
    "struct.widget_attribute",
    "struct.proc_ns_operations",
    "struct.inode_operations",
    "struct.nfs_rpc_ops",
    "struct.xattr_handler",
    "struct.linux_binfmt",
    "struct.ieee80211_ops",
    "struct.drm_i915_private",
    "struct.drm_panel_funcs",
    "struct.input_dev",
    "struct.simple_attr",
    "struct.tg3",
    "struct.uhci_hcd",
    "struct.uart_port",
    "struct.scsi_device_handler",
    "struct.hid_device",
};

/*
 * some common struct type to skip
 */
#define BUILDIN_STRUCT_TO_SKIP 16
[[maybe_unused]]
static const char* _builtin_struct_to_skip [] = 
{
    "struct.list_head",
    "struct.raw_spinlock",
    "struct.hlist_node",
    "struct.wait_queue_head",
    "struct.tracepoint_func",
    "struct.address_space",
    "struct.dentry",
    "struct.inode",
    "struct.file",
    "struct.super_block",
    "struct.seq_file",
    "struct.mount",
    "struct.mountpoint",
    "struct.page",
    "struct.sk_buff",
    "struct.kernel_symbol",
};



#endif//_CAPCHK_INTERNAL_H_

