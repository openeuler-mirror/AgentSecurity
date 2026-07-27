/*
 * sandbox_file.c
 *
 * File runtime authorization via kretprobes
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * KERNEL VERSION DEPENDENCIES:
 *
 * All 13 kretprobes in kprobes[] (line 552) depend on symbol names of
 * internal kernel functions.  Most are static (do_sys_openat2, do_mknodat,
 * hook_file_open, hook_file_truncate, all hook_path_*), so their symbols
 * are only present in kallsyms when CONFIG_KALLSYMS_ALL=y.
 *
 * See the kprobes[] array for the exact symbol list.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/thread_info.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <asm/syscall.h>
#include <uapi/linux/landlock.h>

#include "sandbox.h"
#include "sandbox_net.h"
#include "sandbox_landlock.h"
#include "sandbox_file.h"

static bool trace_all;
module_param_named(trace_all, trace_all, bool, 0644);
MODULE_PARM_DESC(trace_all, "Verbose per-syscall ENTRY/TRACE logging for all processes (default 0)");

static LIST_HEAD(inst_list);
static DEFINE_SPINLOCK(inst_lock);

/**
 * inst_find_by_pidns - Lookup sandbox_instance by pid namespace
 * @pid: PID of the blocked task (for debug / future use)
 * @pid_ns: pid namespace of the blocked task
 *
 * Called from kretprobe handlers to find the sandbox instance for the
 * current process.  Fork children inherit the parent's pid namespace,
 * so matching by pid_ns instead of PID supports arbitrary-depth fork.
 *
 * Two-phase lookup:
 *   Phase 1 — direct ns match (common case: fork shares parent's pid_ns)
 *   Phase 2 — walk pid_ns->parent chain (nested pid namespaces)
 *
 * Context: any (kretprobe handler, may be atomic)
 * Return: pointer to sandbox_instance, or NULL if not found.
 */
static struct sandbox_instance *inst_find_by_pidns(pid_t pid,
						   const struct pid_namespace *pid_ns)
{
	struct sandbox_instance *inst;
	unsigned long flags;

	if (!pid_ns)
		return NULL;

	spin_lock_irqsave(&inst_lock, flags);

	/* Phase 1: direct ns match — fork children share parent's pid_ns */
	list_for_each_entry(inst, &inst_list, list_node)
		if (inst->sandbox_pid_ns && pid_ns == inst->sandbox_pid_ns) {
			spin_unlock_irqrestore(&inst_lock, flags);
			return inst;
		}

	/* Phase 2: walk parent chain — for nested ns (CLONE_NEWPID inside sandbox) */
	{
		const struct pid_namespace *ns = pid_ns->parent;
		while (ns && ns->level > 0) {
			list_for_each_entry(inst, &inst_list, list_node)
				if (inst->sandbox_pid_ns && ns == inst->sandbox_pid_ns) {
					spin_unlock_irqrestore(&inst_lock, flags);
					return inst;
				}
			ns = ns->parent;
		}
	}

	spin_unlock_irqrestore(&inst_lock, flags);
	return NULL;
}

/* ====================================================================== */
/*  kretprobe infrastructure                                              */
/* ====================================================================== */

struct probe_data {
	enum op_type type;
	/* ABI-neutral syscall arguments (saved in entry, parsed in ret handler) */
	unsigned long fname_ptr;
	unsigned long aux_arg;
	/* hook_file_open fields */
	u64 open_flags;
	bool is_dir;
	/* hook_file_truncate field */
	struct file *file;
};

/*
 * Per-task Landlock handoff state, indexed by pid.  Replaces the shared
 * inst->state.ll_denied / is_dir fields: each sandbox child mutates only its
 * own entry, so concurrent children never clobber each other.
 */
struct blocked_state {
	struct list_head node;
	pid_t  pid;
	bool   landlocked;   /* this task's syscall was denied by Landlock */
	bool   is_dir;       /* denied open target is a directory (hook_file_open only) */
};

/*
 * get_thread_state - Find (or create) the per-task blocked_state for @pid
 * @inst: sandbox instance
 * @pid:  task pid to look up
 *
 * Lock only protects the list find/create; the returned pointer is used
 * directly by the caller.  Safe because a pid entry is only ever touched by
 * its own task (sensor set and executor consume run in the same syscall
 * stack), and distinct tasks have distinct pids.
 *
 * Return: pointer to blocked_state, or NULL on allocation failure.
 */
static struct blocked_state *get_thread_state(struct sandbox_instance *inst, pid_t pid)
{
	struct blocked_state *st;
	unsigned long flags;

	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	list_for_each_entry(st, &inst->state.blocked_flag_list, node) {
		if (st->pid == pid) {
			spin_unlock_irqrestore(&inst->state.blocked_lock, flags);
			return st;
		}
	}
	st = kzalloc(sizeof(*st), GFP_ATOMIC);
	if (st) {
		st->pid = pid;
		list_add_tail(&st->node, &inst->state.blocked_flag_list);
	}
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);
	return st;
}

/**
 * entry_handler_syscall - Set type for a kretprobe entry
 * @ri:  kretprobe instance
 * @regs: CPU registers at function entry
 * @type: op_type for this syscall
 *
 * Called at the end of each entry handler wrapper. The probe_name is obtained
 * from get_kretprobe(ri)->kp.symbol_name in the ret handler, so there's no
 * need to pass it through here.
 *
 * Return: 0 (always)
 */
static int entry_handler_syscall(struct kretprobe_instance *ri, struct pt_regs *regs,
				 enum op_type type)
{
	struct probe_data *data = (struct probe_data *)ri->data;

	data->type = type;
	return 0;
}

static int entry_handler_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;

	data->fname_ptr = func_arg_n(regs, 1);	/* filename (char __user *) */
	data->aux_arg   = func_arg_n(regs, 2);	/* open_how */
	
	if (trace_all)
		pr_info("dyn-sandbox: ENTRY [do_sys_openat2] fname_ptr=0x%lx aux=0x%lx\n",
			data->fname_ptr, data->aux_arg);
	return entry_handler_syscall(ri, regs, OP_OPEN);
}

static int entry_handler_unlink(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct filename *fname = (struct filename *)func_arg_n(regs, 1);

	data->fname_ptr = !IS_ERR_OR_NULL(fname) ? (unsigned long)fname->name : 0;
	return entry_handler_syscall(ri, regs, OP_UNLINK);
}

static int entry_handler_rmdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct filename *fname = (struct filename *)func_arg_n(regs, 1);

	data->fname_ptr = !IS_ERR_OR_NULL(fname) ? (unsigned long)fname->name : 0;
	return entry_handler_syscall(ri, regs, OP_RMDIR);
}

static int entry_handler_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct filename *fname = (struct filename *)func_arg_n(regs, 1);

	data->fname_ptr = !IS_ERR_OR_NULL(fname) ? (unsigned long)fname->name : 0;
	return entry_handler_syscall(ri, regs, OP_MKDIR);
}

static int entry_handler_mknod(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct filename *fname = (struct filename *)func_arg_n(regs, 1);

	data->aux_arg   = func_arg_n(regs, 2);	/* mode */
	data->fname_ptr = !IS_ERR_OR_NULL(fname) ? (unsigned long)fname->name : 0;
	return entry_handler_syscall(ri, regs, OP_MKNOD);
}

static int entry_handler_truncate(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;

	data->fname_ptr = func_arg_n(regs, 0);	/* const char __user *pathname */
	return entry_handler_syscall(ri, regs, OP_TRUNCATE);
}

/*
 * entry_handler_hook_file_truncate — Entry handler for hook_file_truncate LSM hook
 *
 * Captures the struct file pointer for path extraction in the ret handler.
 * hook_file_truncate is called from security_file_truncate() which is invoked
 * by do_sys_ftruncate() (the ftruncate(fd) syscall path). This is the only
 * kprobe covering ftruncate — we do all work in one LSM-level kprobe instead
 * of adding a separate do_sys_ftruncate syscall kprobe.
 */
static int entry_handler_hook_file_truncate(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;

	data->file = (struct file *)func_arg_n(regs, 0);
	return entry_handler_syscall(ri, regs, OP_FTRUNCATE);
}

static void extract_parent_dir(char *path)
{
	char *slash;
	size_t len;

	if (!path || !*path)
		return;

	len = strlen(path);
	while (len > 1 && path[len - 1] == '/')
		path[--len] = '\0';

	slash = strrchr(path, '/');
	if (!slash) {
		strcpy(path, ".");
	} else if (slash == path) {
		path[1] = '\0';
	} else {
		*slash = '\0';
	}
}

/**
 * derive_request_access - Translate stored probe data to a Landlock access mask
 * @data: probe_data captured by the entry handler
 *
 * Return: Landlock access mask (FS_* bits)
 */
static u16 derive_request_access(struct probe_data *data)
{
	u16 acc = 0;

	switch (data->type) {
	case OP_OPEN:
		switch (data->open_flags & O_ACCMODE) {
		case O_RDONLY:
			acc = data->is_dir ? LANDLOCK_ACCESS_FS_READ_DIR :
			                     LANDLOCK_ACCESS_FS_READ_FILE;
			break;
		case O_WRONLY:
			acc = LANDLOCK_ACCESS_FS_WRITE_FILE;
			break;
		case O_RDWR:
			acc = LANDLOCK_ACCESS_FS_READ_FILE |
			      LANDLOCK_ACCESS_FS_WRITE_FILE;
			break;
		}
		if (data->open_flags & __FMODE_EXEC)
			acc |= LANDLOCK_ACCESS_FS_EXECUTE;
		if (data->open_flags & O_CREAT)
			acc |= LANDLOCK_ACCESS_FS_MAKE_REG;
		break;

	case OP_UNLINK:
		acc = LANDLOCK_ACCESS_FS_REMOVE_FILE;
		break;

	case OP_RMDIR:
		acc = LANDLOCK_ACCESS_FS_REMOVE_DIR;
		break;

	case OP_MKDIR:
		acc = LANDLOCK_ACCESS_FS_MAKE_DIR;
		break;

	case OP_MKNOD:
		if (S_ISREG((umode_t)data->aux_arg) || (umode_t)data->aux_arg == 0)
			acc = LANDLOCK_ACCESS_FS_MAKE_REG;
		break;

	case OP_TRUNCATE:
	case OP_FTRUNCATE:
		acc = LANDLOCK_ACCESS_FS_TRUNCATE;
		break;
	}
	return acc;
}




/**
 * entry_handler_hook_file_open - Entry handler for hook_file_open
 * @ri:  kretprobe instance
 * @regs: CPU registers at function entry
 *
 * Captures the file flags and directory status for accurate access
 * calculation when this LSM hook denies a file open.
 *
 * Return: 0 (always)
 */
static int entry_handler_hook_file_open(struct kretprobe_instance *ri,
					struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct file *file = (struct file *)func_arg_n(regs, 0);

	if (!IS_ERR_OR_NULL(file)) {
		data->open_flags = file->f_flags;
		data->is_dir = d_is_dir(file->f_path.dentry);
	}
	return 0;
}

/**
 * ret_handler_hook_path - Common sensor: detect Landlock denials from any
 *                         hook_path_* LSM hook
 * @ri:  kretprobe instance
 * @regs: CPU registers at function return
 *
 * Marks the current task's per-task blocked_state so the corresponding
 * syscall ret_handler knows the -EACCES came from Landlock.  For
 * hook_file_open, also captures is_dir for accurate access calculation.
 *
 * Return: 0 (always)
 */
static int ret_handler_hook_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret = (int)regs_return_value(regs);

	if (ret == -EACCES) {
		struct sandbox_instance *inst = inst_find_by_pidns(current->pid, task_active_pid_ns(current));
		const char *name = get_kretprobe(ri)->kp.symbol_name;

		if (inst) {
			struct blocked_state *st = get_thread_state(inst, current->pid);
			if (st) {
				st->landlocked = true;
				if (strcmp(name, "hook_file_open") == 0) {
					struct probe_data *data = (struct probe_data *)ri->data;
					st->is_dir = data->is_dir;
				}
			}
		}
	}

	if (trace_all)
		pr_info("dyn-sandbox: TRACE [hook_path] ret=%ld\n", ret);
	return 0;
}


/**
 * log_blocked_access - Log a Landlock BLOCKED event with human-readable access bits
 * @ri:  kretprobe_instance (used to get the symbol name via get_kretprobe)
 * @data: probe_data captured by the entry handler
 */
static void log_blocked_access(struct kretprobe_instance *ri,
			       struct probe_data *data, const char *path)
{
	static const char * const op_names[] = {
		[OP_OPEN]   = "open",
		[OP_UNLINK] = "unlink",
		[OP_RMDIR]  = "rmdir",
		[OP_MKDIR]  = "mkdir",
		[OP_MKNOD]  = "mknod",
		[OP_TRUNCATE] = "truncate",
		[OP_FTRUNCATE] = "ftruncate",
	};
	const char *op_name = (data->type < ARRAY_SIZE(op_names))
			     ? op_names[data->type] : "?";
	u16 acc = derive_request_access(data);
	char acc_buf[128];

	acc_buf[0] = '\0';
	if (acc & LANDLOCK_ACCESS_FS_READ_FILE)  strcat(acc_buf, "|READ_FILE");
	if (acc & LANDLOCK_ACCESS_FS_READ_DIR)   strcat(acc_buf, "|READ_DIR");
	if (acc & LANDLOCK_ACCESS_FS_WRITE_FILE) strcat(acc_buf, "|WRITE_FILE");
	if (acc & LANDLOCK_ACCESS_FS_EXECUTE)    strcat(acc_buf, "|EXECUTE");
	if (acc & LANDLOCK_ACCESS_FS_TRUNCATE)   strcat(acc_buf, "|TRUNCATE");
	if (acc & LANDLOCK_ACCESS_FS_MAKE_REG)   strcat(acc_buf, "|MAKE_REG");
	if (acc & LANDLOCK_ACCESS_FS_MAKE_DIR)   strcat(acc_buf, "|MAKE_DIR");
	if (acc & LANDLOCK_ACCESS_FS_REMOVE_FILE) strcat(acc_buf, "|REMOVE_FILE");
	if (acc & LANDLOCK_ACCESS_FS_REMOVE_DIR)  strcat(acc_buf, "|REMOVE_DIR");
	pr_info("dyn-sandbox: BLOCKED [%s] op=%s path=%s pid=%d access=%s (0x%04x)\n",
		get_kretprobe(ri)->kp.symbol_name,
		op_name, path ? path : "", current->pid,
		acc_buf[0] ? acc_buf + 1 : "none", acc);
}

/**
 * ret_handler_blocked_common - Shared return handler for all blocked ops
 * @ri:         kretprobe instance
 * @regs:       CPU registers at function return
 *
 * Shared by open/unlink/rmdir/mkdir/mknod/truncate/ftruncate handlers.
 * Uses get_kretprobe(ri)->kp.symbol_name for the probe name (instead of a
 * per-kprobe parameter) so all kprobes[] entries use this same handler.
 * On Landlock -EACCES: SIGSTOP + ERESTARTNOINTR to allow dynamic auth.
 *
 * Return: 0 (always)
 */
/**
 * build_entry - Allocate and fill a blocked_entry from probe data
 * @data: probe_data captured by the entry handler
 *
 * Parses the path, derives the Landlock access mask, extracts parent
 * directory, and resolves the absolute path via kern_path.
 *
 * Return: pointer to blocked_entry, or NULL on allocation failure.
 */
static struct blocked_entry *build_entry(struct probe_data *data)
{
	struct blocked_entry *entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		/* Low memory: skip dynamic auth, Landlock -EACCES
		 * propagates as a hard deny.  Safe fallback.
		 */
		return NULL;

	entry->pid = current->pid;
	entry->type = data->type;

	/* Parse path and auxiliary args from saved registers */
	switch (data->type) {
	case OP_FTRUNCATE:
		if (data->file) {
			char buf[SANDBOX_PATH_MAX];
			char *path = d_path(&data->file->f_path, buf, sizeof(buf));
			if (!IS_ERR(path)) {
				memmove(buf, path, strlen(path) + 1);
				strncpy(entry->blocked_file, buf,
					sizeof(entry->blocked_file) - 1);
				/* Set resolved path directly from d_path */
				strncpy(entry->blocked_resolved, buf,
					sizeof(entry->blocked_resolved) - 1);
			}
		}
		entry->blocked_file_ptr = data->file;
		break;
	case OP_OPEN:
		if (data->fname_ptr)
			strncpy_from_user(entry->blocked_file,
				(const char __user *)data->fname_ptr,
				 sizeof(entry->blocked_file) - 1);
		if (data->aux_arg)
			data->open_flags = ((struct open_how *)data->aux_arg)->flags;
		break;
	case OP_TRUNCATE:
		if (data->fname_ptr)
			strncpy_from_user(entry->blocked_file,
				(const char __user *)data->fname_ptr,
				 sizeof(entry->blocked_file) - 1);
		break;
	case OP_UNLINK:
	case OP_RMDIR:
	case OP_MKDIR:
	case OP_MKNOD:
		if (data->fname_ptr)
			strncpy(entry->blocked_file, (const char *)data->fname_ptr,
				sizeof(entry->blocked_file) - 1);
		break;
	default:
		break;
	}

	entry->request_access = derive_request_access(data);

	/* Parent dir extraction -- not needed for FTRUNCATE */
	switch (data->type) {
	case OP_OPEN:
		if (data->open_flags & O_CREAT)
			extract_parent_dir(entry->blocked_file);
		break;
	case OP_UNLINK:
	case OP_RMDIR:
	case OP_MKDIR:
	case OP_MKNOD:
		extract_parent_dir(entry->blocked_file);
		break;
	default:
		break;
	}

	/* kern_path resolution -- skipped for FTRUNCATE (already resolved via d_path) */
	if (data->type != OP_FTRUNCATE && entry->blocked_file[0])
		kern_path(entry->blocked_file, LOOKUP_FOLLOW,
			  &entry->blocked_path);

	if (entry->blocked_path.dentry) {
		char tmp[SANDBOX_PATH_MAX];
		char *abs = d_path(&entry->blocked_path, tmp, sizeof(tmp));
		if (!IS_ERR(abs))
			strncpy(entry->blocked_resolved, abs,
				sizeof(entry->blocked_resolved) - 1);
	}

	return entry;
}

static int ret_handler_blocked_common(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	long ret = (int)(long)regs_return_value(regs);
	struct sandbox_instance *inst = inst_find_by_pidns(current->pid, task_active_pid_ns(current));
	unsigned long flags;

	if (ret != -EACCES)
		return 0;

	if (!inst)
		return 0;

	/*
	 * OP_FTRUNCATE comes from hook_file_truncate, which is itself a Landlock
	 * LSM hook.  For all other ops, only act on -EACCES that the sensor
	 * confirmed as Landlock; consume the per-task state either way.
	 */
	if (data->type != OP_FTRUNCATE) {
		struct blocked_state *st = get_thread_state(inst, current->pid);
		if (!st || !st->landlocked)
			return 0;
		data->is_dir = st->is_dir;   /* consumed by build_entry below */
		st->landlocked = false;
	}

	struct blocked_entry *entry = build_entry(data);
	if (!entry)
		return 0;

	log_blocked_access(ri, data, entry->blocked_file);

	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	list_add_tail(&entry->list_node, &inst->state.blocked_list);
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	wake_up_interruptible(&inst->blocked_wait);

	send_sig(SIGSTOP, current, 0);
	regs_set_return_value(regs, -ERESTARTNOINTR);

	return 0;
}

/*
 * Kernel symbol version isolation (B1):
 *  - kernel >= 7.0: fs/namei.c do_* series renamed to filename_* (Al Viro, 2026),
 *    symbol name only; signature unchanged (int dfd, struct filename *name, ...).
 *  - openEuler 6.6 / kernel < 7.0: still do_*.
 *  Note: selection is based on LINUX_VERSION_CODE of the build kernel; the module
 *  must be built on the target kernel.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
#define SYM_UNLINKAT	"filename_unlinkat"
#define SYM_RMDIR	"filename_rmdir"
#define SYM_MKDIRAT	"filename_mkdirat"
#define SYM_MKNODAT	"filename_mknodat"
#else
#define SYM_UNLINKAT	"do_unlinkat"
#define SYM_RMDIR	"do_rmdir"
#define SYM_MKDIRAT	"do_mkdirat"
#define SYM_MKNODAT	"do_mknodat"
#endif

static struct kretprobe kprobes[] = {
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_open,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "do_sys_openat2",
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_unlink,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = SYM_UNLINKAT,
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_rmdir,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = SYM_RMDIR,
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_mkdir,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = SYM_MKDIRAT,
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_mknod,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = SYM_MKNODAT,
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_truncate,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "do_sys_truncate",
	},
	{
		.handler	 = ret_handler_blocked_common,
		.entry_handler	 = entry_handler_hook_file_truncate,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_file_truncate",
	},
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_file_open,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_file_open",
	},
	{
		.handler	 = ret_handler_hook_path,
		.kp.symbol_name	 = "hook_path_mknod",
	},
	{
		.handler	 = ret_handler_hook_path,
		.kp.symbol_name	 = "hook_path_mkdir",
	},
	{
		.handler	 = ret_handler_hook_path,
		.kp.symbol_name	 = "hook_path_unlink",
	},
	{
		.handler	 = ret_handler_hook_path,
		.kp.symbol_name	 = "hook_path_rmdir",
	},
	{
		.handler	 = ret_handler_hook_path,
		.kp.symbol_name	 = "hook_path_truncate",
	}
};

#define NUM_KPROBES ARRAY_SIZE(kprobes)

/* ====================================================================== */
/*  Landlock load-time switch (global)                                    */
/* ====================================================================== */

#ifdef CONFIG_LANDLOCK_ENABLE
/* Tri-state: -1 auto (default), 0 off (pure network), 1 on (strict).
 * Load-time only; sysfs is read-only (0444) — no runtime switching. */
static int landlock_enable = -1;
module_param(landlock_enable, int, 0444);
MODULE_PARM_DESC(landlock_enable,
	"Landlock file runtime authorization: -1 auto (default, graceful), 0 off, 1 on (strict)");
#else
/* No-Landlock build: force off, constant 0 —
 * sandbox_file_init short-circuits immediately; the module loads as a pure
 * network sandbox. */
static int landlock_enable = 0;
#endif

/* ====================================================================== */
/*  File ioctl handlers                                                   */
/* ====================================================================== */

/**
 * sandbox_file_handle_set_pid - SANDBOX_FILE_SET_PID ioctl handler
 * @inst: sandbox instance (may be NULL if device open raced teardown)
 * @uarg: userspace pointer to pid_t
 *
 * Registers a child PID with the kprobe infrastructure so that the
 * kretprobe handlers can associate blocked-file events with this instance.
 * Also clears SIGNAL_UNKILLABLE on the child so that SIGSTOP works
 * under CLONE_NEWPID.
 *
 * Return: 0 on success, -EBADFD if inst is NULL, -ESRCH if no task has
 *         the given pid, -EINVAL if the task has no signal struct (dying),
 *         -EFAULT on copy failure
 */
int sandbox_file_handle_set_pid(struct sandbox_instance *inst, void __user *uarg)
{
	pid_t new_pid;
	struct task_struct *task;
	unsigned long flags;

	if (!inst)
		return -EBADFD;
	if (copy_from_user(&new_pid, uarg, sizeof(new_pid)))
		return -EFAULT;

	inst->registered_pid = new_pid;

	spin_lock_irqsave(&inst_lock, flags);
	if (!inst->in_inst_list) {
		list_add(&inst->list_node, &inst_list);
		inst->in_inst_list = true;
	}
	spin_unlock_irqrestore(&inst_lock, flags);

	struct pid *pid = find_get_pid(new_pid);
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;
	if (!task->signal) {
		put_task_struct(task);
		return -EINVAL;
	}

	task->signal->flags &= ~SIGNAL_UNKILLABLE;
	inst->sandbox_pid_ns = task_active_pid_ns(task);
	put_task_struct(task);
	pr_info("dyn-sandbox: SET_PID %d -> pid=%d\n",
		inst->registered_pid, current->pid);
	return 0;
}

/**
 * sandbox_file_handle_get_blocked - SANDBOX_FILE_GET_BLOCKED ioctl handler
 * @inst: sandbox instance (may be NULL)
 * @uarg: userspace pointer to struct sandbox_file_blocked
 *
 * Copies the blocked filename and resolved absolute path from the instance
 * to userspace after a kretprobe handler has SIGSTOP'd the child.
 *
 * Return: 0 on success, -EBADFD if inst is NULL, -EFAULT on copy_to_user failure
 */
int sandbox_file_handle_get_blocked(struct sandbox_instance *inst, void __user *uarg)
{
	struct sandbox_file_blocked info;
	struct blocked_entry *entry;
	unsigned long flags;

	if (!inst)
		return -EBADFD;
	memset(&info, 0, sizeof(info));

	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	entry = list_first_entry_or_null(&inst->state.blocked_list,
					 struct blocked_entry, list_node);
	if (entry) {
		strncpy(info.filename, entry->blocked_file,
			sizeof(info.filename) - 1);
		strncpy(info.resolved, entry->blocked_resolved,
			sizeof(info.resolved) - 1);
	}
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	if (copy_to_user(uarg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

/**
 * sandbox_file_handle_decision - SANDBOX_FILE_DECISION ioctl handler
 * @inst: sandbox instance (may be NULL)
 * @uarg: userspace pointer to struct sandbox_file_decision
 *
 * Refuses at the entry when Landlock runtime auth is not active: blocked
 * events only exist while the kretprobes are registered, and the ALLOW path
 * derefs cred->security + sandbox_lbs_cred which is only safe once the
 * Landlock blobs were allocated.  When not ready the blocked list is
 * necessarily empty, so no SIGSTOP'd child is left hanging.
 *
 * On DECISION_ALLOW: dynamically inserts a Landlock rule for the blocked
 * path via sandbox_landlock_allow_path(), then sends SIGCONT to the child.
 * If the grant fails (e.g. -ENOMEM/-EAGAIN/-ENOENT), the decision is
 * degraded to DENY — the child's return value is forced to -EACCES so it
 * does not restart with -ERESTARTNOINTR and re-block forever — and the
 * failure errno is returned to the daemon.
 * On DECISION_DENY: sets decision state to DENY and sends SIGCONT.
 * On unknown decision: returns -EINVAL.
 *
 * Return: 0 on success, -EBADFD if inst is NULL, -EFAULT on copy_from_user
 *         failure, -EOPNOTSUPP if Landlock runtime auth is not active,
 *         -ENOENT if the blocked list is empty, -EINVAL on unknown decision,
 *         otherwise the sandbox_landlock_allow_path() errno on a failed grant
 *         (child still SIGCONT'd, but as a DENY)
 */
int sandbox_file_handle_decision(struct sandbox_instance *inst, void __user *uarg)
{
	struct sandbox_file_decision d;
	struct blocked_entry *entry;
	unsigned long flags;
	pid_t blocked_pid;
	struct task_struct *child;
	int ret = 0;

	if (!inst)
		return -EBADFD;

	/* Landlock runtime auth must be active for any decision to make sense. */
	if (!sandbox_landlock_ready())
		return -EOPNOTSUPP;

	if (copy_from_user(&d, uarg, sizeof(d)))
		return -EFAULT;

	/* Dequeue the front entry */
	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	entry = list_first_entry_or_null(&inst->state.blocked_list,
					 struct blocked_entry, list_node);
	if (entry)
		list_del(&entry->list_node);
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	if (!entry)
		return -ENOENT;

	blocked_pid = entry->pid;

	struct pid *pid = find_get_pid(blocked_pid);
	child = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!child) {
		/* Task already exited — discard entry */
		if (entry->blocked_path.dentry)
			path_put(&entry->blocked_path);
		kfree(entry);
		return -ESRCH;
	}

	if (d.decision == DECISION_ALLOW) {
		atomic_set(&inst->state.decision, DECISION_ALLOW);

		/* path-based allow (for kprobes that captured dentry) */
		if (entry->blocked_path.dentry) {
			const struct cred *cred;
			void *dom;

			cred = get_task_cred(child);
			dom = *(void **)(cred->security
					 + sandbox_lbs_cred);
			ret = sandbox_landlock_allow_path(
				&entry->blocked_path,
				dom,
				entry->request_access);
			put_cred(cred);

			if (ret) {
				/* Grant failed (e.g. -ENOMEM/-EAGAIN/-ENOENT):
				 * degrade to DENY so the child returns -EACCES
				 * instead of restarting with -ERESTARTNOINTR and
				 * re-blocking forever.  The errno is propagated
				 * to the daemon via the ioctl return value. */
				pr_warn_ratelimited("dyn-sandbox: ALLOW failed (%d), degraded to DENY path=%s\n",
						    ret, entry->blocked_file);
				regs_set_return_value(task_pt_regs(child), -EACCES);
			}
		}

		/* file-based allow (hook_file_truncate: modify cached allowed_access)
		 * Skip when the path-based grant already degraded to DENY: a
		 * contradiction would leave TRUNCATE cached in f_security->allowed_access
		 * even though the child is being denied. */
		if (!ret && entry->type == OP_FTRUNCATE &&
		    entry->blocked_file_ptr &&
		    sandbox_lbs_file >= 0) {
			u16 *allowed_access =
				(u16 *)((char *)entry->blocked_file_ptr->f_security
					 + sandbox_lbs_file);
			WRITE_ONCE(*allowed_access,
				   *allowed_access | LANDLOCK_ACCESS_FS_TRUNCATE);
		}
	} else {
		struct pt_regs *regs = task_pt_regs(child);

		atomic_set(&inst->state.decision, DECISION_DENY);

		regs_set_return_value(regs, -EACCES);
	}

	send_sig(SIGCONT, child, 0);
	put_task_struct(child);

	/* Free entry outside of any lock */
	if (entry->blocked_path.dentry)
		path_put(&entry->blocked_path);
	kfree(entry);

	/* (blocked_list not explicitly emptied here — next dequeue sees empty */

	return ret;
}

/**
 * sandbox_drain_blocked_entries - Free all pending blocked_entry on a list
 * @list: list_head of blocked_entry queue to drain
 *
 * Iterates the list, releases blocked_path references, and frees each entry.
 * The caller must ensure no concurrent access to the list.
 */
static void sandbox_drain_blocked_entries(struct list_head *list)
{
	struct blocked_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, list, list_node) {
		list_del(&entry->list_node);
		if (entry->blocked_path.dentry)
			path_put(&entry->blocked_path);
		kfree(entry);
	}
}

/**
 * sandbox_file_release - Release file auth state for an instance
 * @inst: sandbox instance being released
 *
 * Removes the instance from inst_list (so kprobe handlers no longer find it)
 * and releases the blocked_path if one was captured.
 */
void sandbox_file_release(struct sandbox_instance *inst)
{
	unsigned long flags;

	if (!inst)
		return;

	if (inst->in_inst_list) {
		spin_lock_irqsave(&inst_lock, flags);
		list_del(&inst->list_node);
		spin_unlock_irqrestore(&inst_lock, flags);
		inst->in_inst_list = false;
	}

	/* Drain any leftover blocked entries */
	{
		struct list_head drain_list;

		INIT_LIST_HEAD(&drain_list);
		spin_lock_irqsave(&inst->state.blocked_lock, flags);
		list_splice_init(&inst->state.blocked_list, &drain_list);
		spin_unlock_irqrestore(&inst->state.blocked_lock, flags);
		sandbox_drain_blocked_entries(&drain_list);
	}

	/* Free leftover per-task blocked_state entries (tasks killed before consuming) */
	{
		struct blocked_state *st, *tmp;
		struct list_head drain_flags;

		INIT_LIST_HEAD(&drain_flags);
		spin_lock_irqsave(&inst->state.blocked_lock, flags);
		list_splice_init(&inst->state.blocked_flag_list, &drain_flags);
		spin_unlock_irqrestore(&inst->state.blocked_lock, flags);
		list_for_each_entry_safe(st, tmp, &drain_flags, node)
			kfree(st);
	}

	/* Kill the child process if still alive (e.g., stuck in SIGSTOP) */
	if (inst->registered_pid) {
		struct pid *pid = find_get_pid(inst->registered_pid);
		struct task_struct *task = get_pid_task(pid, PIDTYPE_PID);

		put_pid(pid);
		if (task) {
			send_sig(SIGKILL, task, 0);
			put_task_struct(task);
		}
	}
}

/* ====================================================================== */
/*  Init / Exit                                                           */
/* ====================================================================== */

/**
 * sandbox_file_init - Enable file runtime authorization per the decision
 *
 * Whether to enable is decided ONLY by two inputs:
 *   - landlock_enable param: 1 = on (strict), 0 = off, -1 = unset (default).
 *   - landlock_enable unset (-1, default): sandbox_landlock_probe() — enable
 *     iff lsm_names confirms Landlock is active, otherwise skip (the only
 *     graceful path; module loads network-only).
 *
 * Any value other than -1/0/1 is a configuration error: the module aborts
 * loading rather than silently treating it as "auto".
 *
 * kallsyms_lookup_name is resolved first: both strict and auto need it to even
 * detect Landlock, so a resolution failure is fatal for both — without it the
 * module cannot tell "LSM compiled in but disabled" apart from "absent", and
 * there is no graceful fallback.  landlock_enable=0 returns before this step.
 *
 * Once the decision is "enable", initialization runs to completion and any
 * failure (symbol resolution, kprobe registration) is fatal — the module
 * aborts loading rather than silently losing file authorization.
 *
 * Return: 0 on success or when the decision is "off"; negative errno aborts.
 */
int sandbox_file_init(void)
{
	int ret, i;

	if (landlock_enable < -1 || landlock_enable > 1) {
		pr_err("dyn-sandbox: invalid landlock_enable=%d (must be -1, 0 or 1), aborting init\n",
		       landlock_enable);
		return -EINVAL;
	}

	if (landlock_enable == 0) {
		pr_info("dyn-sandbox: landlock_enable=0, file runtime authorization stays off\n");
		return 0;
	}

	ret = sandbox_landlock_resolve_kln();
	if (ret) {
		pr_err("dyn-sandbox: cannot resolve kallsyms_lookup_name, aborting init\n");
		return ret;
	}

	if (!sandbox_landlock_probe()) {
		if (landlock_enable == 1) {
			pr_err("dyn-sandbox: Landlock requested but unavailable, aborting init\n");
			return -EOPNOTSUPP;
		} else {
			/* -1 (auto): graceful — Landlock absent, module loads network-only. */
			pr_info("dyn-sandbox: Landlock unavailable, file runtime authorization stays off\n");
			return 0;
		}
	}

	/* Decision is "enable": any init failure below aborts module load. */
	ret = sandbox_landlock_init();
	if (ret) {
		pr_err("dyn-sandbox: Landlock init failed (%d), aborting init\n", ret);
		return ret;
	}

	for (i = 0; i < NUM_KPROBES; i++) {
		ret = register_kretprobe(&kprobes[i]);
		if (ret < 0) {
			pr_err("dyn-sandbox: register_kretprobe(%s) failed: %d\n",
			       kprobes[i].kp.symbol_name, ret);
			goto err_kprobes;
		}
		pr_info("dyn-sandbox: kretprobe on %s registered\n",
			kprobes[i].kp.symbol_name);
	}
	pr_info("dyn-sandbox: file runtime authorization enabled\n");
	return 0;

err_kprobes:
	for (i--; i >= 0; i--)
		unregister_kretprobe(&kprobes[i]);
	sandbox_landlock_deactivate();
	pr_err("dyn-sandbox: Landlock file auth init failed (%d), aborting init\n", ret);
	return ret;
}

/**
 * sandbox_file_exit - Unregister kretprobes if active, assert inst_list empty
 *
 * Uses sandbox_landlock_ready() as the guard: at exit time it is true iff the
 * kretprobes were registered — landlock_active is set only on a successful
 * init chain, and cleared on any partial-failure unwind (err_kprobes) and on
 * graceful skip.  Module refcounting guarantees all instances were released
 * via their file_operations release path before this.
 */
void sandbox_file_exit(void)
{
	int i;

	if (sandbox_landlock_ready()) {
		for (i = 0; i < NUM_KPROBES; i++)
			unregister_kretprobe(&kprobes[i]);
	}
	sandbox_landlock_deactivate();

	WARN_ONCE(!list_empty(&inst_list),
		  "dyn-sandbox: inst_list not empty on module exit (instance leak)\n");
}
