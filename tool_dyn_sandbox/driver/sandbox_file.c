// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_file.c
 *
 * File runtime authorization via kretprobes
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */

/*
 * KERNEL VERSION DEPENDENCIES:
 * All kretprobes in kprobes[] hook internal (mostly static) kernel functions,
 * whose symbols are only in kallsyms when CONFIG_KALLSYMS_ALL=y.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
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
#include <linux/workqueue.h>
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
 * inst_find_by_pidns - Find the sandbox instance for a blocked task.
 * Fork children inherit the parent's pid namespace, so matching by pid_ns
 * (instead of PID) supports arbitrary-depth fork: direct ns match first, then
 * walk the pid_ns->parent chain for nested namespaces (CLONE_NEWPID).
 *
 * Context: any (kretprobe handler, may be atomic)
 * Return: instance with an extra kref taken (caller must kref_put), or NULL.
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
			kref_get(&inst->ref); /* caller owns a ref until it kref_put's */
			spin_unlock_irqrestore(&inst_lock, flags);
			return inst;
		}

	/* Phase 2: walk parent chain — for nested ns (CLONE_NEWPID inside sandbox) */
	{
		const struct pid_namespace *ns = pid_ns->parent;
		while (ns && ns->level > 0) {
			list_for_each_entry(inst, &inst_list, list_node)
				if (inst->sandbox_pid_ns && ns == inst->sandbox_pid_ns) {
					kref_get(&inst->ref); /* caller owns a ref until it kref_put's */
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
	/* Object the LSM hook denied on (snapshot at entry; ref taken on -EACCES) */
	enum blocked_cap_kind cap_kind;
	struct path  cap_path;
	struct file *cap_file;
	/* hook_file_open / hook_path_mknod aux (captured by the hook entry handler) */
	u64    open_flags;
	bool   is_dir;
	umode_t mode;
	/* hook_file_truncate field */
	struct file *file;
};

/*
 * Per-task Landlock handoff state, indexed by pid: each sandbox child mutates
 * only its own entry, so concurrent children never clobber each other.
 */
struct blocked_state {
	struct list_head node;
	pid_t  pid;
	bool   landlocked;   /* this task's syscall was denied by Landlock */
	bool   is_dir;       /* denied open target is a directory (hook_file_open only) */
	/* Object the sensor hook denied on, held between hook ret and syscall ret */
	u64    open_flags;
	umode_t mode;
	enum blocked_cap_kind cap_kind;
	struct path  cap_path;
	struct file *cap_file;
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
 * Return: pointer to blocked_state, or NULL on allocation failure.  Valid only
 * while the caller holds an inst reference (see struct comment above).
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
 * entry_handler_probe_data_reset - Reset the reused probe_data at a kretprobe entry
 * @type: op_type for this probe
 *
 * ri->data is kmalloc'd (not kzalloc'd) and reused, so each probe invocation
 * resets the cap slots before the object is (re)captured.  Shared by the
 * syscall-level wrappers (entry_handler_open & co.) and the self-contained
 * hook_file_truncate probe.
 *
 * Return: 0 (always)
 */
static int entry_handler_probe_data_reset(struct kretprobe_instance *ri, struct pt_regs *regs,
				 enum op_type type)
{
	struct probe_data *data = (struct probe_data *)ri->data;

	data->type = type;
	data->cap_kind = BLOCKED_CAP_NONE;
	data->cap_file = NULL;
	data->mode = 0;
	return 0;
}

/*
 * Syscall entry handlers only tag the op type; the object is captured from
 * the LSM hook (child's context) and reaches the entry via blocked_state.
 */
static int entry_handler_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_OPEN);
}

static int entry_handler_unlink(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_UNLINK);
}

static int entry_handler_rmdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_RMDIR);
}

static int entry_handler_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_MKDIR);
}

static int entry_handler_mknod(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_MKNOD);
}

static int entry_handler_truncate(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return entry_handler_probe_data_reset(ri, regs, OP_TRUNCATE);
}

/*
 * entry_handler_hook_file_truncate — Entry handler for hook_file_truncate.
 * The only kprobe covering ftruncate: it works at the LSM level instead of a
 * separate do_sys_ftruncate syscall probe.
 */
static int entry_handler_hook_file_truncate(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct file *file = (struct file *)func_arg_n(regs, 0);

	entry_handler_probe_data_reset(ri, regs, OP_FTRUNCATE);

	data->file = file;
	if (file) {
		data->cap_path = file->f_path;
		data->cap_kind = BLOCKED_CAP_PATH;
	}
	return 0;
}

/*
 * entry_handler_hook_path - Shared entry handler for the hook_path_* LSM probes.
 * Snapshots the denied object (hook arg0).  Value copy only — the ret
 * handler takes the reference on -EACCES.  arg2 is the mode for mkdir/mknod.
 */
static int entry_handler_hook_path(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct path *p = (struct path *)func_arg_n(regs, 0);

	data->cap_kind = BLOCKED_CAP_NONE;
	if (p) {
		data->cap_path = *p;
		data->cap_kind = BLOCKED_CAP_PATH;
	}
	data->mode = (umode_t)func_arg_n(regs, 2);	/* mknod/mkdir mode */
	return 0;
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
		if (data->cap_kind == BLOCKED_CAP_PATH) {
			/* O_CREAT create: Landlock denies in hook_path_mknod (parent
			 * dir MAKE_REG).  That probe carries the parent dir as cap_path
			 * and sets no open_flags, so derive from the create semantics,
			 * not the (unset) open flags. */
			acc = LANDLOCK_ACCESS_FS_MAKE_REG;
			break;
		}
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
		if (S_ISREG(data->mode) || data->mode == 0)
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
 * entry_handler_hook_file_open - Entry handler for hook_file_open.
 * Captures the flags/dir status and snapshots the file (object) for DECISION.
 */
static int entry_handler_hook_file_open(struct kretprobe_instance *ri,
					struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	struct file *file = (struct file *)func_arg_n(regs, 0);

	data->cap_kind = BLOCKED_CAP_NONE;
	if (!IS_ERR_OR_NULL(file)) {
		data->open_flags = file->f_flags;
		data->is_dir = d_is_dir(file->f_path.dentry);
		data->cap_file = file;
		data->cap_kind = BLOCKED_CAP_FILE;
	}
	return 0;
}

/**
 * ret_handler_hook_path - Common sensor for the hook_path_* LSM probes.
 * On -EACCES, marks the per-task blocked_state so the syscall ret handler
 * knows the denial came from Landlock; for hook_file_open also captures
 * is_dir/open_flags.
 */
static int ret_handler_hook_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret = (int)regs_return_value(regs);
	struct probe_data *data = (struct probe_data *)ri->data;

	if (ret == -EACCES) {
		struct sandbox_instance *inst = inst_find_by_pidns(current->pid, task_active_pid_ns(current));
		const char *name = get_kretprobe(ri)->kp.symbol_name;

		if (inst) {
			struct blocked_state *st = get_thread_state(inst, current->pid);
			if (st) {
				st->landlocked = true;
				if (strcmp(name, "hook_file_open") == 0) {
					st->is_dir = data->is_dir;
					st->open_flags = data->open_flags;
				}
				if (strcmp(name, "hook_path_mknod") == 0)
					st->mode = data->mode;
				/* Take the reference only on denial (the object is still
				 * live here: the trampoline runs before the caller's error
				 * cleanup).  For BLOCKED_CAP_FILE, hold cap_path separately
				 * because do_dentry_open() zeroes f->f_path on -EACCES. */
				st->cap_kind = data->cap_kind;
				if (data->cap_kind == BLOCKED_CAP_PATH) {
					path_get(&data->cap_path);
					st->cap_path = data->cap_path;
				} else if (data->cap_kind == BLOCKED_CAP_FILE) {
					st->cap_file = get_file(data->cap_file);
					st->cap_path = data->cap_file->f_path;
					path_get(&st->cap_path);
				}
				data->cap_kind = BLOCKED_CAP_NONE;
			}
			kref_put(&inst->ref, inst_release);
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
 * fill_entry_paths - Fill user-facing paths from an object: blocked_file is the
 * last d_path component (works for mount roots, whose dentry name is "/");
 * blocked_resolved is the full d_path() string.  d_path() does not sleep
 * (rename_lock seqcount-guarded), safe in kprobe ret context.  Display-only:
 * grants act on the captured object, never on these strings.
 */
static void fill_entry_paths(const struct path *p, struct blocked_entry *entry)
{
	char buf[SANDBOX_PATH_MAX];
	char *path;
	const char *slash;

	if (!p)
		return;
	path = d_path(p, buf, sizeof(buf));
	if (IS_ERR(path))
		return;
	memmove(buf, path, strlen(path) + 1);
	strncpy(entry->blocked_resolved, buf, sizeof(entry->blocked_resolved) - 1);
	slash = strrchr(buf, '/');
	strscpy(entry->blocked_file, slash && slash[1] ? slash + 1 : "/",
		sizeof(entry->blocked_file));
}

/**
 * release_entry_caps - Release every owned object held by an entry
 * @entry: blocked_entry whose owned refs to drop (not freed here)
 *
 * Process context only: path_put may sleep (dput -> dentry_kill).  The drain
 * (inst_release, possibly atomic) must NOT call this inline — it defers whole
 * entries to the sb_defer worker instead.
 */
static void release_entry_caps(struct blocked_entry *entry)
{
	if (entry->blocked_file_ptr) {
		fput(entry->blocked_file_ptr);
		entry->blocked_file_ptr = NULL;
	}
	if (entry->cap_kind == BLOCKED_CAP_PATH) {
		path_put(&entry->cap_path);
		entry->cap_kind = BLOCKED_CAP_NONE;
	} else if (entry->cap_kind == BLOCKED_CAP_FILE) {
		fput(entry->cap_file);
		entry->cap_file = NULL;
		path_put(&entry->cap_path);
		entry->cap_kind = BLOCKED_CAP_NONE;
	}
}

/**
 * build_entry - Allocate and fill a blocked_entry from probe data.
 * The entry takes ownership of the object the LSM hook denied on.
 * Return: entry, or NULL when there is nothing to grant on (allocation
 *         failure or no captured object).
 */
static struct blocked_entry *build_entry(struct probe_data *data)
{
	struct blocked_entry *entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		/* Low memory: -EACCES propagates as a hard deny. */
		return NULL;

	entry->pid = current->pid;
	entry->type = data->type;

	entry->cap_kind = data->cap_kind;
	entry->cap_path = data->cap_path;
	entry->cap_file = data->cap_file;
	entry->open_flags = data->open_flags;

	entry->request_access = derive_request_access(data);

	/* Display strings from the owned object (grant never uses these). */
	switch (data->type) {
	case OP_FTRUNCATE:
		if (entry->cap_kind == BLOCKED_CAP_PATH)
			fill_entry_paths(&entry->cap_path, entry);
		else if (data->file)
			fill_entry_paths(&data->file->f_path, entry);

		if (data->file)
			/* Own a file ref so the cached allowed_access grant in
			 * DECISION survives a child killed before it. */
			entry->blocked_file_ptr = get_file(data->file);
		break;
	case OP_OPEN:
		/* BLOCKED_CAP_FILE: open denied (cap_file->f_path zeroed by
		 * do_dentry_open's cleanup_all, so cap_path holds the ref).
		 * BLOCKED_CAP_PATH: O_CREAT denied in hook_path_mknod (parent dir). */
		if (entry->cap_kind == BLOCKED_CAP_FILE ||
		    entry->cap_kind == BLOCKED_CAP_PATH)
			fill_entry_paths(&entry->cap_path, entry);
		break;
	case OP_TRUNCATE:
	case OP_UNLINK:
	case OP_RMDIR:
	case OP_MKDIR:
	case OP_MKNOD:
		if (entry->cap_kind == BLOCKED_CAP_PATH)
			fill_entry_paths(&entry->cap_path, entry);
		break;
	default:
		break;
	}

	/* No object -> nothing to grant on; drop so -EACCES propagates as a hard
	 * deny.  FTRUNCATE is exempt: its grant is file-based (blocked_file_ptr). */
	if (entry->cap_kind == BLOCKED_CAP_NONE && data->type != OP_FTRUNCATE) {
		kfree(entry);
		return NULL;
	}

	return entry;
}

static int ret_handler_blocked_common(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *data = (struct probe_data *)ri->data;
	long ret = (int)(long)regs_return_value(regs);
	struct sandbox_instance *inst;
	unsigned long flags;

	if (ret != -EACCES)
		return 0;

	inst = inst_find_by_pidns(current->pid, task_active_pid_ns(current));
	if (!inst)
		return 0;

	/*
	 * OP_FTRUNCATE comes from hook_file_truncate, itself a Landlock LSM hook;
	 * for all other ops only act on -EACCES the sensor confirmed as Landlock.
	 */
	if (data->type != OP_FTRUNCATE) {
		struct blocked_state *st = get_thread_state(inst, current->pid);
		if (!st || !st->landlocked) {
			kref_put(&inst->ref, inst_release);
			return 0;
		}
		/* Move the sensor's object into probe_data (build_entry takes
		 * ownership); st is fully consumed so a stale entry cannot
		 * double-release the object. */
		data->is_dir = st->is_dir;
		data->open_flags = st->open_flags;
		data->mode = st->mode;
		data->cap_kind = st->cap_kind;
		data->cap_path = st->cap_path;
		data->cap_file = st->cap_file;
		st->cap_kind = BLOCKED_CAP_NONE;
		st->landlocked = false;
	} else if (data->cap_kind == BLOCKED_CAP_PATH) {
		/* hook_file_truncate denied: snapshot is still live here (trampoline
		 * runs before do_dentry_open's cleanup_all zeroes f->f_path). */
		path_get(&data->cap_path);
	}

	struct blocked_entry *entry = build_entry(data);
	if (!entry) {
		/* build_entry took no ownership: release what we pulled from st. */
		if (data->cap_kind == BLOCKED_CAP_PATH)
			path_put(&data->cap_path);
		else if (data->cap_kind == BLOCKED_CAP_FILE) {
			fput(data->cap_file);
			path_put(&data->cap_path);
		}
		data->cap_kind = BLOCKED_CAP_NONE;
		kref_put(&inst->ref, inst_release);
		return 0;
	}

	log_blocked_access(ri, data, entry->blocked_resolved);

	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	list_add_tail(&entry->list_node, &inst->state.blocked_list);
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	wake_up_interruptible(&inst->blocked_wait);

	send_sig(SIGSTOP, current, 0);
	regs_set_return_value(regs, -ERESTARTNOINTR);

	kref_put(&inst->ref, inst_release);
	return 0;
}

/*
 * Kernel symbol version isolation:
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
	/* Every hook_path_* probe needs data_size + entry handler — the entry
	 * handler snapshots arg0; the ret handler references it on -EACCES only. */
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_path,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_path_mknod",
	},
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_path,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_path_mkdir",
	},
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_path,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_path_unlink",
	},
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_path,
		.data_size	 = sizeof(struct probe_data),
		.kp.symbol_name	 = "hook_path_rmdir",
	},
	{
		.handler	 = ret_handler_hook_path,
		.entry_handler	 = entry_handler_hook_path,
		.data_size	 = sizeof(struct probe_data),
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

	spin_lock_irqsave(&task->sighand->siglock, flags);
	task->signal->flags &= ~SIGNAL_UNKILLABLE;
	spin_unlock_irqrestore(&task->sighand->siglock, flags);

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
 * Return: 0 on success, -EBADFD if inst is NULL, -ENOENT if blocked_list is
 *         empty (spurious wake / already consumed), -EFAULT on copy_to_user failure
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

	if (!entry)
		return -ENOENT;

	if (copy_to_user(uarg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

/*
 * entry_grant_path - Landlock grant target from an entry's object.
 * BLOCKED_CAP_PATH: the parent dir or file; BLOCKED_CAP_FILE: the file, or for
 * O_CREAT the parent dir (the file inode may be recreated on restart; a rule on
 * the parent covers it, since Landlock is inode-keyed + hierarchical).
 */
static bool entry_grant_path(const struct blocked_entry *entry, struct path *out)
{
	if (entry->cap_kind == BLOCKED_CAP_PATH) {
		*out = entry->cap_path;
		return true;
	}
	if (entry->cap_kind == BLOCKED_CAP_FILE && entry->cap_path.dentry) {
		if (entry->type == OP_OPEN && (entry->open_flags & O_CREAT)) {
			/* cap_path holds a ref on its dentry, so d_parent is stable
			 * (reparenting only happens under a live-dentry rename). */
			out->mnt = entry->cap_path.mnt;
			out->dentry = entry->cap_path.dentry->d_parent;
		} else {
			*out = entry->cap_path;
		}
		return true;
	}
	return false;
}

/**
 * sandbox_file_handle_decision - SANDBOX_FILE_DECISION ioctl handler
 *
 * ALLOW: inserts a Landlock rule for the denied object (cap_path/cap_file),
 * then SIGCONT the child.  A failed grant degrades to DENY: the child returns
 * -EACCES instead of restarting with -ERESTARTNOINTR and re-blocking forever.
 * DENY: sets decision state and SIGCONT.  Refuses with -EOPNOTSUPP when
 * Landlock runtime auth is not active (the blocked list is necessarily empty,
 * so no SIGSTOP'd child is left hanging).
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
		/* Task already exited — discard entry (drop owned objects first) */
		release_entry_caps(entry);
		kfree(entry);
		return -ESRCH;
	}

	if (d.decision == DECISION_ALLOW) {
		atomic_set(&inst->state.decision, DECISION_ALLOW);

		/* Object-based grant: no path resolution, so namespace-local
		 * mounts (tmpfs /mnt, bind mounts) grant on the child's actual inodes.
		 * FTRUNCATE with a captured path grants here too: an O_TRUNC denial
		 * restarts open() and recomputes allowed_access from the ruleset, so
		 * TRUNCATE must be in the ruleset or the cache grant is lost.  The
		 * cache grant still runs below for ftruncate(fd) on an open file. */
		if (entry->type != OP_FTRUNCATE ||
		    entry->cap_kind == BLOCKED_CAP_PATH) {
			struct path grant;
			bool have_grant = entry_grant_path(entry, &grant);

			if (have_grant) {
				const struct cred *cred;
				void *dom;

				cred = get_task_cred(child);
				dom = *(void **)(cred->security
						 + sandbox_lbs_cred);
				ret = sandbox_landlock_allow_path(
					&grant, dom, entry->request_access);
				put_cred(cred);

				if (ret) {
					/* Grant failed: degrade to DENY so the child returns
					 * -EACCES instead of re-blocking forever.  Errno is
					 * propagated to the daemon via the ioctl return. */
					pr_warn_ratelimited("dyn-sandbox: ALLOW failed (%d), degraded to DENY path=%s\n",
							    ret, entry->blocked_resolved);
					regs_set_return_value(task_pt_regs(child), -EACCES);
				}
			} else {
				/* No object to grant on: degrade to DENY. */
				ret = -ENOENT;
				pr_warn_ratelimited("dyn-sandbox: ALLOW no grant object, degraded to DENY path=%s\n",
						    entry->blocked_resolved);
				regs_set_return_value(task_pt_regs(child), -EACCES);
			}
		}

		/* File-based allow (hook_file_truncate): set TRUNCATE in the cached
		 * allowed_access.  Skipped if the path grant degraded to DENY. */
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

	/* Drop owned objects (path_put/fput).  Process context — safe to sleep. */
	release_entry_caps(entry);
	kfree(entry);

	return ret;
}

/*
 * Deferred-free machinery: inst_release() (possibly atomic kprobe context)
 * cannot path_put (may sleep), so drained entries/states are freed by this
 * workqueue worker in process context.  flush_work() in exit guarantees release
 * before unload.
 */
static DEFINE_SPINLOCK(sb_defer_lock);
static LIST_HEAD(sb_defer_entries);
static LIST_HEAD(sb_defer_states);
static struct work_struct sb_defer_work;

static void sb_defer_release(struct work_struct *work)
{
	struct blocked_entry *entry, *entry_tmp;
	struct blocked_state *st, *st_tmp;
	struct list_head elist, slist;
	unsigned long flags;

	INIT_LIST_HEAD(&elist);
	INIT_LIST_HEAD(&slist);

	spin_lock_irqsave(&sb_defer_lock, flags);
	list_splice_init(&sb_defer_entries, &elist);
	list_splice_init(&sb_defer_states, &slist);
	spin_unlock_irqrestore(&sb_defer_lock, flags);

	/* Process context: path_put/fput may sleep here. */
	list_for_each_entry_safe(entry, entry_tmp, &elist, list_node) {
		list_del(&entry->list_node);
		release_entry_caps(entry);
		kfree(entry);
	}
	list_for_each_entry_safe(st, st_tmp, &slist, node) {
		list_del(&st->node);
		if (st->cap_kind == BLOCKED_CAP_PATH)
			path_put(&st->cap_path);
		else if (st->cap_kind == BLOCKED_CAP_FILE) {
			fput(st->cap_file);
			path_put(&st->cap_path);
		}
		kfree(st);
	}
}

/**
 * sandbox_file_drain_blocks - Splice both blocked lists off the instance and
 * move everything to the sb_defer worker for release.  Must not sleep: called
 * from inst_release(), which can run in atomic kprobe context.  Safe because
 * every list writer holds a transient inst reference, so a zero refcount
 * implies all list_adds completed.
 */
void sandbox_file_drain_blocks(struct sandbox_instance *inst)
{
	struct blocked_entry *entry, *entry_tmp;
	struct blocked_state *st, *st_tmp;
	struct list_head drain_list, drain_flags;
	unsigned long flags;

	INIT_LIST_HEAD(&drain_list);
	INIT_LIST_HEAD(&drain_flags);
	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	list_splice_init(&inst->state.blocked_list, &drain_list);
	list_splice_init(&inst->state.blocked_flag_list, &drain_flags);
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	list_for_each_entry_safe(entry, entry_tmp, &drain_list, list_node) {
		list_del(&entry->list_node);
		spin_lock_irqsave(&sb_defer_lock, flags);
		list_add_tail(&entry->list_node, &sb_defer_entries);
		spin_unlock_irqrestore(&sb_defer_lock, flags);
	}
	/* Leftover per-task blocked_state (tasks killed before consuming it). */
	list_for_each_entry_safe(st, st_tmp, &drain_flags, node) {
		list_del(&st->node);
		spin_lock_irqsave(&sb_defer_lock, flags);
		list_add_tail(&st->node, &sb_defer_states);
		spin_unlock_irqrestore(&sb_defer_lock, flags);
	}

	/* Schedule under the lock so the empty-check sees anything added here. */
	spin_lock_irqsave(&sb_defer_lock, flags);
	if (!list_empty(&sb_defer_entries) || !list_empty(&sb_defer_states))
		schedule_work(&sb_defer_work);
	spin_unlock_irqrestore(&sb_defer_lock, flags);
}

/**
 * sandbox_file_release - Remove the instance from inst_list and kill the child.
 * Blocked lists are NOT drained here; inst_release() (atomic-safe) handles them
 * once the last kprobe handler has dropped its transient reference.
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
 * sandbox_file_init - Enable file runtime authorization per the decision.
 *
 * Decision inputs: landlock_enable param (1 = strict on, 0 = off, -1 = unset);
 * when unset, sandbox_landlock_probe() enables iff lsm_names shows Landlock is
 * active (the only graceful path — module loads network-only otherwise).
 * Any other value aborts loading.  landlock_enable=0 returns before resolving
 * kallsyms_lookup_name; otherwise a resolution failure is fatal (needed to tell
 * "LSM compiled in but disabled" apart from "absent").  Once the decision is
 * "enable", any init failure (symbols, kprobe registration) aborts the load.
 *
 * Return: 0 on success or when the decision is "off"; negative errno aborts.
 */
int sandbox_file_init(void)
{
	int ret, i;

	/* Deferred-free worker must be usable whenever an instance can be closed
	 * (inst_release -> drain), regardless of the landlock switch. */
	INIT_WORK(&sb_defer_work, sb_defer_release);

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
 * sandbox_file_exit - Unregister kretprobes if active, assert inst_list empty.
 * sandbox_landlock_ready() is true iff the kretprobes were registered.
 */
void sandbox_file_exit(void)
{
	int i;

	/* Drain any deferred capped objects before the module unloads. */
	flush_work(&sb_defer_work);

	if (sandbox_landlock_ready()) {
		for (i = 0; i < NUM_KPROBES; i++)
			unregister_kretprobe(&kprobes[i]);
	}
	sandbox_landlock_deactivate();

	WARN_ONCE(!list_empty(&inst_list),
		  "dyn-sandbox: inst_list not empty on module exit (instance leak)\n");
}
