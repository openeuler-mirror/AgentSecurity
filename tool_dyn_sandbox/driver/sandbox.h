/*
 * sandbox.h
 *
 * Kernel-side internal header for dyn_sandbox.ko
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
#ifndef _SANDBOX_H
#define _SANDBOX_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/path.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "sandbox_dev.h"

struct pid_namespace;
struct pt_regs;

#define MAX_ENV_IDS 16384

/**
 * func_arg_n - Read the n-th argument of a C function call from pt_regs
 * @regs: pt_regs captured at function entry (e.g., by kprobe)
 * @n: argument index (0-based)
 *
 * Uses the architecture's C function calling convention, NOT the syscall ABI.
 * x86_64: args in rdi, rsi, rdx, rcx, r8, r9
 * arm64:  args in x0..x5  (regs[0]..regs[5])
 *
 * Return: value of the n-th function argument
 */
static inline unsigned long func_arg_n(struct pt_regs *regs, unsigned int n)
{
	switch (n) {
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	case 0:	return regs->di;
	case 1:	return regs->si;
	case 2:	return regs->dx;
	case 3:	return regs->cx;	/* rcx, not r10 (r10 is syscall ABI) */
	case 4:	return regs->r8;
	case 5:	return regs->r9;
#elif defined(CONFIG_ARM64)
	case 0:	return regs->regs[0];
	case 1:	return regs->regs[1];
	case 2:	return regs->regs[2];
	case 3:	return regs->regs[3];
	case 4:	return regs->regs[4];
	case 5:	return regs->regs[5];
#endif
	default:
		BUILD_BUG_ON_MSG(1, "func_arg_n: unsupported architecture");
		return 0;
	}
}

/**
 * op_type - File operation type for kprobe handlers and blocked_entry
 */
enum op_type {
	OP_OPEN   = 0,
	OP_UNLINK = 1,
	OP_RMDIR  = 2,
	OP_MKDIR  = 3,
	OP_MKNOD  = 4,
	OP_TRUNCATE = 5,
	OP_FTRUNCATE = 6,
};

/**
 * struct blocked_entry - One blocked file authorization request
 *
 * When a kprobe handler catches a Landlock -EACCES, it allocates a
 * blocked_entry and adds it to sandbox_state.blocked_list.  The
 * userspace decision-maker (sandbox-run) dequeues entries one at a
 * time via the GET_BLOCKED / DECISION ioctls.
 */
struct blocked_entry {
	struct list_head list_node;
	pid_t            pid;               /* PID of the blocked task */
	char             blocked_file[SANDBOX_PATH_MAX];
	char             blocked_resolved[SANDBOX_PATH_MAX];
	struct path      blocked_path;
	u16              request_access;
	struct file     *blocked_file_ptr;   /* for hook_file_truncate */
	enum op_type     type;              /* matches probe_data.type */
};

/**
 * struct sandbox_state - File authorization state (one per sandbox_instance)
 */
struct sandbox_state {
	struct list_head blocked_list;       /* blocked_entry queue */
	spinlock_t       blocked_lock;       /* protects blocked_list + blocked_flag_list */
	atomic_t         decision;
	struct list_head blocked_flag_list;  /* per-task Landlock handoff states */
};

/**
 * struct sandbox_net_env - Network environment (one per net instance)
 */
struct sandbox_net_env {
	int                  id;
	bool                 used;
	char                 domains[SANDBOX_MAX_DOMAINS][SANDBOX_DOMAIN_MAX_LEN];
	int                  ndomains;
	struct sandbox_cidr  cidrs[SANDBOX_MAX_CIDRS];
	int                  ncidrs;
	char                 ns_path[128];
	char                 veth_host[SANDBOX_IFNAME_SZ];
	__be32               child_ip;
	__be32               host_ip;
};

/**
 * struct sandbox_instance - Per-open-instance state
 */
struct sandbox_instance {
	struct list_head list_node;	 /* in inst_list (kprobe PID lookup) */
	struct list_head net_node;	 /* in net_inst_list (REPORT_DNS by child_ip) */
	pid_t            registered_pid;
	bool             in_inst_list;
	bool             in_net_inst_list;
	struct sandbox_state state;	 /* blocked_file, decision, etc */
	struct sandbox_net_env *net;	 /* NULL = no network */
	const struct pid_namespace *sandbox_pid_ns;  /* set at SET_PID, for fork child lookup */
	wait_queue_head_t blocked_wait;              /* poll wait queue for blocked event notification */
};

#endif /* _SANDBOX_H */
