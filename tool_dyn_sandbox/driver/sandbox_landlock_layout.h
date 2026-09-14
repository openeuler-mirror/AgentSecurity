// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_landlock_layout.h
 *
 * Mirrors of kernel-internal Landlock types from
 * security/landlock/{ruleset.h,object.h,fs.c} — NOT part of the stable
 * kernel API; layouts change between versions.  ll_ruleset is selected at
 * build time from LINUX_VERSION_CODE (6.7+ vs 6.6, BTF-verified on
 * 6.8.0-136-generic and openEuler 6.6.0-159.4.3.154).  Porting to a new
 * kernel touches only this file for Landlock layout changes.
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 */
#ifndef _SANDBOX_LANDLOCK_LAYOUT_H
#define _SANDBOX_LANDLOCK_LAYOUT_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/version.h>

/* Credential security blob: holds pointer to the ruleset domain */
struct ll_cred_sec {
	void *domain;  /* struct landlock_ruleset * */
};

/* Inode security blob: holds pointer to the landlock_object */
struct ll_inode_sec {
	void *object;  /* struct landlock_object __rcu * */
};

/*
 * struct landlock_object (kernel: security/landlock/object.h)
 * Mirrors offsets 0..15 of the kernel object.  The trailing union is
 * kernel-owned (landlock_create_object()/landlock_put_object() handle
 * alloc/release), so only the refcounted prefix used by
 * ll_get_inode_object() needs mirroring: usage@0, lock@4, underobj@8.
 */
struct ll_object {
	refcount_t usage;     /* offset 0 */
	spinlock_t lock;      /* offset 4 */
	void *underobj;       /* offset 8 */
};

/*
 * struct landlock_layer (kernel: security/landlock/ruleset.h)
 * One permission layer in a Landlock rule.
 */
struct ll_layer {
	u16 level;
	u16 access;
};

/*
 * struct landlock_rule (kernel: security/landlock/ruleset.h)
 * Maps a landlock_object to an array of permission layers.
 */
struct ll_rule {
	struct rb_node node;
	union {
		struct ll_object *object;
		unsigned long data;
	} key;
	u32 num_layers;
	struct ll_layer layers[];
};

/*
 * struct landlock_ruleset (kernel: security/landlock/ruleset.h)
 * Layout selected at build time: 6.7+ has root_inode + root_net_port (net
 * rules landed in 6.7) and u32 access_masks[]; 6.6 has single root and
 * u16 fs_access_masks[] (BTF-verified on 6.8.0-136-generic / openEuler
 * 6.6.0-159.4.3.154).  A mismatched layout silently corrupts data (mutex
 * at wrong offset), so keep the version boundary in sync when porting.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
struct ll_ruleset {
	struct rb_root root_inode;
	struct rb_root root_net_port;
	void *hierarchy;
	struct mutex lock;
	refcount_t usage;
	u32 num_rules;
	u32 num_layers;
	u32 access_masks[];
};
#else
struct ll_ruleset {
	struct rb_root root;
	void *hierarchy;
	struct mutex lock;
	refcount_t usage;
	u32 num_rules;
	u32 num_layers;
	u16 fs_access_masks[];
};
#endif

/* Accessor for the inode-rule rb_root — the only tree used for path-based
 * authorization.  The member was renamed root -> root_inode in 6.7. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define LL_RULESET_ROOT(r) (&(r)->root_inode)
#else
#define LL_RULESET_ROOT(r) (&(r)->root)
#endif

/*
 * struct landlock_object_underops (kernel: security/landlock/object.h)
 * Callbacks for object lifecycle.
 */
struct ll_object_underops {
	void (*release)(const struct ll_object *);
};

#endif /* _SANDBOX_LANDLOCK_LAYOUT_H */
