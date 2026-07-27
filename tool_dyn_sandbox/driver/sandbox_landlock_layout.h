/*
 * sandbox_landlock_layout.h
 *
 * Kernel-version-dependent Landlock internal struct mirrors.
 *
 * ALL definitions in this file mirror kernel-internal types from
 * security/landlock/{ruleset.h,object.h,fs.c}.  These types are NOT
 * part of the stable kernel API and their layouts change between
 * kernel versions.
 *
 * The version-dependent struct (ll_ruleset) is selected at build time
 * from LINUX_VERSION_CODE: the 6.7+ layout (root_inode + root_net_port,
 * u32 access_masks) is BTF-verified on 6.8.0-136-generic; the 6.6 and
 * older layout (single root, u16 fs_access_masks) is verified on
 * openEuler 6.6.0-159.4.3.154.x86_64.
 *
 * When porting to a new kernel, this is the ONLY file that needs
 * updating for Landlock struct layout changes (see the version boundary
 * on ll_ruleset and the LL_RULESET_ROOT() accessor below).
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * Mirrors the kernel-internal object refcounted by Landlock rules.
 */
struct ll_object {
	refcount_t usage;
	spinlock_t lock;
	void *underobj;
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
 *
 * Layout is kernel-version dependent, selected at build time:
 *  - 6.7+: two rb_roots (root_inode, root_net_port) — network rules
 *    landed in 6.7 — then hierarchy and the lock/.../access_masks block
 *    with u32 access_masks (renamed from fs_access_masks, widened).
 *    BTF-verified on 6.8.0-136-generic.
 *  - 6.6 and older: a single 'root' rb_root (inode rules only), and
 *    u16 fs_access_masks.  Verified on openEuler 6.6.0-159.4.3.154.
 *
 * A mismatched layout does not fail to compile — it silently corrupts
 * data (e.g. the mutex lock sits at the wrong offset and allow_path
 * hangs).  Keep the version boundary in sync with the running kernel
 * when porting.
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
