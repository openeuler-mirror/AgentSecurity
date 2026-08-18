// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_landlock.c
 *
 * Landlock runtime authorization helpers
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */

/*
 * KERNEL VERSION DEPENDENCIES:
 *
 * 1. ll_ruleset / ll_rule / ll_object / ll_layer struct layouts
 *    Mirror security/landlock/{ruleset.h,object.h} — internal Landlock
 *    types NOT exposed to modules.  Layout changes between kernel
 *    versions break the mirror.  Known example: kernel >= 6.7 adds
 *    root_net_port to struct landlock_ruleset, shifting all fields
 *    after it; a build for 6.6 will silently corrupt data on 6.7+.
 *
 * 2. landlock_fs_underops (via kallsyms_lookup_name)
 *    static const in security/landlock/fs.c.  Its symbol is only
 *    present in kallsyms when CONFIG_KALLSYMS_ALL=y.
 *
 * 3. landlock_create_object (via kprobe address)
 *    Defined in security/landlock/object.c.  Not EXPORT_SYMBOL'd.
 *    Function name and signature may change across versions.
 *
 * 4. struct lsm_blob_sizes (landlock_blob_sizes global)
 *    Read via kallsyms + the PUBLIC header <linux/lsm_hooks.h> for the
 *    struct type — no manual mirror, so field reordering/insertion is
 *    picked up on rebuild.  landlock_blob_sizes itself is a non-static
 *    global in security/landlock/setup.c (only the type is public).
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>
#include <linux/lsm_hooks.h>
#include <linux/string.h>
#include <linux/version.h>
#include <uapi/linux/landlock.h>

#include "sandbox_landlock.h"
#include "sandbox_landlock_layout.h"

/* Landlock LSM internal structures (kernel 6.8.0-136-generic, BTF-based) */
int sandbox_lbs_cred  = -1;
int sandbox_lbs_file  = -1;
static int sandbox_lbs_inode = -1;

static void *(*ll_create_object)(const void *underops, void *underobj);
static const struct ll_object_underops *ll_fs_underops;
static const struct lsm_blob_sizes *ll_blob_sizes;

/* Cached kallsyms_lookup_name, resolved once by the availability probe. */
static unsigned long (*kln)(const char *);

/* True only after init confirmed symbol presence AND the availability probe
 * confirmed lsm_names contains landlock (i.e. the LSM actually ran
 * landlock_init and allocated blobs). */
static bool landlock_active = false;

bool sandbox_landlock_ready(void)
{
	return landlock_active;
}

void sandbox_landlock_deactivate(void)
{
	landlock_active = false;
}

static bool rb_rule_less(struct rb_node *a, const struct rb_node *b)
{
	return rb_entry(a, struct ll_rule, node)->key.object <
	       rb_entry(b, struct ll_rule, node)->key.object;
}

static int rb_rule_cmp(const void *key, const struct rb_node *node)
{
	const struct ll_object *obj = key;
	const struct ll_object *this_obj = rb_entry(node, struct ll_rule, node)->key.object;

	/*
	 * rb_find() convention: cmp(key,node) < 0 -> go left (key < node).
	 * This must match the tree order built by rb_rule_less() (smaller
	 * objects on the left) and landlock's own landlock_find_rule()
	 * (this->key.data < id.key.data -> rb_right).
	 */
	if (obj < this_obj)
		return -1;
	if (obj > this_obj)
		return 1;
	return 0;
}

static struct ll_rule *rule_alloc_init(struct ll_object *obj, u32 num_layers, u16 access)
{
	struct ll_rule *rule;
	unsigned int i;

	rule = kzalloc(sizeof(*rule) + num_layers * sizeof(struct ll_layer), GFP_KERNEL);
	if (!rule)
		return NULL;

	rule->key.object = obj;
	rule->num_layers = num_layers;
	for (i = 0; i < num_layers; i++)
		rule->layers[i] = (struct ll_layer){
			.level = num_layers,
			.access = access,
		};
	return rule;
}

int sandbox_landlock_allow_path(struct path *path, void *dom_ptr, u16 access_mask)
{
	struct ll_ruleset *dom = dom_ptr;
	struct inode *inode;
	struct ll_object *obj;
	struct ll_rule *rule;
	bool owns_obj = false;   /* obj was created here, not yet adopted by a rule/blob */
	bool locked   = false;
	int ret = -ENOMEM;

	if (!path || !dom_ptr)
		return -EINVAL;
	if (!landlock_active || !ll_blob_sizes)
		return -EOPNOTSUPP;

	inode = d_backing_inode(path->dentry);
	if (!inode)
		return -ENOENT;

	rcu_read_lock();
	obj = *(void __rcu **)(inode->i_security + sandbox_lbs_inode);
	if (obj)
		obj = (void *)rcu_dereference(obj);
	rcu_read_unlock();

	if (!obj) {
		obj = ll_create_object(ll_fs_underops, inode);
		if (!obj)
			goto err;
		owns_obj = true;
	}

	if (!mutex_trylock(&dom->lock)) {
		pr_warn_ratelimited("dyn-sandbox: domain lock contended (child is STOPPED, should not happen)\n");
		ret = -EAGAIN;
		goto err;
	}
	locked = true;

	rule = rb_entry(rb_find(obj, LL_RULESET_ROOT(dom), rb_rule_cmp), struct ll_rule, node);
	if (rule) {
		unsigned int i;
		pr_info("dyn-sandbox: ALLOW_PATH ino=%lu access=0x%x UPDATE layers_before=[",
			inode->i_ino, access_mask);
		for (i = 0; i < rule->num_layers; i++)
			pr_cont("(lvl=%u acc=0x%x)",
				rule->layers[i].level,
				rule->layers[i].access);
		pr_cont("]\n");
		for (i = 0; i < rule->num_layers; i++)
			rule->layers[i].access |= access_mask;
	} else {
		pr_info("dyn-sandbox: ALLOW_PATH ino=%lu access=0x%x INSERT\n",
			inode->i_ino, access_mask);
		rule = rule_alloc_init(obj, dom->num_layers, access_mask);
		if (!rule)
			goto err;      /* err releases the mutex */
		/* A newly created obj has usage=1 as this rule's reference (same handoff as
		 * create_rule); take +1 only when obj came from the inode blob (already
		 * referenced by another rule). */
		if (!owns_obj)
			refcount_inc(&obj->usage);
		owns_obj = false;  /* rule holds the obj reference now, not this function */
		rb_add(&rule->node, LL_RULESET_ROOT(dom), rb_rule_less);
		dom->num_rules++;
	}

	mutex_unlock(&dom->lock);
	locked = false;

	if (!rcu_access_pointer(*(void __rcu **)(inode->i_security + sandbox_lbs_inode))) {
		rcu_read_lock();
		if (!rcu_dereference(*(void __rcu **)(inode->i_security + sandbox_lbs_inode))) {
			ihold(inode);
			rcu_assign_pointer(*(void __rcu **)(inode->i_security + sandbox_lbs_inode), obj);
		}
		rcu_read_unlock();
	}

	return 0;

err:
	if (locked)
		mutex_unlock(&dom->lock);
	if (owns_obj)
		kfree(obj);
	return ret;
}

static void probe_landlock_offsets(const struct lsm_blob_sizes *blob)
{
	ll_blob_sizes = blob;

	sandbox_lbs_cred  = blob->lbs_cred;
	sandbox_lbs_file  = blob->lbs_file;
	sandbox_lbs_inode = blob->lbs_inode;
	pr_info("dyn-sandbox: landlock_blob_sizes @ %p, lbs_cred=%d, lbs_file=%d, lbs_inode=%d\n",
		blob, sandbox_lbs_cred, sandbox_lbs_file, sandbox_lbs_inode);
}

/**
 * sandbox_landlock_resolve_kln - Resolve kallsyms_lookup_name (once, cached).
 *
 * See sandbox_landlock.h for the full contract.
 */
int sandbox_landlock_resolve_kln(void)
{
	struct kprobe kp_kl = { .symbol_name = "kallsyms_lookup_name" };

	if (kln)
		return 0;
	if (register_kprobe(&kp_kl) == 0) {
		kln = (void *)kp_kl.addr;
		unregister_kprobe(&kp_kl);
	}
	return kln ? 0 : -EOPNOTSUPP;
}

/**
 * sandbox_landlock_probe - Early check: is the Landlock LSM actually active?
 *
 * Runs BEFORE sandbox_landlock_init().  Requires kallsyms_lookup_name to have
 * been resolved first via sandbox_landlock_resolve_kln().  Uses lsm_names —
 * the framework-level list of *actually-enabled* LSMs (the data behind
 * /sys/kernel/security/lsm).  Symbol presence only proves Landlock was compiled
 * in; if the LSM was not put on the active list, landlock_init() never ran and
 * its security blobs were never allocated, so cred->security + sandbox_lbs_cred
 * would be a wild deref later.
 *
 * Return: true if the kernel runs Landlock, false otherwise (caller aborts
 *         when landlock_enable=1, or degrades gracefully when auto).
 */
bool sandbox_landlock_probe(void)
{
	unsigned long addr;

	if (!kln) {
		pr_warn("dyn-sandbox: kallsyms_lookup_name not resolved; probe aborted\n");
		return false;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	/*
	 * kernel >= 7.0: the global lsm_names symbol is gone; /sys/kernel/security/lsm
	 * is now filled by security/inode.c:lsm_read() from lsm_idlist[MAX_LSM_COUNT] +
	 * lsm_active_cnt (security/security.c). Match "landlock" by walking the active list.
	 */
	{
		const struct lsm_id **idlist;
		unsigned int *acnt;
		int i;

		addr = kln("lsm_idlist");
		acnt = (unsigned int *)kln("lsm_active_cnt");
		if (!addr || !acnt) {
			pr_warn("dyn-sandbox: cannot resolve lsm_idlist/lsm_active_cnt\n");
			return false;
		}

		idlist = (const struct lsm_id **)addr;
		for (i = 0; i < *acnt; i++) {
			if (idlist[i] && strcmp(idlist[i]->name, "landlock") == 0)
				return true;
		}

		pr_warn("dyn-sandbox: landlock not in active LSM list, LSM inactive\n");
		return false;
	}
#else
	/* openEuler 6.6 / kernel < 7.0: match via lsm_names as before */
	{
		const char *names;

		addr = kln("lsm_names");
		if (!addr) {
			pr_warn("dyn-sandbox: cannot resolve lsm_names\n");
			return false;
		}

		names = *(const char **)addr;
		if (!names || !strstr(names, "landlock")) {
			pr_warn("dyn-sandbox: landlock not in lsm_names (%s), LSM inactive\n",
				names ? names : "<null>");
			return false;
		}

		return true;
	}
#endif
}

int sandbox_landlock_init(void)
{
	struct kprobe kp_cr = { .symbol_name = "landlock_create_object" };

	if (!kln) {
		pr_err("dyn-sandbox: kallsyms_lookup_name not resolved, aborting Landlock init\n");
		return -EOPNOTSUPP;
	}

	if (register_kprobe(&kp_cr) == 0) {
		ll_create_object = (void *)kp_cr.addr;
		unregister_kprobe(&kp_cr);
	}

	ll_fs_underops = (const struct ll_object_underops *)kln("landlock_fs_underops");

	ll_blob_sizes = (const struct lsm_blob_sizes *)kln("landlock_blob_sizes");
	if (ll_blob_sizes)
		probe_landlock_offsets(ll_blob_sizes);

	if (!ll_create_object || !ll_fs_underops || !ll_blob_sizes) {
		pr_warn("dyn-sandbox: Landlock symbol resolution incomplete "
			"(create_obj=%s underops=%s blob_sizes=%s), ALLOW_FILE disabled\n",
			ll_create_object ? "ok" : "missing",
			ll_fs_underops ? "ok" : "missing",
			ll_blob_sizes ? "ok" : "missing");
		return -EOPNOTSUPP;
	}

	landlock_active = true;

	pr_info("dyn-sandbox: create_obj=%p underops=%p lbs_cred=%d lbs_file=%d lbs_inode=%d\n",
		ll_create_object, ll_fs_underops,
		sandbox_lbs_cred, sandbox_lbs_file, sandbox_lbs_inode);

	return 0;
}
