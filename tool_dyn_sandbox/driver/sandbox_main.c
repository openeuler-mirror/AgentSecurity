// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_main.c
 *
 * Sandbox char device + init/exit
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/inet.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>

#include "sandbox.h"
#include "sandbox_version.h"
#include "sandbox_net.h"
#include "sandbox_file.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dyn-sandbox team");
MODULE_DESCRIPTION("dyn-sandbox kernel module: network isolation + file runtime authorization");

/* ====================================================================== */
/*  Char device — /dev/dyn-sandbox                                        */
/* ====================================================================== */

static int sandbox_ioctl_check(uint32_t permission, unsigned int cmd);

static long sandbox_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct sandbox_instance *inst = filp->private_data;
	int ret;

	if (!inst)
		return -EBADFD;

	ret = sandbox_ioctl_check(inst->caller_permission, cmd);
	if (ret)
		return ret;

	switch (cmd) {
	/* --- Network ioctls --- */
	case SANDBOX_NET_CREATE:
		return net_create(inst, uarg);

	case SANDBOX_NET_REPORT_DNS:
		return net_report_dns(uarg);

	case SANDBOX_NET_SET_DNS_PORT:
		return net_set_dns_port(uarg);

	/* --- File ioctls --- */
	case SANDBOX_FILE_GET_BLOCKED:
		return sandbox_file_handle_get_blocked(inst, uarg);

	case SANDBOX_FILE_DECISION:
		return sandbox_file_handle_decision(inst, uarg);

	case SANDBOX_FILE_SET_PID:
		return sandbox_file_handle_set_pid(inst, uarg);

	default:
		return -ENOTTY;	/* 兜底: 门禁外的未知命令不应可达 */
	}
}

/*
 * sandbox_ioctl_check - Command-level permission gate for /dev/dyn-sandbox
 * @permission: permission bitmask granted to the caller at open (see
 *              sandbox_caller_permission)
 * @cmd:        ioctl command to check
 *
 * Each trusted binary is granted only the bits for its own role's commands
 * (see sandbox_trusted_exe).  This prevents a compromised dyn-sandbox-dns
 * from issuing launcher commands (NET_CREATE / FILE_*) and vice versa.
 *
 * Return: 0 if allowed, -EPERM if the command is not in the caller's mask,
 *         -ENOTTY if cmd does not carry this device's magic (keeps the
 *         pre-existing unknown-command behavior, e.g. version-skew detection).
 */
static int sandbox_ioctl_check(uint32_t permission, unsigned int cmd)
{
	unsigned int nr;

	if (_IOC_TYPE(cmd) != SANDBOX_IOCTL_MAGIC)
		return -ENOTTY;

	nr = _IOC_NR(cmd);
	if (nr >= 32)
		return -EPERM;	/* NR 超出 uint32_t 位域: 无对应权限位 */

	return (permission & (1U << nr)) ? 0 : -EPERM;
}

/*
 * Only these executables may open /dev/dyn-sandbox.  Matched against the
 * caller's *actual* executable (current->mm->exe_file), NOT current->comm:
 * comm is a user-settable string (prctl(PR_SET_NAME)) and is trivially
 * spoofable.  mm->exe_file is bound at execve() to the real binary's inode,
 * so the process must genuinely be running one of these files.
 *
 * The sandbox core (dyn-sandbox) and the DNS proxy (dyn-sandbox-dns) are
 * installed at /usr/bin by the RPM.  Any other caller — including a sandbox
 * tool after execve() — is rejected.
 *
 * Each entry also carries the ioctl permission mask granted to that binary
 * (its own role only).  sandbox_ioctl_check() enforces it per command, so a
 * compromised dyn-sandbox-dns cannot issue launcher commands (NET_CREATE /
 * FILE_*) and vice versa.
 */
static const struct {
	const char *path;
	uint32_t    permission;
} sandbox_trusted_exe[] = {
	{ "/usr/bin/dyn-sandbox",
	  SANDBOX_PERM(SANDBOX_NET_CREATE) | SANDBOX_PERM(SANDBOX_FILE_GET_BLOCKED) |
	  SANDBOX_PERM(SANDBOX_FILE_DECISION) | SANDBOX_PERM(SANDBOX_FILE_SET_PID) },
	{ "/usr/bin/dyn-sandbox-dns",
	  SANDBOX_PERM(SANDBOX_NET_REPORT_DNS) | SANDBOX_PERM(SANDBOX_NET_SET_DNS_PORT) },
};

/**
 * sandbox_caller_permission - Resolve the current process's ioctl permission
 *
 * Resolves the caller's executable path via d_path() on mm->exe_file and
 * compares it byte-for-byte against the trusted list.  Full-path exact
 * matching only — a copied binary named "dyn-sandbox" elsewhere must NOT
 * pass, and prefix/basename matches are rejected too.
 *
 * Return: the granted permission bitmask if trusted, 0 otherwise.
 */
static uint32_t sandbox_caller_permission(void)
{
	struct mm_struct *mm = current->mm;
	struct file *exe_file;
	char *buf;
	char *path;
	uint32_t permission = 0;
	int i;

	/* Kernel threads / exec teardown edge cases have no usable exe. */
	if (!mm)
		return 0;

	rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	/* kernel >= 7.0: get_file_rcu() takes struct file ** and returns the
	 * file (NULL when the refcount was already zero); the lockless pattern
	 * rcu_dereference() + get_file_rcu() is folded into it. */
	exe_file = get_file_rcu(&mm->exe_file);
#else
	/* kernel < 7.0: get_file_rcu(struct file *) is a refcount bump on an
	 * already-dereferenced pointer — must rcu_dereference() first. */
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
#endif
	rcu_read_unlock();
	if (!exe_file)
		return 0;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (buf) {
		path = d_path(&exe_file->f_path, buf, PAGE_SIZE);
		if (!IS_ERR(path)) {
			for (i = 0; i < ARRAY_SIZE(sandbox_trusted_exe); i++) {
				if (strcmp(path, sandbox_trusted_exe[i].path) == 0) {
					permission = sandbox_trusted_exe[i].permission;
					break;
				}
			}
		}
		free_page((unsigned long)buf);
	}
	fput(exe_file);

	return permission;
}

/**
 * sandbox_open - Allocate per-open instance on device open
 * @inode: inode of /dev/dyn-sandbox
 * @filp:  file pointer to attach the instance to
 *
 * Authenticates the caller first: only the trusted binaries (see
 * sandbox_caller_permission) may open the device, and each is granted only
 * its own ioctl permission mask.  Anything else — an attacker, or a sandbox
 * tool that execve'd something else — gets -EPERM before any instance is
 * allocated.
 *
 * Return: 0 on success, -EPERM if the caller is not a trusted binary,
 *         -ENOMEM on allocation failure
 */
static int sandbox_open(struct inode *inode, struct file *filp)
{
	struct sandbox_instance *inst;
	uint32_t permission;

	permission = sandbox_caller_permission();
	if (permission == 0)
		return -EPERM;

	inst = kzalloc(sizeof(*inst), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	inst->caller_permission = permission;

	kref_init(&inst->ref); /* root reference owned by sandbox_release */
	INIT_LIST_HEAD(&inst->net_node);
	INIT_LIST_HEAD(&inst->state.blocked_list);
	INIT_LIST_HEAD(&inst->state.blocked_flag_list);
	spin_lock_init(&inst->state.blocked_lock);
	init_waitqueue_head(&inst->blocked_wait);
	filp->private_data = inst;

	pr_info("dyn-sandbox: opened by pid=%d\n", current->pid);
	return 0;
}

/**
 * inst_release - kref release callback.  May run in atomic kprobe context
 * (a handler can drop the last transient reference), so only atomic-safe
 * teardown here: sandbox_file_drain_blocks() then kfree(inst).
 */
void inst_release(struct kref *kref)
{
	struct sandbox_instance *inst = container_of(kref, struct sandbox_instance, ref);

	sandbox_file_drain_blocks(inst);
	kfree(inst);
}

/**
 * sandbox_release - Clean up file auth state + network env, then drop the
 * instance's root reference (drain + kfree happen in inst_release()).
 */
static int sandbox_release(struct inode *inode, struct file *filp)
{
	struct sandbox_instance *inst = filp->private_data;

	if (!inst)
		return 0;

	sandbox_file_release(inst);

	if (inst->net)
		net_destroy(inst);

	kref_put(&inst->ref, inst_release);
	filp->private_data = NULL;
	return 0;
}

static __poll_t sandbox_poll(struct file *filp, poll_table *wait)
{
	struct sandbox_instance *inst = filp->private_data;
	__poll_t mask = 0;
	unsigned long flags;
	if (!inst)
		return 0;

	poll_wait(filp, &inst->blocked_wait, wait);

	/* blocked_list is mutated by kretprobe/DECISION concurrently; read under the same lock */
	spin_lock_irqsave(&inst->state.blocked_lock, flags);
	if (!list_empty(&inst->state.blocked_list))
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock_irqrestore(&inst->state.blocked_lock, flags);

	return mask;
}

static struct file_operations sandbox_fops = {
	.owner          = THIS_MODULE,
	.open           = sandbox_open,
	.release        = sandbox_release,
	.unlocked_ioctl = sandbox_ioctl,
	.poll           = sandbox_poll,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = sandbox_ioctl,
#endif
};

/* ====================================================================== */
/*  Module init / exit                                                     */
/* ====================================================================== */

static dev_t         sandbox_devno;
static struct cdev   sandbox_cdev;
static struct class *sandbox_class;
static struct device *sandbox_dev;

/**
 * sandbox_devnode - Set /dev/dyn-sandbox permissions to 0666
 * @dev: device
 * @mode: pointer to store the mode
 *
 * Return: NULL (default devnode)
 */
static char *sandbox_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return NULL;
}

/**
 * sandbox_init - Module init entry
 *
 * 1. Register /dev/dyn-sandbox char device
 * 2. Initialize file runtime authorization (kretprobes + Landlock symbols)
 *
 * Return: 0 on success, negative errno on failure
 */
static int __init sandbox_init(void)
{
	int ret;

	/* 0. Refuse loading on a kernel that differs from the build kernel */
	if (!sandbox_version_matches_build()) {
		pr_err("dyn-sandbox: running kernel %s does not match the build "
		       "kernel %u.%u; refusing to load.\n",
		       utsname()->release,
		       (LINUX_VERSION_CODE >> 16) & 0xff,
		       (LINUX_VERSION_CODE >> 8) & 0xff);
		return -EOPNOTSUPP;
	}

	/* 1. Register char device */
	ret = alloc_chrdev_region(&sandbox_devno, 0, 1, "dyn-sandbox");
	if (ret < 0) {
		pr_err("dyn-sandbox: alloc_chrdev_region: %d\n", ret);
		return ret;
	}

	cdev_init(&sandbox_cdev, &sandbox_fops);
	sandbox_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sandbox_cdev, sandbox_devno, 1);
	if (ret) {
		pr_err("dyn-sandbox: cdev_add: %d\n", ret);
		goto err_unreg;
	}

	sandbox_class = class_create("dyn-sandbox");
	if (IS_ERR(sandbox_class)) {
		ret = PTR_ERR(sandbox_class);
		pr_err("dyn-sandbox: class_create: %d\n", ret);
		goto err_cdev;
	}
	sandbox_class->devnode = sandbox_devnode;

	sandbox_dev = device_create(sandbox_class, NULL, sandbox_devno,
				     NULL, "dyn-sandbox");
	if (IS_ERR(sandbox_dev)) {
		ret = PTR_ERR(sandbox_dev);
		pr_err("dyn-sandbox: device_create: %d\n", ret);
		goto err_class;
	}

	pr_info("dyn-sandbox: /dev/dyn-sandbox registered, major=%d\n", MAJOR(sandbox_devno));

	/* 2. File auth init (kretprobes + Landlock symbol resolution) */
	ret = sandbox_file_init();
	if (ret)
		goto err_class;

	/* 3. Network init (subnet auto-detection + MASQUERADE) */
	ret = net_init();
	if (ret) {
		pr_err("dyn-sandbox: net_init failed (%d), aborting\n", ret);
		goto err_file;
	}

	return 0;

err_file:
	sandbox_file_exit();
err_class:
	if (sandbox_dev)
		device_destroy(sandbox_class, sandbox_devno);
	class_destroy(sandbox_class);
err_cdev:
	cdev_del(&sandbox_cdev);
err_unreg:
	unregister_chrdev_region(sandbox_devno, 1);
	return ret;
}

/**
 * sandbox_exit - Module exit
 *
 * 1. Teardown file runtime authorization (kretprobes, inst_list)
 * 2. Remove nftables MASQUERADE
 * 3. Clean up char device
 */
static void __exit sandbox_exit(void)
{
	/* 1. File auth cleanup (unregisters kprobes, cleans inst_list) */
	sandbox_file_exit();

	/* 2. Remove MASQUERADE */
	net_cleanup_nat();

	/* 3. Clean up char device */
	if (sandbox_dev)
		device_destroy(sandbox_class, sandbox_devno);
	if (sandbox_class)
		class_destroy(sandbox_class);
	cdev_del(&sandbox_cdev);
	unregister_chrdev_region(sandbox_devno, 1);

	pr_info("dyn-sandbox: unloaded\n");
}

module_init(sandbox_init);
module_exit(sandbox_exit);
