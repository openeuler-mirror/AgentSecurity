/*
 * sandbox_landlock.h
 *
 * Landlock runtime authorization interface
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
#ifndef _SANDBOX_LANDLOCK_H
#define _SANDBOX_LANDLOCK_H

#include <linux/types.h>
#include <linux/path.h>

/**
 * sandbox_lbs_cred - Landlock security blob offset for cred.
 *
 * Set during module init; used by ioctl handler to locate the
 * Landlock ruleset from a task's credentials.
 */
extern int sandbox_lbs_cred;

/** sandbox_lbs_file - Landlock security blob offset for file.
 *
 * Used by hook_file_truncate decision handler to modify the cached
 * allowed_access on a struct file.
 */
extern int sandbox_lbs_file;

/**
 * sandbox_landlock_resolve_kln - Resolve kallsyms_lookup_name (once, cached).
 *
 * The cached function pointer is shared by sandbox_landlock_probe() and
 * sandbox_landlock_init().  Resolution is owned by the caller
 * (sandbox_file_init) so that a failure can abort module loading there —
 * without kallsyms_lookup_name the module cannot even determine whether
 * Landlock is active, so graceful degradation is not allowed.
 *
 * Return: 0 on success, -EOPNOTSUPP if kallsyms_lookup_name cannot be resolved
 *         (kallsyms/kprobes unavailable).
 */
int sandbox_landlock_resolve_kln(void);

/**
 * sandbox_landlock_probe - Early availability check (runs before init).
 *
 * Returns true only if lsm_names contains "landlock" — i.e. the LSM is
 * compiled in AND actually enabled, so its security blobs are allocated.
 * Callers must run this before sandbox_landlock_init().  On false: when the
 * module was loaded with landlock_enable=1 the caller aborts (strict failure);
 * when landlock_enable is unspecified (auto, -1) the caller degrades gracefully
 * and skips Landlock file-auth initialization.
 */
bool sandbox_landlock_probe(void);

/** sandbox_landlock_init - Initialize Landlock runtime support — resolves internal symbols. */
int sandbox_landlock_init(void);

/**
 * sandbox_landlock_ready - Is Landlock runtime authorization active?
 *
 * True once sandbox_landlock_init() succeeded, i.e. the Landlock symbols and
 * blob layout were resolved and validated (the caller's probe confirmed
 * lsm_names contains landlock).  It does NOT track kretprobe registration —
 * that is the caller's concern, and the caller keeps the two consistent
 * (deactivates on kretprobe failure).
 */
bool sandbox_landlock_ready(void);

/**
 * sandbox_landlock_deactivate - Mark Landlock runtime authorization inactive.
 *
 * Used when a partial enable fails (err_kprobes unwind) or Landlock was
 * skipped, so DECISION_ALLOW is refused and kprobes are not re-unregistered.
 */
void sandbox_landlock_deactivate(void);

/**
 * sandbox_landlock_allow_path - Dynamically grant access to a path in a Landlock ruleset
 *
 * Returns 0 on success, negative errno on failure.
 */
int sandbox_landlock_allow_path(struct path *path, void *dom, u16 access_mask);

#endif /* _SANDBOX_LANDLOCK_H */
