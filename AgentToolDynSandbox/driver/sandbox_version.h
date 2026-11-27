// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_version.h
 *
 * Supported-kernel whitelist
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 */
#ifndef _SANDBOX_VERSION_H
#define _SANDBOX_VERSION_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/utsname.h>

/*
 * SUPPORTED KERNEL WHITELIST
 *
 * dyn_sandbox.ko mirrors non-exported Landlock internals and internal
 * kprobe symbols, which change between kernel versions.  A mismatch does
 * not fail to compile — a wrong layout silently corrupts data — so we
 * only build for / load on the support kernels (matched by maj-min).
 *
 * Two layers of enforcement:
 *   1. build: #error below aborts make on an unsupported kernel.
 *   2. load:  sandbox_version_matches_build() in sandbox_init() refuses
 *             to load if the RUNNING kernel differs from the build
 *             kernel (guards against --force / vermagic bypass).
 *
 * Add a kernel by extending SANDBOX_SUPPORTED below.
 */

#define VERSION_MAJ_MIN(maj, min)	(((maj) << 16) | ((min) << 8))
#define VERSION_NOSUB(code)	((code) & ~0xff)

/* One line per support kernel series — add a new kernel by adding a line. */
#define SANDBOX_SUPPORTED(code) \
	((code) == VERSION_MAJ_MIN(6, 6) || \
	 (code) == VERSION_MAJ_MIN(6, 8) || \
	 (code) == VERSION_MAJ_MIN(7, 0))

#if !SANDBOX_SUPPORTED(VERSION_NOSUB(LINUX_VERSION_CODE))
#error "dyn-sandbox: unsupported kernel version - support on 6.6 / 6.8 / 7.0 (see sandbox_version.h)"
#endif

/* Parse "major.minor" out of utsname()->release (e.g. "7.0.0-28-generic").
 * Pure integer arithmetic, no lib deps. */
static inline void sandbox_version_parse(const char *s, int *maj, int *min)
{
	int a = 0, b = 0;

	*maj = *min = 0;
	if (!s)
		return;
	while (*s >= '0' && *s <= '9')
		a = a * 10 + (*s++ - '0');
	if (*s++ != '.')
		return;
	while (*s >= '0' && *s <= '9')
		b = b * 10 + (*s++ - '0');
	*maj = a;
	*min = b;
}

/**
 * sandbox_version_matches_build - Does the RUNNING kernel match the build kernel?
 *
 * Reads utsname()->release at load time — the layout/symbol reasoning and
 * the --force / vermagic-bypass rationale are in the whitelist block above.
 *
 * Return: true when major.minor matches the build kernel, false otherwise.
 *         Fail-closed: an unparseable release string is refused.
 */
static inline bool sandbox_version_matches_build(void)
{
	int maj, min;

	sandbox_version_parse(utsname()->release, &maj, &min);
	return VERSION_MAJ_MIN(maj, min) == VERSION_NOSUB(LINUX_VERSION_CODE);
}

#endif /* _SANDBOX_VERSION_H */
