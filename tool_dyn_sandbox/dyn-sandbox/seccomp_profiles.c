// SPDX-License-Identifier: MulanPSL-2.0
/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * dyn-sandbox is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the
 * Mulan PSL v2.  You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/*
 * seccomp_profiles.c — 预置 seccomp profile + 动态 BPF 构建
 *
 * 每个 profile 定义为 syscall 号数组, seccomp_build() 在运行时构建 BPF。
 * 这样新增 syscall 只需在数组中加一项, 无需手写 BPF 指令。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <asm/unistd.h>

/* -- aarch64 compat: map missing or differently-named syscall macros -- */
#ifdef __aarch64__
#ifndef __NR_getpgrp
#define __NR_getpgrp __NR_getpgid
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait __NR_epoll_pwait
#endif
#ifndef __NR_dup2
#define __NR_dup2 __NR_dup3
#endif
#endif  /* __aarch64__ */

  /* 跨架构 syscall 号 (x86_64: asm/unistd_64.h, arm64: asm/unistd.h) */

/* BPF_STMT / BPF_JUMP — kernel headers define these with { } initializer
 * syntax which doesn't work in userspace assignment context. Redefine with
 * compound literals so they can appear on the RHS of =.
 */
#ifdef BPF_STMT
#undef BPF_STMT
#endif
#define BPF_STMT(code, k) \
	((struct sock_filter){ (unsigned short)(code), 0, 0, (unsigned int)(k) })

#ifdef BPF_JUMP
#undef BPF_JUMP
#endif
#define BPF_JUMP(code, k, jt, jf) \
	((struct sock_filter){ (unsigned short)(code), \
			       (unsigned char)(jt), (unsigned char)(jf), \
			       (unsigned int)(k) })

#include "seccomp_profiles.h"

/* 跨架构 AUDIT_ARCH: x86_64 -> X86_64, arm64 -> AARCH64 */
#ifdef __aarch64__
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#endif

/* ------------------------------------------------------------------ */
/*  BPF 指令辅助宏                                                     */
/* ------------------------------------------------------------------ */
#define BPF_LOAD_ARCH   BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4)
#define BPF_JEQ_ARCH(x) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, x, 1, 0)
#define BPF_ALLOW       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define BPF_KILL        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD)
#define BPF_DENY        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
#define BPF_LOAD_SYSCALL BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0)

/* 每个 syscall 需要 3 条 BPF 指令: 加载号 + 判断 + 允许 */
#define BPF_PER_SYSCALL 3

/* ------------------------------------------------------------------ */
/*  glibc 启动必需 -- 跨架构                                          */
/* ------------------------------------------------------------------ */
#ifdef __aarch64__
#define GLIBC_STARTUP \
	__NR_set_tid_address, /* 线程/glibc 初始化 */ \
	__NR_set_robust_list, /* glibc 健性锁初始化 */ \
	__NR_rseq,            /* 可重启序列 (glibc 2.35+) */ \
	__NR_fstat,           /* stat fd (glibc ld.so) */ \
	__NR_prlimit64,       /* 栈限制查询 */       \
	__NR_prctl,           /* NO_NEW_PRIVS + 降权 */ \
	__NR_capset,          /* drop_privileges() */  \
	__NR_chdir            /* chdir workdir */
#elif defined(__x86_64__)
#define GLIBC_STARTUP \
	__NR_arch_prctl,      /* TLS 设置 (x86_64) */ \
	__NR_set_tid_address, /* 线程/glibc 初始化 */ \
	__NR_set_robust_list, /* glibc 健性锁初始化 */ \
	__NR_rseq,            /* 可重启序列 (glibc 2.35+) */ \
	__NR_fstat,           /* stat fd (glibc ld.so) */ \
	__NR_prlimit64,       /* 栈限制查询 */       \
	__NR_prctl,           /* NO_NEW_PRIVS + 降权 */ \
	__NR_capset,          /* drop_privileges() */  \
	__NR_chdir            /* chdir workdir */
#else
#error "Unsupported architecture (only x86_64 and arm64 are supported)"
#endif
/* ------------------------------------------------------------------ */
/*  Profile: default (~31 syscalls) — 保守白名单                       */
/*  适用于: 运行基本命令                                               */
/* ------------------------------------------------------------------ */
static const int default_syscalls[] = {
	GLIBC_STARTUP,
	__NR_execve,
	__NR_read,
	__NR_write,
	__NR_openat,
	__NR_close,
	__NR_mmap,
	__NR_mprotect,
	__NR_munmap,
	__NR_brk,
	__NR_exit_group,
	__NR_exit,
	__NR_newfstatat,
	__NR_lseek,
	__NR_pread64,
	__NR_pwrite64,
#ifdef __x86_64__
	__NR_access,
#endif
	__NR_faccessat,
	__NR_getdents64,
	__NR_dup,
	__NR_dup2,
	__NR_nanosleep,
	/* 信号 — 必须, 否则 SIGUSR1 handler 会被杀死 */
	__NR_rt_sigaction,
	__NR_rt_sigreturn,
	__NR_rt_sigprocmask,
	__NR_getpgrp,
	__NR_futex,
	/* ioctl — 必须, 用于 SANDBOX_FILE_* 交互 */
	__NR_ioctl,
	/* writev — 用于 stderr 输出 */
	__NR_writev,
};

/* ------------------------------------------------------------------ */
/*  Profile: file_access (~28 syscalls) — 文件读写工具                 */
/*  包括 execve + mprotect + access, 可运行动态链接的文件工具          */
/* ------------------------------------------------------------------ */
static const int file_access_syscalls[] = {
	GLIBC_STARTUP,
	__NR_execve,
	__NR_read,
	__NR_write,
	__NR_openat,
	__NR_close,
	__NR_mmap,
	__NR_mprotect,
	__NR_munmap,
	__NR_brk,
	__NR_exit_group,
	__NR_exit,
	__NR_newfstatat,
	__NR_lseek,
	__NR_pread64,
	__NR_pwrite64,
#ifdef __x86_64__
	__NR_access,
#endif
	__NR_rt_sigaction,
	__NR_rt_sigreturn,
	__NR_rt_sigprocmask,
	__NR_getpgrp,
	__NR_futex,
	__NR_ioctl,
	__NR_writev,
};

/* ------------------------------------------------------------------ */
/*  Profile: script (~75 syscalls) — shell/Python 脚本执行            */
/* ------------------------------------------------------------------ */
static const int script_syscalls[] = {
	GLIBC_STARTUP,
	__NR_read,
	__NR_write,
	__NR_openat,
	__NR_close,
	__NR_mmap,
	__NR_mprotect,
	__NR_munmap,
	__NR_brk,
	__NR_exit_group,
	__NR_exit,
	__NR_newfstatat,
	__NR_lseek,
	__NR_pread64,
	__NR_pwrite64,
#ifdef __x86_64__
	__NR_access,
#endif
	__NR_faccessat,
	__NR_getdents64,
	__NR_dup,
	__NR_dup2,
	__NR_nanosleep,
	__NR_rt_sigaction,
	__NR_rt_sigreturn,
	__NR_rt_sigprocmask,
	__NR_getpgrp,
	__NR_futex,
	__NR_ioctl,
	__NR_writev,
	__NR_execve,
	__NR_clone,
	__NR_clone3,
#ifdef __x86_64__
	__NR_vfork,
#endif
	__NR_wait4,
	__NR_waitid,
	__NR_pipe2,
	__NR_socket,
	__NR_connect,
	__NR_bind,
	__NR_listen,
	__NR_accept,
	__NR_getsockname,
	__NR_getpeername,
	__NR_setsockopt,
	__NR_getsockopt,
	__NR_sendto,
	__NR_recvfrom,
	__NR_sendmsg,
	__NR_recvmsg,
	/* 网络 I/O 必需: 多路复用/关闭/批量收发 (curl/py 都会用到) */
	/* poll/select 仅 x86_64 有; arm64 无该 syscall, glibc 映射到 ppoll/pselect6 */
#ifdef __x86_64__
	__NR_poll,
	__NR_select,
#endif
	__NR_ppoll,
	__NR_pselect6,
	__NR_shutdown,
	__NR_sendmmsg,
	__NR_recvmmsg,
	__NR_fcntl,
#ifdef __x86_64__
	__NR_stat,
#endif
	__NR_statx,
#ifdef __x86_64__
	__NR_readlink,
#endif
	__NR_readlinkat,
	__NR_uname,
	__NR_getcwd,
	__NR_chdir,
	__NR_fchdir,
	__NR_getuid,
	__NR_getgid,
	__NR_geteuid,
	__NR_getegid,
	__NR_getppid,
	__NR_getpid,
	__NR_gettid,
	__NR_sysinfo,
	__NR_clock_gettime,
#ifdef __x86_64__
	__NR_time,
#endif
	/* Python 额外需要的 */
	__NR_eventfd2,
	__NR_epoll_create1,
	__NR_epoll_ctl,
	__NR_epoll_wait,
	__NR_timerfd_create,
	__NR_timerfd_settime,
	__NR_futex,
	__NR_getrandom,
	__NR_sched_yield,
	__NR_set_robust_list,
	__NR_rseq,
};

/* ------------------------------------------------------------------ */
/*  seccomp_build — 从 syscall 数组动态构建 BPF 过滤器                  */
/* ------------------------------------------------------------------ */
struct sock_fprog seccomp_build(const int *syscalls, int count)
{
	/* 布局:
	 *   [0] LD arch
	 *   [1] JEQ arch (1:ok, 0:kill)
	 *   [2] KILL (arch mismatch)
	 *   for each syscall:
	 *     [i*3+3] LD syscall_nr
	 *     [i*3+4] JEQ nr (1:allow, 0:next)
	 *     [i*3+5] ALLOW
	 *   最后: KILL (默认)
	 */
	int len = 3 + count * BPF_PER_SYSCALL + 1;
	struct sock_filter *filter = calloc(len, sizeof(struct sock_filter));
	struct sock_fprog prog = { .len = 0, .filter = NULL };

	if (!filter) {
		fprintf(stderr, "seccomp_build: calloc failed\n");
		return prog;
	}

	int i = 0;
	/* 架构检查 */
	filter[i++] = BPF_LOAD_ARCH;
	filter[i++] = BPF_JEQ_ARCH(SECCOMP_AUDIT_ARCH);
	filter[i++] = BPF_KILL;

	/* 每个 syscall 一条规则 */
	for (int j = 0; j < count; j++) {
		filter[i++] = BPF_LOAD_SYSCALL;
		filter[i++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscalls[j], 0, 1);
		filter[i++] = BPF_ALLOW;
	}

	/* 默认 deny (EPERM, 不杀进程) */
	filter[i++] = BPF_DENY;

	prog.len = i;
	prog.filter = filter;
	return prog;
}

/* ------------------------------------------------------------------ */
/*  seccomp_lookup — 通过名称查找并构建 profile                         */
/* ------------------------------------------------------------------ */
struct sock_fprog seccomp_lookup(const char *name)
{
	const int *syscalls = NULL;
	int count = 0;

	if (strcmp(name, "default") == 0) {
		syscalls = default_syscalls;
		count = sizeof(default_syscalls) / sizeof(default_syscalls[0]);
	} else if (strcmp(name, "file_access") == 0) {
		syscalls = file_access_syscalls;
		count = sizeof(file_access_syscalls) / sizeof(file_access_syscalls[0]);
	} else if (strcmp(name, "script") == 0) {
		syscalls = script_syscalls;
		count = sizeof(script_syscalls) / sizeof(script_syscalls[0]);
	} else {
		struct sock_fprog empty = { .len = 0, .filter = NULL };
		return empty;
	}

	return seccomp_build(syscalls, count);
}

int seccomp_valid_profile(const char *name)
{
	return strcmp(name, "default") == 0 ||
	       strcmp(name, "file_access") == 0 ||
	       strcmp(name, "script") == 0;
}

/* ------------------------------------------------------------------ */
/*  Syscall name-to-number lookup table                                */
/*  Users pass names (matching strace / man syscalls convention)       */
/* ------------------------------------------------------------------ */
struct syscall_map {
	const char *name;
	int nr;
};

static const struct syscall_map syscall_names[] = {
	/* 文件描述符操作 */
	{"read",         __NR_read},
	{"write",        __NR_write},
	{"writev",       __NR_writev},
	{"pread64",      __NR_pread64},
	{"pwrite64",     __NR_pwrite64},
	{"openat",       __NR_openat},
	{"close",        __NR_close},
	{"lseek",        __NR_lseek},
	{"dup",          __NR_dup},
	{"dup2",         __NR_dup2},
	{"dup3",         __NR_dup3},
	{"fcntl",        __NR_fcntl},
	{"ioctl",        __NR_ioctl},
#ifdef __x86_64__
	{"access",       __NR_access},
#endif
	{"faccessat",    __NR_faccessat},
	{"getdents64",   __NR_getdents64},
	/* 内存映射 */
	{"mmap",         __NR_mmap},
	{"munmap",       __NR_munmap},
	{"mprotect",     __NR_mprotect},
	{"brk",          __NR_brk},
	/* 进程/线程 */
	{"exit",         __NR_exit},
	{"exit_group",   __NR_exit_group},
	{"execve",       __NR_execve},
#ifdef __x86_64__
	{"arch_prctl",   __NR_arch_prctl},
#endif
	{"set_tid_address", __NR_set_tid_address},
	{"prlimit64",    __NR_prlimit64},
	{"fstat",        __NR_fstat},
	{"prctl",        __NR_prctl},
	{"capset",       __NR_capset},
	{"chdir",        __NR_chdir},
	{"clone",        __NR_clone},
	{"clone3",       __NR_clone3},
#ifdef __x86_64__
	{"vfork",        __NR_vfork},
#endif
	{"wait4",        __NR_wait4},
	{"waitid",       __NR_waitid},
	{"nanosleep",    __NR_nanosleep},
	{"sched_yield",  __NR_sched_yield},
	{"getrandom",    __NR_getrandom},
	{"set_robust_list", __NR_set_robust_list},
	{"rseq",         __NR_rseq},
	/* 信号 */
	{"rt_sigaction",     __NR_rt_sigaction},
	{"rt_sigreturn",     __NR_rt_sigreturn},
	{"rt_sigprocmask",   __NR_rt_sigprocmask},
	/* 文件系统路径 */
#ifdef __x86_64__
	{"stat",         __NR_stat},
#endif
	{"statx",        __NR_statx},
	{"newfstatat",   __NR_newfstatat},
#ifdef __x86_64__
	{"readlink",     __NR_readlink},
#endif
	{"readlinkat",   __NR_readlinkat},
	{"getcwd",       __NR_getcwd},
	{"chdir",        __NR_chdir},
	{"fchdir",       __NR_fchdir},
	{"uname",        __NR_uname},
	{"pipe2",        __NR_pipe2},
	/* 网络 */
	{"socket",       __NR_socket},
	{"connect",      __NR_connect},
	{"bind",         __NR_bind},
	{"listen",       __NR_listen},
	{"accept",       __NR_accept},
	{"getsockname",  __NR_getsockname},
	{"getpeername",  __NR_getpeername},
	{"setsockopt",   __NR_setsockopt},
	{"getsockopt",   __NR_getsockopt},
	{"sendto",       __NR_sendto},
	{"recvfrom",     __NR_recvfrom},
	{"sendmsg",      __NR_sendmsg},
	{"recvmsg",      __NR_recvmsg},
	/* 时间 */
	{"clock_gettime", __NR_clock_gettime},
#ifdef __x86_64__
	{"time",         __NR_time},
#endif
	/* epoll */
	{"epoll_create1", __NR_epoll_create1},
	{"epoll_ctl",     __NR_epoll_ctl},
	{"epoll_wait",    __NR_epoll_wait},
	{"eventfd2",     __NR_eventfd2},
	{"timerfd_create",  __NR_timerfd_create},
	{"timerfd_settime", __NR_timerfd_settime},
	/* 其他 */
	{"futex",        __NR_futex},
	{"sysinfo",      __NR_sysinfo},
	{"getpid",       __NR_getpid},
	{"gettid",       __NR_gettid},
	{"getppid",      __NR_getppid},
	{"getuid",       __NR_getuid},
	{"getgid",       __NR_getgid},
	{"geteuid",      __NR_geteuid},
	{"getegid",      __NR_getegid},
};

#define NSYSCALL_NAMES (sizeof(syscall_names) / sizeof(syscall_names[0]))

static int syscall_name_to_nr(const char *name)
{
	for (size_t i = 0; i < NSYSCALL_NAMES; i++) {
		if (strcmp(name, syscall_names[i].name) == 0)
			return syscall_names[i].nr;
	}
	return -1;
}

struct sock_fprog seccomp_build_from_names(const char *names)
{
	int syscalls[128];
	int count = 0;

	/* 自动加入 dyn-sandbox 内部必需 + 目标二进制启动必需的 syscall */
	int mandatory[] = {
		__NR_execve,        /* 启动目标二进制 */
		__NR_prctl,         /* NO_NEW_PRIVS + 降权 */
		__NR_capset,        /* drop_privileges() */
		__NR_chdir,         /* chdir workdir */
		__NR_rt_sigaction,  /* 信号重置循环 */
		__NR_close,         /* fd 关闭循环 */
		__NR_openat,        /* drop_privileges fopen */
		__NR_read,          /* drop_privileges fread */
		__NR_fstat,         /* drop_privileges fopen */
		__NR_prlimit64,	/* sysconf(_SC_OPEN_MAX) + glibc */
#ifdef __x86_64__
		__NR_arch_prctl,
#endif
		__NR_set_tid_address,
		__NR_set_robust_list,
		__NR_rseq,
		__NR_mmap,
		__NR_brk,
		__NR_mprotect,
		__NR_munmap,
		__NR_exit_group,
		__NR_exit,
	};
	for (size_t i = 0; i < sizeof(mandatory)/sizeof(mandatory[0]); i++)
		syscalls[count++] = mandatory[i];

	char buf[512];
	char *p, *token;

	strncpy(buf, names, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	p = buf;
	while ((token = strsep(&p, ",")) != NULL) {
		/* skip leading whitespace */
		while (*token == ' ' || *token == '\t')
			token++;
		/* skip trailing whitespace */
		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t'))
			*end-- = '\0';

		if (*token == '\0')
			continue;

		if (count >= 128) {
			fprintf(stderr, "seccomp: too many syscalls (max 128)\n");
			struct sock_fprog empty = { .len = 0, .filter = NULL };
			return empty;
		}

		int nr = syscall_name_to_nr(token);
		if (nr < 0) {
			fprintf(stderr, "seccomp: unknown syscall name: %s\n", token);
			struct sock_fprog empty = { .len = 0, .filter = NULL };
			return empty;
		}
		syscalls[count++] = nr;
	}

	return seccomp_build(syscalls, count);
}
