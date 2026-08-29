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
 * sandbox-run.c — AI Agent Tool 执行沙箱
 *
 * 单进程沙箱生命周期:
 *   1. 解析 CLI 参数
 *   2. 检查 /dev/dyn-sandbox
 *   3. 网络: unshare NEWUSER → unshare NEWNET → ioctl SANDBOX_NET_CREATE
 *   4. unshare NEWNS + MS_PRIVATE
 *   5. pivot_root → tmpfs
 *   6. Bind mount 策略路径, /proc, /dev
 *   7. Landlock restrict_self
 *   8. seccomp-bpf
 *   9. Finalize: 信号/fd/drop caps/NO_NEW_PRIVS
 *  10. execve(tool_cmd)
 *
 * 编译: gcc -o sandbox-run sandbox-run.c param_parse.c seccomp_profiles.c landlock.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <linux/securebits.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <poll.h>
#include <linux/filter.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "../driver/sandbox_dev.h"
#include "param_parse.h"
#include "landlock.h"
#include "seccomp_profiles.h"

/* 退出码 */
#define EXIT_TOOL_OK       0
#define EXIT_TOOL_FAIL     1
#define EXIT_LANDLOCK_ERR  2
#define EXIT_SECCOMP_ERR   3
#define EXIT_MOUNT_ERR     4
#define EXIT_NS_ERR        5
#define EXIT_KPROBE_ERR    6
#define EXIT_NET_ERR       7

static int sandbox_fd = -1;
static int child_wait_fd = -1;  /* eventfd: child 等 parent 写完 UID map */
static in_addr_t sandbox_dns = 0;

/* Pipe forwarding: parent controls child's stdio through pipes */
static int child_stdin[2]  = { -1, -1 };  /* parent writes, child reads  */
static int child_stdout[2] = { -1, -1 };  /* child writes, parent reads */
static int child_stderr[2] = { -1, -1 };  /* child writes, parent reads */

/* child 专用: 直接 _exit, 不调 cleanup_exit (parent 统一清理)
 * child 的 stderr 是 pipe, glibc 默认全缓冲, _exit 前必须 flush */
#define CHILD_FAIL_EXIT(code, msg, ...)                                    \
	do {                                                                 \
		fprintf(stderr, "dyn-sandbox: " msg "\n", ##__VA_ARGS__);   \
		fflush(stderr);                                              \
		_exit(code);                                                 \
	} while (0)

static void cleanup_exit(int code)
{
	/* 关闭 fd 会自动触发 sandbox_release → net_destroy (per-instance) */
	if (sandbox_fd >= 0) {
		close(sandbox_fd);
		sandbox_fd = -1;
	}
	exit(code);
}

/* ------------------------------------------------------------------ */
/*  安全降权                                                           */
/* ------------------------------------------------------------------ */
static void drop_privileges(void)
{
	FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
	int last_cap = 63;
	if (f) {
		char buf[16];
		if (fgets(buf, sizeof(buf), f)) {
			char *end;
			errno = 0;
			long v = strtol(buf, &end, 10);
			/* buf 以 '\n' 结尾; 只接受纯数字, 否则保持默认值 63 */
			if (errno != ERANGE && end != buf &&
			    (*end == '\0' || *end == '\n') &&
			    v >= 0 && v <= 63)
				last_cap = (int)v;
		}
		fclose(f);
	}

	for (int i = 0; i <= last_cap; i++)
		prctl(PR_CAPBSET_DROP, i, 0, 0, 0);

	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = { {0, 0, 0}, {0, 0, 0} };
	syscall(SYS_capset, &hdr, data);

	prctl(PR_SET_SECUREBITS,
		SECBIT_NOROOT | SECBIT_NOROOT_LOCKED, 0, 0, 0);
}

/* ------------------------------------------------------------------ */
/*  raw_clone — fork 风格创建子进程 + 新命名空间                         */
/* ------------------------------------------------------------------ */
/**
 * mkdir_p - mkdir -p equivalent: create directory hierarchy recursively
 * @path: absolute path to create (modified in-place by mkdir(2), copy first)
 *
 * Iterates through each path component, creating each non-existent
 * directory along the way.
 *
 * Return: 0 on success, -1 on error (errno set by last failed mkdir).
 */
static int mkdir_p(const char *path)
{
       char buf[PATH_MAX], *p;

       strncpy(buf, path, sizeof(buf) - 1);
       buf[sizeof(buf) - 1] = '\0';

       if (buf[0] != '/')
               return -1;

       for (p = buf + 1; *p; p++) {
               if (*p != '/')
                       continue;
               *p = '\0';
               if (mkdir(buf, 0755) < 0 && errno != EEXIST) {
                       *p = '/';
                       return -1;
               }
               *p = '/';
       }
       /* Last component */
       if (mkdir(buf, 0755) < 0 && errno != EEXIST)
               return -1;
       return 0;
}

static pid_t raw_clone_wrapper(unsigned long flags)
{
	/* 直接 syscall 跳过 glibc 的 clone(fn, stack, ...) 封装,
	 * 传 NULL 栈使子进程从调用点继续执行 (COW 共享 parent 栈) */
	return (pid_t)syscall(SYS_clone, flags, NULL);
}

/* ------------------------------------------------------------------ */
/*  写 uid/gid map (parent → child, 非 root 时需要)                    */
/* ------------------------------------------------------------------ */
static void write_uid_gid_map(pid_t child_pid)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
	FILE *f = fopen(path, "w");
	if (f) {
		fprintf(f, "0 %d 1\n", uid);
		fclose(f);
	} else {
		fprintf(stderr, "dyn-sandbox: cannot write %s: %s\n", path, strerror(errno));
	}

	snprintf(path, sizeof(path), "/proc/%d/setgroups", child_pid);
	f = fopen(path, "w");
	if (f) {
		fprintf(f, "deny\n");
		fclose(f);
	}

	snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
	f = fopen(path, "w");
	if (f) {
		fprintf(f, "0 %d 1\n", gid);
		fclose(f);
	} else {
		fprintf(stderr, "dyn-sandbox: cannot write %s: %s\n", path, strerror(errno));
	}
}


/* ------------------------------------------------------------------ */
/*  bind_mount_override — 覆盖宿主机文件, 正确处理 symlink 场景        */
/*  如果 target 是 symlink, 解析到实际路径后 mount;                     */
/*  如果是普通文件, 直接 mount --bind 覆盖                              */
/* ------------------------------------------------------------------ */
static void bind_mount_override(const char *src, const char *target)
{
	char resolved[512];
	struct stat st;

	if (lstat(target, &st) == 0 && S_ISLNK(st.st_mode)) {
		char linkbuf[256];
		ssize_t llen = readlink(target, linkbuf, sizeof(linkbuf) - 1);
		if (llen > 0) {
			linkbuf[llen] = '\0';
			if (linkbuf[0] == '/') {
				snprintf(resolved, sizeof(resolved), "%s", linkbuf);
			} else {
				/* 相对 symlink, 基于 target 所在目录解析 */
				const char *slash = strrchr(target, '/');
				if (slash && slash != target) {
					size_t dirlen = slash - target;
					snprintf(resolved, sizeof(resolved), "%.*s/%s",
						 (int)dirlen, target, linkbuf);
				} else {
					snprintf(resolved, sizeof(resolved), "/%s", linkbuf);
				}
			}

			/* 创建父目录 */
			char *sep = strrchr(resolved, '/');
			if (sep) {
				*sep = '\0';
				if (mkdir_p(resolved) < 0)
					fprintf(stderr, "dyn-sandbox: warning: mkdir_p %s: %s\n",
						resolved, strerror(errno));
				*sep = '/';
			}
		} else {
			snprintf(resolved, sizeof(resolved), "%s", target);
		}
	} else {
		snprintf(resolved, sizeof(resolved), "%s", target);
	}

	if (mount(src, resolved, NULL, MS_BIND, NULL) < 0) {
		fprintf(stderr, "dyn-sandbox: warning: mount override %s -> %s failed: %s\n",
			src, resolved, strerror(errno));
	}
}

/* ------------------------------------------------------------------ */
/*  pivot_root_into_tmpfs — 创建 tmpfs 根并 pivot_root                 */
/* ------------------------------------------------------------------ */
static int pivot_root_into_tmpfs(void)
{
	char base_path[] = "/tmp/sandbox-XXXXXX";
	char oldroot[512];
	char leak[512];

	if (!mkdtemp(base_path)) {
		perror("mkdtemp");
		return -1;
	}

	if (mount("tmpfs", base_path, "tmpfs", 0, NULL) < 0) {
		perror("mount tmpfs base");
		return -1;
	}

	snprintf(oldroot, sizeof(oldroot), "%s/oldroot", base_path);
	if (mkdir(oldroot, 0755) < 0 && errno != EEXIST) {
		perror("mkdir oldroot");
		return -1;
	}

	if (syscall(SYS_pivot_root, base_path, oldroot) < 0) {
		perror("pivot_root");
		return -1;
	}

	chdir("/");
	/* Remove the mkdtemp dir left on the host /tmp. After pivot_root it is
	 * a plain empty dir on the shared host filesystem — dead weight, safe to
	 * drop; ignoring any rmdir error keeps this best-effort. */
	snprintf(leak, sizeof(leak), "/oldroot%s", base_path);
	rmdir(leak);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  setup_default_mounts — 默认路径挂载 (/usr, /etc, /sys, symlinks)   */
/* ------------------------------------------------------------------ */
static int setup_default_mounts(void)
{
	/* 1. /usr — ro bind mount */
	{
		if (mkdir("/usr", 0755) < 0 && errno != EEXIST) {
			fprintf(stderr, "mkdir /usr: %s\n", strerror(errno));
			return -1;
		}
		/* 单次 MS_BIND|MS_RDONLY 会被内核忽略（bind 只克隆源挂载点 flags），
		 * 必须两步：先 bind，再 MS_REMOUNT 应用 ro/nosuid/nodev。
		 * 注意 /usr 不能 noexec —— bash/python/动态库都在 /usr 下，需可执行 */
		if (mount("/oldroot/usr", "/usr", NULL, MS_BIND | MS_REC, NULL) < 0) {
			fprintf(stderr, "mount /usr: %s\n", strerror(errno));
			return -1;
		}
		if (mount(NULL, "/usr", NULL,
			  MS_BIND | MS_REMOUNT | MS_RDONLY |
			  MS_NODEV | MS_NOSUID, NULL) < 0) {
			fprintf(stderr, "mount /usr ro: %s\n", strerror(errno));
			return -1;
		}
	}

	/* 2. merged-usr 符号链接 */
	symlink("usr/bin", "/bin");
	symlink("usr/sbin", "/sbin");
	symlink("usr/lib", "/lib");
	symlink("usr/lib64", "/lib64");

	/* 3. /etc — ro bind mount + 覆盖关键文件 */
	{
		if (mkdir("/etc", 0755) < 0 && errno != EEXIST) {
			fprintf(stderr, "mkdir /etc: %s\n", strerror(errno));
			return -1;
		}

		if (mount("/oldroot/etc", "/etc", NULL, MS_BIND, NULL) < 0) {
			fprintf(stderr, "mount /etc: %s\n", strerror(errno));
			return -1;
		}

		if (mount(NULL, "/etc", NULL,
			  MS_BIND | MS_REMOUNT | MS_RDONLY |
			  MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) < 0) {
			fprintf(stderr, "mount /etc ro: %s\n", strerror(errno));
			return -1;
		}
	}

	/* 4. /sys — ro bind mount (非 fatal) */
	{
		if (mkdir("/sys", 0555) < 0 && errno != EEXIST) {
			fprintf(stderr, "mkdir /sys: %s\n", strerror(errno));
			return -1;
		}
		if (mount("/oldroot/sys", "/sys", NULL, MS_BIND | MS_REC, NULL) < 0) {
			fprintf(stderr, "dyn-sandbox: warning: mount /sys failed: %s\n",
				strerror(errno));
		} else if (mount(NULL, "/sys", NULL,
			      MS_BIND | MS_REMOUNT | MS_RDONLY |
			      MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) < 0) {
			fprintf(stderr, "dyn-sandbox: warning: mount /sys ro failed: %s\n",
				strerror(errno));
		}
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  setup_user_mounts — 用户参数指定挂载                                */
/* ------------------------------------------------------------------ */
static int setup_user_mounts(struct sandbox_config *cfg)
{
	for (int i = 0; i < cfg->nmounts; i++) {
		struct mount_entry *e = &cfg->mounts[i];
		const char *dest = e->dest;

		if (e->is_tmpfs) {
                       if (mkdir_p(dest) < 0) {
                               fprintf(stderr, "mkdir -p %s: %s\n", dest, strerror(errno));
				return -1;
			}
			char opts[64] = "mode=0777";
			char size_opt[32];
			if (e->size > 0) {
				snprintf(size_opt, sizeof(size_opt),
					 "mode=0777,size=%luM", e->size);
				strcpy(opts, size_opt);
			}
			if (mount("tmpfs", dest, "tmpfs", 0, opts) < 0) {
				fprintf(stderr, "mount tmpfs %s: %s\n",
					dest, strerror(errno));
				return -1;
			}
		} else {
			char src[512];
			snprintf(src, sizeof(src), "/oldroot/%s", e->src);

                       if (mkdir_p(dest) < 0) {
                               fprintf(stderr, "mkdir -p %s: %s\n", dest, strerror(errno));
				return -1;
			}
			/* 单次 MS_BIND|MS_RDONLY 不生效，必须两步 */
			if (mount(src, dest, NULL, MS_BIND, NULL) < 0) {
				fprintf(stderr, "mount bind %s: %s\n",
					src, strerror(errno));
				return -1;
			}
			/* 不加 MS_NOEXEC：--mount /usr:ro 这类挂载需要可执行
			 * （bash/python/动态库在 /usr 下），与默认 /usr 挂载一致 */
			unsigned long remount_flags =
				MS_BIND | MS_REMOUNT | MS_NODEV |
				MS_NOSUID;
			if (!e->rw)
				remount_flags |= MS_RDONLY;
			if (mount(NULL, dest, NULL, remount_flags, NULL) < 0) {
				fprintf(stderr, "mount remount %s: %s\n",
					dest, strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  setup_virtual_fs — 虚拟文件系统 (/proc, /dev, /dev/shm, /tmp)      */
/* ------------------------------------------------------------------ */
static int setup_virtual_fs(struct sandbox_config *cfg)
{
	/* /proc */
	if (mkdir("/proc", 0555) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir /proc: %s\n", strerror(errno));
		return -1;
	}
	if (mount("proc", "/proc", "proc", MS_RDONLY, NULL) < 0) {
		perror("mount /proc");
		return -1;
	}

	/* /dev — mknod 设备节点 (根已是 tmpfs, /oldroot/dev 在 pivot_root 后不可用) */
	if (mkdir("/dev", 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir /dev: %s\n", strerror(errno));
		return -1;
	}

	/* /dev — bind-mount 宿主设备节点 (userns 内无法 mknod 设备) */
	{
		static const char *const dev_nodes[] = {
			"null", "zero", "full", "random", "urandom", "tty",
		};
		for (size_t i = 0; i < sizeof(dev_nodes) / sizeof(dev_nodes[0]); i++) {
			char src[64], dst[64];
			snprintf(dst, sizeof(dst), "/dev/%s", dev_nodes[i]);
			snprintf(src, sizeof(src), "/oldroot/dev/%s", dev_nodes[i]);
			/* 先建占位文件, bind 目标须存在 */
			int fd = open(dst, O_CREAT | O_WRONLY | O_CLOEXEC, 0666);
			if (fd < 0) {
				fprintf(stderr, "dyn-sandbox: create %s: %s\n",
					dst, strerror(errno));
				return -1;
			}
			close(fd);
			if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
				fprintf(stderr, "dyn-sandbox: bind %s: %s\n",
					src, strerror(errno));
				return -1;
			}
		}
	}

	if (mkdir("/dev/pts", 0755) < 0 && errno != EEXIST)
		fprintf(stderr, "dyn-sandbox: warning: mkdir /dev/pts: %s\n", strerror(errno));
	if (mkdir("/dev/shm", 0755) < 0 && errno != EEXIST)
		fprintf(stderr, "dyn-sandbox: warning: mkdir /dev/shm: %s\n", strerror(errno));
	if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0) {
		fprintf(stderr, "mount /dev/shm: %s\n", strerror(errno));
		return -1;
	}

	/* /tmp — 独立 tmpfs */
	if (mkdir("/tmp", 0777) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir /tmp: %s\n", strerror(errno));
		return -1;
	}
	unsigned long tmpfs_sz = cfg->tmpfs_size_mb > 0 ? cfg->tmpfs_size_mb : 256;
	char tmpfs_opt[64];
	snprintf(tmpfs_opt, sizeof(tmpfs_opt), "mode=0777,size=%luM", tmpfs_sz);
	if (mount("tmpfs", "/tmp", "tmpfs", 0, tmpfs_opt) < 0) {
		fprintf(stderr, "mount /tmp: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  bind_host_resolv_conf — 把宿主 resolv.conf 真实内容带进沙箱          */
/*  /etc 已 bind 宿主 /etc; 若 resolv.conf 是真文件, 内容天然在。
 *  若是软链 (一层), 把软链目标对应的宿主文件 bind 到"解析后的沙箱路径"。
 *  手动拼相对链接 (不依赖沙箱 /run 存在), 宿主源加 /oldroot 前缀。     */
/* ------------------------------------------------------------------ */
static void bind_host_resolv_conf(void)
{
	const char *target = "/etc/resolv.conf";
	struct stat st;

	if (lstat(target, &st) != 0 || !S_ISLNK(st.st_mode))
		return;

	char linkbuf[256];
	ssize_t llen = readlink(target, linkbuf, sizeof(linkbuf) - 1);
	if (llen <= 0)
		return;
	linkbuf[llen] = '\0';

	char resolved[512];
	if (linkbuf[0] == '/') {
		snprintf(resolved, sizeof(resolved), "%s", linkbuf);
	} else {
		/* 相对软链: 基于 target 所在目录 (/etc) 解析 */
		const char *slash = strrchr(target, '/');
		size_t dirlen = slash ? (size_t)(slash - target) : 0;
		snprintf(resolved, sizeof(resolved), "%.*s/%s",
			 (int)dirlen, target, linkbuf);
	}

	/* 创建挂载点: 递归建父目录 + 占位文件 (mount 目标必须存在) */
	/* mkdir_p 会把最后一级也建成目录, 所以只传父目录部分 */
	char parent[512];
	{
		const char *slash = strrchr(resolved, '/');
		if (slash && slash != resolved) {
			size_t plen = (size_t)(slash - resolved);
			snprintf(parent, sizeof(parent), "%.*s", (int)plen, resolved);
		} else {
			snprintf(parent, sizeof(parent), "/");
		}
	}
	if (mkdir_p(parent) < 0)
		fprintf(stderr, "dyn-sandbox: warning: mkdir_p %s: %s\n",
			parent, strerror(errno));
	int fd = open(resolved, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) close(fd);

	/* bind 宿主文件到解析路径 */
	char hostpath[512];
	snprintf(hostpath, sizeof(hostpath), "/oldroot%s", resolved);
	if (mount(hostpath, resolved, NULL, MS_BIND, NULL) < 0)
		fprintf(stderr, "dyn-sandbox: warning: bind host resolv.conf %s -> %s failed: %s\n",
			hostpath, resolved, strerror(errno));
}

/* ------------------------------------------------------------------ */
/*  setup_resolv_conf — 按网络模式配置沙箱 DNS                          */
/*  - isolate:     无网络, resolv.conf 悬空 = 无 DNS (不处理)          */
/*  - share-net:   共享宿主网络, 把宿主 resolv.conf 内容带进沙箱       */
/*  - whitelist:   同上, 再用沙箱自定义 nameserver 覆盖               */
/*  pivot_root + 虚拟文件系统后调用                                     */
/* ------------------------------------------------------------------ */
static void setup_resolv_conf(struct sandbox_config *cfg)
{
	if (cfg->network_mode == NET_MODE_ISOLATE)
		return;

	/* 1. 把宿主 resolv.conf 真实内容带进沙箱 (share 和 whitelist 都需要) */
	bind_host_resolv_conf();

	/* 2. 白名单模式: 用自定义内容覆盖 */
	if (cfg->network_mode == NET_MODE_WHITELIST) {
		FILE *rf = fopen("/tmp/sandbox-resolv.conf", "w");
		if (rf) {
			struct in_addr dns_s = { .s_addr = sandbox_dns };
			fprintf(rf, "nameserver %s\n", inet_ntoa(dns_s));
			fclose(rf);
		}
		bind_mount_override("/tmp/sandbox-resolv.conf", "/etc/resolv.conf");
	}
}

/* ------------------------------------------------------------------ */
/*  setup_filesystem — 协调各阶段构建沙箱文件系统                        */
/* ------------------------------------------------------------------ */
static int setup_filesystem(struct sandbox_config *cfg)
{
	if (pivot_root_into_tmpfs() < 0)
		return -1;
	if (setup_default_mounts() < 0)
		return -1;
	if (setup_virtual_fs(cfg) < 0)
		return -1;
	setup_resolv_conf(cfg);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  网络: 创建隔离环境                                                  */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  forward_fd — 从 src fd 读到 buf, 全部写入 dst fd                    */
/*  返回 1 = 继续转发; 0 = src 已 EOF/出错或写失败, 调用方收敛该 fd      */
/* ------------------------------------------------------------------ */
static int forward_fd(int src, int dst)
{
	char buf[4096];
	ssize_t n = read(src, buf, sizeof(buf));
	if (n > 0) {
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(dst, buf + off, n - off);
			if (w < 0) return 0;      /* 对端已关(EPIPE), 停止转发 */
			off += w;
		}
		return 1;
	}
	return n < 0 && errno == EINTR;   /* EINTR 重试; 其余(含 EOF)收敛该 fd */
}

/* ------------------------------------------------------------------ */
/* decide_file_action — 从 stdin 读授权回复并转换为 ALLOW/DENY 决策      */
/*  仅 ALLOW/allow（去首尾空白后完全匹配）放行，其余（含 EOF）一律 DENY  */
/* ------------------------------------------------------------------ */
static int decide_file_action(void)
{
	char resp[64] = {0};
	if (!fgets(resp, sizeof(resp), stdin))
		resp[0] = '\0';
	resp[strcspn(resp, "\n")] = '\0';

	char *start = resp;
	char *end = resp + strlen(resp);
	while (start < end &&
	       (*start == ' ' || *start == '\t' || *start == '\r'))
		start++;
	while (end > start &&
	       (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
		end--;

	if (end - start == 5 &&
	    (memcmp(start, "ALLOW", 5) == 0 ||
	     memcmp(start, "allow", 5) == 0))
		return DECISION_ALLOW;
	return DECISION_DENY;
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
static void run_parent(pid_t child_pid, struct sandbox_config *cfg)
{
	/* ========================================================= */
	/*  PARENT (原始命名空间中)                                    */
	/* ========================================================= */

	/* 关掉 child 端的 pipe 口 */
	close(child_stdin[0]);   child_stdin[0]  = -1;
	close(child_stdout[1]);  child_stdout[1] = -1;
	close(child_stderr[1]);  child_stderr[1] = -1;

	/* 父进程忽略 SIGPIPE: 向已死子进程写 stdin 不再自杀, 由 forward_fd
	 * 以 EPIPE 返回并收敛该 fd。须在 clone 之后设置, 避免传给 exec 的工具。 */
	signal(SIGPIPE, SIG_IGN);

	/* 先阻塞 SIGCHLD 再唤醒子进程: 若子进程在 signalfd 建好前退出,
	 * 未阻塞的 SIGCHLD 会被默认处置直接丢弃, 父进程将永远感知不到
	 * 子进程死亡。先阻塞, 死讯挂起在 pending, signalfd 建好即可读。 */
	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigmask, NULL);

	/* 非 root: parent 写 child 的 uid/gid map */
	if (getuid() != 0)
		write_uid_gid_map(child_pid);

	/* 唤醒子进程 (UID map 已就绪) */
	{
		eventfd_t val = 1;
		if (write(child_wait_fd, &val, sizeof(val)) < 0)
			perror("write child_wait_fd");
		close(child_wait_fd);
		child_wait_fd = -1;
	}

	/* 注册 child PID 到 kprobe (用于 Landlock 动态授权) */
	if (ioctl(sandbox_fd, SANDBOX_FILE_SET_PID, &child_pid) < 0) {
		/* 动态授权是监控模式的立足点: 失败则继续跑 = 静默降级成静态拒绝,
		 * child 的阻塞事件永远到不了 parent。异常退出, 且 SET_PID 失败时
		 * driver 的 registered_pid 未设置、sandbox_release 不会杀 child,
		 * 需在此显式 kill, 避免 child 作为新 pidns 的 PID 1 泄漏。 */
		fprintf(stderr,
			"dyn-sandbox: SET_PID %d failed (%s): dynamic file auth "
			"unavailable, aborting sandbox\n",
			child_pid, strerror(errno));
		kill(child_pid, SIGKILL);
		cleanup_exit(1);
	}
	printf("dyn-sandbox: monitor pid=%d, child pid=%d\n",
	       getpid(), child_pid);
	fflush(stdout);

	/* ── signalfd: 把 SIGCHLD 映射成 fd ── */
	int sfd = signalfd(-1, &sigmask, SFD_CLOEXEC);
	if (sfd < 0) {
		perror("signalfd");
		cleanup_exit(1);
	}

	/* stdin 转发状态: 初始为 fd0, EOF 后置 -1 摘出 poll 集合 (poll 忽略负 fd) */
	int stdin_fd = 0;

	/* ── poll 事件循环: I/O 转发 + 信号 ── */
	while (1) {
		struct pollfd fds[5];
		int nfds = 0;

		fds[nfds].fd = sfd;
		fds[nfds].events = POLLIN;
		nfds++;

		fds[nfds].fd = child_stdout[0];
		fds[nfds].events = POLLIN;
		nfds++;

		fds[nfds].fd = child_stderr[0];
		fds[nfds].events = POLLIN;
		nfds++;

		fds[nfds].fd = sandbox_fd;
		fds[nfds].events = POLLIN;
		nfds++;

		fds[nfds].fd = stdin_fd;
		fds[nfds].events = POLLIN;
		nfds++;

		int p_ret = poll(fds, nfds, -1);
		if (p_ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		/* ── 转发: child stdout → 父进程 stdout ── */
		if (fds[1].revents & (POLLIN | POLLHUP) && !forward_fd(child_stdout[0], 1))
			child_stdout[0] = -1;   /* EOF/写失败: 摘 fd, 停止转发 */

		/* ── 转发: child stderr → 父进程 stderr ── */
		if (fds[2].revents & (POLLIN | POLLHUP) && !forward_fd(child_stderr[0], 2))
			child_stderr[0] = -1;

		/* ── sandbox_fd: 内核 blocked 事件（任意子/孙进程） ── */
		if (fds[3].revents & POLLIN) {
			struct sandbox_file_blocked info;
			memset(&info, 0, sizeof(info));
			if (ioctl(sandbox_fd, SANDBOX_FILE_GET_BLOCKED, &info) == 0
			    && info.filename[0]) {
				dprintf(2, "AUTH_REQ:%s:%s\n",
					info.filename, info.resolved);
				fflush(stderr);

				int dec = decide_file_action();

				struct sandbox_file_decision d;
				memset(&d, 0, sizeof(d));
				strncpy(d.path, info.filename, sizeof(d.path) - 1);
				d.decision = dec;

				if (info.resolved[0] && strcmp(info.filename, info.resolved) != 0)
					printf("dyn-sandbox:   -> resolved: %s\n",
					       info.resolved);
				printf("dyn-sandbox: %s %s\n",
				       dec == DECISION_ALLOW ? "ALLOW" : "DENY",
				       info.filename);
				fflush(stdout);

				if (ioctl(sandbox_fd, SANDBOX_FILE_DECISION, &d) < 0)
					fprintf(stderr,
						"dyn-sandbox: DECISION %s failed (%s), child got DENY\n",
						dec == DECISION_ALLOW ? "ALLOW" : "DENY",
						strerror(errno));
			}
		}

		/* ── SIGCHLD: child 退出 / 信号终止 ── */
		if (fds[0].revents & POLLIN) {
			struct signalfd_siginfo si;
			read(sfd, &si, sizeof(si));

			int status;
			pid_t w = waitpid(child_pid, &status, WNOHANG);
			if (w <= 0)
				continue;

			if (WIFEXITED(status))
				cleanup_exit(WEXITSTATUS(status));
			else if (WIFSIGNALED(status))
				cleanup_exit(1);
		}
		/* ── 转发: 父进程 stdin → child stdin ── */
		if (stdin_fd >= 0 && (fds[4].revents & (POLLIN | POLLHUP))) {
			if (!forward_fd(stdin_fd, child_stdin[1])) {
				/* stdin EOF/出错: 摘 fd 停止转发; 关 child_stdin[1] 写端
				 * 传播 EOF 给子进程。fd0 自身保留, AUTH(decide_file_action)
				 * 仍读 stdin, EOF 后默认 DENY。 */
				stdin_fd = -1;
				if (child_stdin[1] >= 0) {
					close(child_stdin[1]);
					child_stdin[1] = -1;
				}
			}
		}
	}
	cleanup_exit(1);
}

/* ------------------------------------------------------------------ */
/*  setup_landlock_base — 创建规则集 + 添加基础规则，返回 ruleset_fd   */
/*  返回: ruleset_fd (>=0), -1 表示失败                                 */
/* ------------------------------------------------------------------ */
static int setup_landlock_base(struct sandbox_config *cfg)
{
	int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi <= 0) {
		fprintf(stderr, "dyn-sandbox: Landlock not available (ABI=%d)\n", abi);
		return -1;
	}

	struct landlock_ruleset_attr attr = {0};
	attr.handled_access_fs =
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_TRUNCATE;

	int ruleset_fd = ll_create_ruleset(&attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		fprintf(stderr, "dyn-sandbox: landlock_create_ruleset: %s\n",
			strerror(errno));
		return -1;
	}

	/* Default rules */
	static const char *default_rules[] = {
		"/usr/bin:read+execute",
		"/usr/lib:read+execute",
		"/usr/lib64:read+execute",
		"/usr/share:read",
		"/etc:read",
		"/proc/self:read",
		"/proc/filesystems:read",
		"/proc/1/mounts:read",
		"/proc/stat:read",
		"/proc/cpuinfo:read",
		"/proc/meminfo:read",
		"/proc/uptime:read",
		"/proc/version:read",
		"/proc/devices:read",
		"/proc/loadavg:read",
		"/sys:read",
		"/dev/null:read+write+truncate",
		"/dev/zero:read+write+truncate",
		"/dev/full:read+write+truncate",
		"/dev/random:read+write+truncate",
		"/dev/urandom:read+write+truncate",
		"/dev/tty:read+write+truncate",
		"/dev/shm:read+write+truncate",
		"/dev/pts:read+write+truncate",
		"/tmp:read+write+truncate",
		NULL,
	};

	for (const char **r = default_rules; *r; r++) {
		if (ll_add_rule_str(ruleset_fd, *r) < 0) {
			fprintf(stderr, "dyn-sandbox: warning: skipped landlock rule: %s (errno=%d)\n",
				*r, errno);
		}
	}

	/* 非 isolate 模式需要 DNS: /etc/resolv.conf 必须可读。
	 * Landlock 按解析后 dentry 判权, 对符号链接路径加 read 规则,
	 * open() 会跟随链接绑定到真实目标 inode, 覆盖 /run/... 目标。
	 * (若宿主机 resolv.conf 是普通文件, 规则同样命中其自身) */
	if (cfg->network_mode != NET_MODE_ISOLATE) {
		if (ll_add_rule_str(ruleset_fd, "/etc/resolv.conf:read") < 0) {
			fprintf(stderr, "dyn-sandbox: warning: skipped landlock rule: /etc/resolv.conf:read (errno=%d)\n",
				errno);
		}
	}

	return ruleset_fd;
}

/* ------------------------------------------------------------------ */
/*  setup_landlock_user — 向已有 ruleset 添加用户规则                    */
/*  返回: 0 成功, -1 失败                                              */
/* ------------------------------------------------------------------ */
static int setup_landlock_user(struct sandbox_config *cfg, int ruleset_fd)
{
	for (int i = 0; i < cfg->nlandlock; i++) {
		char rule_str[1088];

		snprintf(rule_str, sizeof(rule_str), "%s:%s",
			 cfg->landlock_rules[i].path,
			 cfg->landlock_rules[i].perms);
		if (ll_add_rule_str(ruleset_fd, rule_str) < 0) {
			fprintf(stderr, "dyn-sandbox: Landlock rule %d failed\n", i);
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  enable_sandbox — 统一应用安全策略（execvp 前最后调用）                */
/*  1. NO_NEW_PRIVS                                                     */
/*  2. landlock_restrict_self                                           */
/*  3. SECCOMP_SET_MODE_FILTER                                          */
/*  调用后 landlock_fd 被关闭                                             */
/* ------------------------------------------------------------------ */
static int enable_sandbox(int landlock_fd, const struct sock_fprog *seccomp_prog)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		fprintf(stderr, "dyn-sandbox: prctl NO_NEW_PRIVS: %s\n",
			strerror(errno));
		return -1;
	}

	if (landlock_fd >= 0) {
		if (ll_restrict_self(landlock_fd, 0) < 0) {
			fprintf(stderr, "dyn-sandbox: landlock_restrict_self: %s\n",
				strerror(errno));
			close(landlock_fd);
			return -1;
		}
		close(landlock_fd);
	}

	if (seccomp_prog && seccomp_prog->len > 0 && seccomp_prog->filter) {
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_TSYNC, seccomp_prog) < 0) {
			fprintf(stderr, "dyn-sandbox: seccomp: %s\n",
				strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  build_seccomp_prog — 构建 seccomp BPF 程序（不生效，不 NO_NEW_PRIVS） */
/*  返回: sock_fprog（调用者负责 free(.filter)）。无 seccomp 时返回空    */
/* ------------------------------------------------------------------ */
static struct sock_fprog build_seccomp_prog(struct sandbox_config *cfg)
{
	if (!cfg->seccomp_profile[0] && !cfg->seccomp_syscalls[0])
		return (struct sock_fprog){0, NULL};

	struct sock_fprog prog;

	if (cfg->seccomp_syscalls[0])
		prog = seccomp_build_from_names(cfg->seccomp_syscalls);
	else
		prog = seccomp_lookup(cfg->seccomp_profile);

	if (prog.len == 0 || !prog.filter) {
		fprintf(stderr, "dyn-sandbox: seccomp setup failed\n");
		return (struct sock_fprog){0, NULL};
	}

	return prog;
}

/* ------------------------------------------------------------------ */
/*  CHILD: 在全新命名空间中设置沙箱隔离环境                              */
/*  所有错误路径直接 _exit (parent 统一 cleanup)                        */
/* ------------------------------------------------------------------ */
/*  run_child 阶段函数                                               */
/* ------------------------------------------------------------------ */

/* 阶段 1: stdio 重定向 + 等待父进程 UID map */
static void child_setup_stdio(void)
{
	dup2(child_stdin[0], 0);
	dup2(child_stdout[1], 1);
	dup2(child_stderr[1], 2);
	close(child_stdin[0]);  close(child_stdin[1]);
	close(child_stdout[0]); close(child_stdout[1]);
	close(child_stderr[0]); close(child_stderr[1]);

	eventfd_t val;
	if (read(child_wait_fd, &val, sizeof(val)) < 0)
		perror("read child_wait_fd");
	close(child_wait_fd);
	child_wait_fd = -1;
}

/* 阶段 2: 网络隔离 — veth pair + nftables
 * 仅白名单模式进入; isolate 无网络, --share-net 共享宿主网络 */
static void child_setup_network(struct sandbox_config *cfg)
{
	if (cfg->network_mode != NET_MODE_WHITELIST)
		return;

	struct sandbox_net_create req;
	memset(&req, 0, sizeof(req));
	req.flags = 0;
	req.ndomains = cfg->ndomains;
	for (int di = 0; di < cfg->ndomains; di++)
		strncpy(req.domains[di], cfg->domains[di],
			SANDBOX_DOMAIN_MAX_LEN - 1);
	req.ncidrs = cfg->ncidrs;
	for (int ci = 0; ci < cfg->ncidrs; ci++)
		req.cidrs[ci] = cfg->cidrs[ci];

	if (ioctl(sandbox_fd, SANDBOX_NET_CREATE, &req) < 0)
		CHILD_FAIL_EXIT(EXIT_NET_ERR, "SANDBOX_NET_CREATE: %s",
				strerror(errno));

	struct in_addr child_ip = { .s_addr = req.child_ip };
	struct in_addr gateway  = { .s_addr = req.gateway };
	sandbox_dns = req.gateway;

	char cmd[256];
	snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s",
		 inet_ntoa(child_ip), req.prefix, req.veth_child);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "ip link set %s up", req.veth_child);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "ip route add default via %s",
		 inet_ntoa(gateway));
	system(cmd);
	system("ip link set lo up");
}

/* 阶段 3: mount namespace + pivot_root + Landlock + seccomp */
/* 失败时内部调用 _exit，不会正常返回 */
static void child_setup_security(struct sandbox_config *cfg,
				 int *landlock_fd,
				 struct sock_fprog *seccomp_prog)
{
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) < 0)
		CHILD_FAIL_EXIT(EXIT_MOUNT_ERR, "mount MS_PRIVATE: %s",
				strerror(errno));

	if (setup_filesystem(cfg) < 0)
		CHILD_FAIL_EXIT(EXIT_MOUNT_ERR, "filesystem setup failed");

	if (cfg->no_landlock) {
		*landlock_fd = -1;
	} else {
		*landlock_fd = setup_landlock_base(cfg);
		if (*landlock_fd < 0)
			CHILD_FAIL_EXIT(EXIT_LANDLOCK_ERR, "Landlock base rules failed");
	}

	if (setup_user_mounts(cfg) < 0)
		CHILD_FAIL_EXIT(EXIT_MOUNT_ERR, "user mount failed");
	if (!cfg->no_landlock) {
		if (setup_landlock_user(cfg, *landlock_fd) < 0)
			CHILD_FAIL_EXIT(EXIT_LANDLOCK_ERR, "Landlock user rules failed");
	}

	/* 提前构建 seccomp BPF（当前不生效，仅构建程序） */
	*seccomp_prog = build_seccomp_prog(cfg);
	if (seccomp_prog->len == 0 &&
	    (cfg->seccomp_profile[0] || cfg->seccomp_syscalls[0]))
		CHILD_FAIL_EXIT(EXIT_SECCOMP_ERR, "seccomp setup failed");
}

/* ------------------------------------------------------------------ */
/*  child_close_fds — 关闭子进程所有 fd >=3，只保留 landlock_fd       */
/* ------------------------------------------------------------------ */
static void child_close_fds(int landlock_fd)
{
	if (landlock_fd > 3) {
		syscall(SYS_close_range, 3, landlock_fd - 1, 0);
		syscall(SYS_close_range, landlock_fd + 1, UINT_MAX, 0);
	} else {
		syscall(SYS_close_range, 3, UINT_MAX, 0);
	}
}

/* 阶段 4: /oldroot 清理 + 信号恢复 + fd 清理 + 降权 + exec */
static void child_finalize(struct sandbox_config *cfg,
			   int landlock_fd,
			   struct sock_fprog *seccomp_prog)
{
	if (umount2("/oldroot", MNT_DETACH) < 0)
		fprintf(stderr, "dyn-sandbox: warning: umount /oldroot: %s\n",
			strerror(errno));
	rmdir("/oldroot");

	child_close_fds(landlock_fd);

	if (cfg->workdir[0] && chdir(cfg->workdir) < 0)
		CHILD_FAIL_EXIT(EXIT_TOOL_FAIL, "invalid workdir %s: %s",
				cfg->workdir, strerror(errno));

	if (enable_sandbox(landlock_fd, seccomp_prog) < 0)
		CHILD_FAIL_EXIT(EXIT_LANDLOCK_ERR, "sandbox enable failed");
	free(seccomp_prog->filter);

	fflush(stdout);
	execvp(cfg->cmd_argv[0], cfg->cmd_argv);
	CHILD_FAIL_EXIT(EXIT_TOOL_FAIL, "execve %s: %s",
			cfg->cmd_argv[0], strerror(errno));
}

/* ------------------------------------------------------------------ */
static void run_child(struct sandbox_config *cfg)
{
	child_setup_stdio();
	child_setup_network(cfg);

	int landlock_fd;
	struct sock_fprog seccomp_prog;
	child_setup_security(cfg, &landlock_fd, &seccomp_prog);

	child_finalize(cfg, landlock_fd, &seccomp_prog);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
	struct sandbox_config cfg;

	/* Phase 0: 解析 CLI 参数 */
	if (parse_args(&cfg, argc, argv) < 0) {
		print_usage(argv[0]);
		return 1;
	}

	/* Phase 0.5: --dump-config 模式, 打印后退出 */
	if (cfg.dump_config) {
		dump_config(&cfg);
		return 0;
	}

	/* 打开 /dev/dyn-sandbox (检查模块是否加载) */
	sandbox_fd = open(SANDBOX_DEVICE, O_RDWR);
	if (sandbox_fd < 0) {
		fprintf(stderr, "dyn-sandbox: cannot open %s\n", SANDBOX_DEVICE);
		return EXIT_KPROBE_ERR;
	}

	/* 创建 eventfd: 子进程等父进程写完 UID map 后再初始化文件系统 */
	child_wait_fd = eventfd(0, EFD_CLOEXEC);
	if (child_wait_fd < 0) {
		perror("eventfd");
		return EXIT_NS_ERR;
	}

	/* raw_clone 一次性创建命名空间:
	 *   mount — 文件系统隔离 (始终需要)
	 *   pid   — 进程树隔离 (防止看到 host 进程)
	 *   ipc   — IPC 资源隔离
	 *   uts   — hostname 隔离
	 *   net   — 网络隔离 (默认完全空 netns, 有 --domain/--cidr 时才配置 veth)
	 *   user  — 非 root 时自动创建 (parent 写 uid_map) */
	/* 创建三路 pipe: parent 控制 child 的 stdio */
	(void)pipe2(child_stdin,  O_CLOEXEC);
	(void)pipe2(child_stdout, O_CLOEXEC);
	(void)pipe2(child_stderr, O_CLOEXEC);
	int clone_flags = SIGCHLD | CLONE_NEWNS | CLONE_NEWPID |
			  CLONE_NEWIPC | CLONE_NEWUTS;
	/* isolate / whitelist 隔离网络; --share-net 复用宿主网络 */
	if (cfg.network_mode != NET_MODE_SHARE)
		clone_flags |= CLONE_NEWNET;
	if (getuid() != 0)
		clone_flags |= CLONE_NEWUSER;

	pid_t child_pid = raw_clone_wrapper(clone_flags);
	if (child_pid < 0) {
		perror("raw_clone");
		return EXIT_NS_ERR;
	}

	if (child_pid > 0)
		run_parent(child_pid, &cfg);
	else
		run_child(&cfg);

	return EXIT_TOOL_FAIL; /* unreached */
}
