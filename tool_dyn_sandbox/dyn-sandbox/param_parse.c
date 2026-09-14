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
 * param_parse.c — 参数解析（CLI + YAML policy）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "param_parse.h"
#include "seccomp_profiles.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * sandbox_validate_mount_path — 挂载路径校验 (CLI --mount/--mount-tmpfs, YAML bind/tmpfs
 * 共用). bind 路径是宿主路径 (setup_user_mounts 拼 "/oldroot/" 前缀), tmpfs 路径是沙箱内
 * 目标; 两者都必须是以 '/' 开头的干净绝对路径: 组件不得为空 ('//'/尾部'/')、'.' 或 '..',
 * 且不得命中内部停泊根挂载点 /oldroot.
 *
 * 理由 (见 reports/closed/mitigated/②): 含 '..' 的路径在 bind 前缀后成 "/oldroot//../oldroot",
 * 可自停泊根弹回沙箱根再叠回该挂载点; 而 bind 字面 /oldroot、tmpfs 的 /oldroot 目标会把新
 * 挂载直接叠在停泊根上 — 两者都使 child_finalize 的单层 umount2 剥不掉宿主根. 形状校验保证
 * 无 '..'/'//'/'.'/尾部 '/', 故对 /oldroot 做字面比较对静态拼写即完备 (其它拼写皆被形状规则
 * 排除). 已知残留 (按 2026-09-03 决策接受, 不在此拦): mount 时才经 magic-link 重解析的路径,
 * 如 dest=/proc/self/root/oldroot (/proc 先于 user mounts 挂载, /proc/self/root 解析到沙箱
 * tmpfs 根, 其下 /oldroot 即停泊挂载点) — 需运行时 realpath 锚定才拦得住, 见该报告处置.
 */
int sandbox_validate_mount_path(const char *path)
{
	const char *s;
	size_t n;

	if (!path || path[0] != '/')
		return -1;

	for (const char *p = path + 1; *p; ) {
		s = p;
		while (*p && *p != '/')
			p++;
		n = (size_t)(p - s);
		if (n == 0 ||				 /* '//' 或尾部 '/' */
		    (n == 1 && s[0] == '.') ||
		    (n == 2 && s[0] == '.' && s[1] == '.'))
			return -1;
		if (*p)
			p++;
	}
	if (strcmp(path, "/oldroot") == 0)	 /* 内部停泊根挂载点 */
		return -1;
	return 0;
}

/*
 * 单参数逗号分隔多值 — --mount/--mount-tmpfs/--domain/--cidr 同族 (usage-guide)。
 * 参数解析规则逐条:
 *
 *  1. 逗号是保留分隔符: 值内不得含 ','; 一个参数即一条多值列表。
 *  2. 空段一律拒绝, 不静默跳过: 串首 ','、连续 ','、尾 ','、整参空串都报错。
 *     收严来历: 与 S2"静默丢第二个挂载"同源 — domain/cidr 早先用 strtok
 *     跳过空段, 行为与 mount 家族不一致, 已收严对齐。
 *  3. 每个逗号段是一次独立解析, 交给选项各自的 one() (签名见下); 段内才找
 *     ':' / '/', 段界限定在段内, 不会把下一段读进来 (段本身不保证 NUL 结尾)。
 *  4. 条数上限在 one() 内检查, 本层不重复计数: MAX_MOUNTS=32 (bind+tmpfs
 *     合计) / SANDBOX_MAX_DOMAINS / SANDBOX_MAX_CIDRS。
 *  5. mount 同 dest 去重 (重复选项/逗号撞车/YAML mount 列表) 由 parse_args
 *     收尾统一拒绝 — 完整说明见 parse_args 末尾。
 */
typedef int (*comma_seg_fn)(struct sandbox_config *cfg, const char *seg,
                            size_t seglen);

/* 逗号区分多值 */
static int for_each_comma_seg(struct sandbox_config *cfg, const char *arg,
                              const char *optname, size_t scan,
                              comma_seg_fn one)
{
	if (arg[0] == '\0') {
		fprintf(stderr, "empty --%s argument\n", optname);
		return -1;
	}
	const char *p = arg;
	for (;;) {
		if (*p == '\0')
			break;			/* 正常串尾 */
		size_t seg_len = strnlen(p, scan);
		const char *comma = memchr(p, ',', seg_len);
		size_t seglen = comma ? (size_t)(comma - p) : seg_len;
		if (seglen == 0) {		/* p 在逗号上: 串首或连续逗号 → 空段 */
			fprintf(stderr,
				"empty --%s entry (commas must separate non-empty entries)\n",
				optname);
			return -1;
		}
		if (one(cfg, p, seglen) < 0)
			return -1;
		if (!comma)
			break;			/* 最后一段后无逗号 */
		p = comma + 1;
		if (*p == '\0') {		/* 尾逗号 → 空段 */
			fprintf(stderr,
				"empty --%s entry (commas must separate non-empty entries)\n",
				optname);
			return -1;
		}
	}
	return 0;
}

static int parse_mount_one(struct sandbox_config *cfg, const char *seg, size_t seglen)
{
	/* 段内找冒号: plen = 路径段长; ':' 后即 rw/ro */
	const char *colon = memchr(seg, ':', seglen);
	size_t plen = colon ? (size_t)(colon - seg) : seglen;
	if (plen >= sizeof(cfg->mounts[0].src)) {
		fprintf(stderr, "mount path too long: %zu chars (max %zu)\n",
			plen, sizeof(cfg->mounts[0].src) - 1);
		return -1;
	}
	int rw = 0;
	if (colon) {
		/* rw/ro 精确匹配: optlen 限段内剩余字节 (段界已保证不越界读) */
		size_t optlen = seglen - plen - 1;
		if (optlen > 3)
			optlen = 3;
		if (optlen == 2 && memcmp(colon + 1, "rw", 2) == 0)
			rw = 1;
		else if (!(optlen == 2 && memcmp(colon + 1, "ro", 2) == 0)) {
			fprintf(stderr, "invalid mount option: %.*s (use ro or rw)\n",
				(int)optlen, colon + 1);
			return -1;
		}
	}

	if (cfg->nmounts >= MAX_MOUNTS) {
		fprintf(stderr, "too many --mount entries\n");
		return -1;
	}
	/* 先写目标槽位再校验 (CLI 段不保证 NUL 结尾, memcpy+补 NUL 后按 entry
	 * 字段校验, 与 policy_parser finalize 对 YAML 路径的验法一致):
	 * nmounts 最后才 ++, 失败即整体 return 丢弃 cfg, 无半写残留 */
	struct mount_entry *e = &cfg->mounts[cfg->nmounts];
	memcpy(e->src, seg, plen);
	e->src[plen] = '\0';
	if (sandbox_validate_mount_path(e->src) < 0) {
		fprintf(stderr,
			"invalid --mount path '%s' (absolute, not /oldroot, no '..'/'.'/'//')\n",
			e->src);
		return -1;
	}
	memcpy(e->dest, seg, plen);
	e->dest[plen] = '\0';
	e->rw = rw;
	e->is_tmpfs = 0;
	e->size = 0;
	cfg->nmounts++;
	return 0;
}

static int parse_mount(struct sandbox_config *cfg, const char *arg)
{
	return for_each_comma_seg(cfg, arg, "mount",
				  sizeof(cfg->mounts[0].src) + 8,
				  parse_mount_one);
}

static int parse_mount_tmpfs_one(struct sandbox_config *cfg, const char *seg, size_t seglen)
{
	/* 段内找冒号: plen = 目标路径长; ':' 后为 size */
	const size_t path_max = sizeof(cfg->mounts[0].dest);
	const char *colon = memchr(seg, ':', seglen);
	size_t plen = colon ? (size_t)(colon - seg) : seglen;
	if (plen >= path_max) {
		fprintf(stderr, "mount path too long: %zu chars (max %zu)\n",
			plen, path_max - 1);
		return -1;
	}
	unsigned long size = 0;
	if (colon) {
		/* size 必须是段内纯数字: 拷进限幅缓冲再 strtol (逗号后的段不会被吞进数字) */
		char numbuf[24];
		size_t numlen = seglen - plen - 1;
		if (numlen >= sizeof(numbuf)) {
			fprintf(stderr, "invalid tmpfs size\n");
			return -1;
		}
		memcpy(numbuf, colon + 1, numlen);
		numbuf[numlen] = '\0';
		char *end;
		errno = 0;
		long s = strtol(numbuf, &end, 10);
		/* size=0 合法 = 默认 256M (与 --tmpfs-size 0、/tmp 分支、usage-guide 一致);
		 * 负值/非数字/越界仍拒绝. */
		if (errno == ERANGE || end == numbuf || *end != '\0' || s < 0) {
			fprintf(stderr, "invalid tmpfs size: %ld\n", s);
			return -1;
		}
		size = s;
	}

	/* /tmp 已由系统挂载, 只修改大小即可; 不新增条目, 故不占 MAX_MOUNTS、不参与去重.
	 * S4: /tmp 大小旋钮只能设置一次 — 本拼写重复或与 --tmpfs-size 混用都报错. */
	if (plen == 4 && memcmp(seg, "/tmp", 4) == 0) {
		if (cfg->tmpfs_size_src != 0) {
			fprintf(stderr,
				"conflicting /tmp size (--tmpfs-size / --mount-tmpfs /tmp): /tmp size may be set only once\n");
			return -1;
		}
		cfg->tmpfs_size_src = 2;
		cfg->tmpfs_size_mb = size > 0 ? size : 256;
		return 0;
	}

	if (cfg->nmounts >= MAX_MOUNTS) {
		fprintf(stderr, "too many --mount entries\n");
		return -1;
	}
	/* 同上: 先写 dest 槽位补 NUL 再校验, nmounts 最后才 ++ */
	struct mount_entry *e = &cfg->mounts[cfg->nmounts];
	memcpy(e->dest, seg, plen);
	e->dest[plen] = '\0';
	if (sandbox_validate_mount_path(e->dest) < 0) {
		fprintf(stderr,
			"invalid --mount-tmpfs path '%s' (absolute, not /oldroot, no '..'/'.'/'//')\n",
			e->dest);
		return -1;
	}
	e->is_tmpfs = 1;
	e->size = size;
	cfg->nmounts++;
	return 0;
}

static int parse_mount_tmpfs(struct sandbox_config *cfg, const char *arg)
{
	return for_each_comma_seg(cfg, arg, "mount-tmpfs",
				  sizeof(cfg->mounts[0].dest) + 8,
				  parse_mount_tmpfs_one);
}

#ifdef CONFIG_LANDLOCK_ENABLE
static int parse_landlock(struct sandbox_config *cfg, const char *arg)
{
	if (cfg->nlandlock >= MAX_LANDLOCK) {
		fprintf(stderr, "too many --landlock entries\n");
		return -1;
	}
	struct landlock_entry *e = &cfg->landlock_rules[cfg->nlandlock++]; /* 先占位, 错误分支不回滚 */

	/* 限范围扫描, 同 parse_mount: 先 strnlen 限幅取串长, 再 memchr 只在串内找冒号 */
	size_t alen = strnlen(arg, sizeof(e->path));
	const char *colon = memchr(arg, ':', alen);
	size_t plen = colon ? (size_t)(colon - arg) : alen;
	if (plen >= sizeof(e->path)) {
		fprintf(stderr, "landlock path too long: %zu chars (max %zu)\n",
			plen, sizeof(e->path) - 1);
		return -1;
	}
	memcpy(e->path, arg, plen);
	e->path[plen] = '\0';

	/* 权限串: 限 sizeof(e->perms) 内校验长度, 超长显式拒绝 */
	if (colon) {
		size_t permlen = strnlen(colon + 1, sizeof(e->perms));
		if (permlen >= sizeof(e->perms)) {
			fprintf(stderr, "landlock perms too long: max %zu\n",
				sizeof(e->perms) - 1);
			return -1;
		}
		memcpy(e->perms, colon + 1, permlen);
		e->perms[permlen] = '\0';
	}
	return 0;
}
#endif

static int parse_domain_one(struct sandbox_config *cfg, const char *seg, size_t len)
{
	if (len >= SANDBOX_DOMAIN_MAX_LEN) {
		fprintf(stderr, "domain too long: %zu chars (max %d)\n",
			len, SANDBOX_DOMAIN_MAX_LEN - 1);
		return -1;
	}
	if (cfg->ndomains >= SANDBOX_MAX_DOMAINS) {
		fprintf(stderr, "too many --domain entries (max %d)\n",
			SANDBOX_MAX_DOMAINS);
		return -1;
	}
	memcpy(cfg->domains[cfg->ndomains], seg, len);
	cfg->domains[cfg->ndomains][len] = '\0';
	cfg->ndomains++;
	return 0;
}

static int parse_domains(struct sandbox_config *cfg, const char *arg)
{
	return for_each_comma_seg(cfg, arg, "domain",
				  SANDBOX_DOMAIN_MAX_LEN, parse_domain_one);
}

static int parse_cidr_one(struct sandbox_config *cfg, const char *seg, size_t seglen)
{
	/* 合法 CIDR 段 ≤16 字符, 64 封顶, 超长拒绝 */
	if (seglen >= 64) {
		fprintf(stderr, "invalid CIDR segment too long (max 63)\n");
		return -1;
	}
	if (cfg->ncidrs >= SANDBOX_MAX_CIDRS) {
		fprintf(stderr, "too many --cidr entries (max %d)\n",
			SANDBOX_MAX_CIDRS);
		return -1;
	}
	/* 段内找 '/' : 只在 seglen 内 */
	const char *slash = memchr(seg, '/', seglen);
	if (!slash) {
		fprintf(stderr, "invalid CIDR: %.*s (need /prefix)\n",
			(int)seglen, seg);
		return -1;
	}
	size_t iplen = (size_t)(slash - seg);
	if (iplen == 0 || iplen >= INET_ADDRSTRLEN) {
		fprintf(stderr, "invalid CIDR: %.*s\n", (int)seglen, seg);
		return -1;
	}
	char ip[INET_ADDRSTRLEN];
	memcpy(ip, seg, iplen);
	ip[iplen] = '\0';

	/* 前缀段: 限斜杠后的段内字节(合法 1..32, ≤3 字符), 不越过逗号/串尾 */
	size_t pfx_region = seglen - iplen - 1;
	size_t pfxlen = strnlen(slash + 1, pfx_region);
	if (pfxlen == 0 || pfxlen > 3) {
		fprintf(stderr, "invalid prefix: %.*s\n",
			(int)pfxlen, slash + 1);
		return -1;
	}
	char pfxbuf[4];
	memcpy(pfxbuf, slash + 1, pfxlen);
	pfxbuf[pfxlen] = '\0';
	char *end;
	long pfx;
	errno = 0;
	pfx = strtol(pfxbuf, &end, 10);
	if (errno == ERANGE || end == pfxbuf || *end != '\0' ||
	    pfx < 1 || pfx > 32) {
		/* 拒绝非数字(/abc 曾静默成 /0)和 /0: 白名单加 0.0.0.0/0 会放行全部流量 */
		fprintf(stderr, "invalid prefix: %s\n", pfxbuf);
		return -1;
	}

	struct in_addr ia;
	if (inet_pton(AF_INET, ip, &ia) != 1) {
		fprintf(stderr, "invalid CIDR address: %s\n", ip);
		return -1;
	}
	struct sandbox_cidr *c = &cfg->cidrs[cfg->ncidrs++];
	c->addr = ia.s_addr;
	c->mask = htonl(~0U << (32 - pfx)); /* pfx 已保证 1..32 */
	return 0;
}

static int parse_cidrs(struct sandbox_config *cfg, const char *arg)
{
	return for_each_comma_seg(cfg, arg, "cidr", 64, parse_cidr_one);
}

/* ------------------------------------------------------------------ */
/*  S7: --seccomp-syscalls 追加 (union)                                 */
/* ------------------------------------------------------------------ */

/* 重复 --seccomp-syscalls = 追加合并, 逗号连接 — 与 YAML syscalls 的
 * append_joined 语义对齐 (重复 = 累加白名单, 不是 last-wins 覆盖).
 * 累计超 511 拒绝, 不静默截断; 顺带消除旧 strncpy 在源 >= 512 时不补
 * NUL 的潜伏未终止 bug (现改为显式报错). 0 成功, -1 失败已打错 */
static int append_seccomp_syscalls(struct sandbox_config *cfg, const char *arg)
{
	size_t cur = strlen(cfg->seccomp_syscalls);
	size_t add = strlen(arg);
	size_t sep = cur ? 1 : 0;   /* 已有列表时补一个分隔逗号 */
	if (cur + sep + add + 1 > sizeof(cfg->seccomp_syscalls)) {
		fprintf(stderr, "--seccomp-syscalls too long (max %d)\n",
			(int)sizeof(cfg->seccomp_syscalls) - 1);
		return -1;
	}
	if (sep)
		cfg->seccomp_syscalls[cur++] = ',';
	memcpy(cfg->seccomp_syscalls + cur, arg, add);
	cfg->seccomp_syscalls[cur + add] = '\0';
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Main entry                                                         */
/* ------------------------------------------------------------------ */

int parse_args(struct sandbox_config *cfg, int argc, char **argv)
{
	memset(cfg, 0, sizeof(*cfg));
	strcpy(cfg->workdir, "/");

#ifndef CONFIG_LANDLOCK_ENABLE
	/* 无 Landlock 构建: 默认处于 no-landlock 状态 */
	cfg->no_landlock = 1;
#endif

	static struct option long_opts[] = {
		{"mount",        required_argument, NULL, 'm'},
		{"mount-tmpfs",  required_argument, NULL, 't'},
#ifdef CONFIG_LANDLOCK_ENABLE
		{"landlock",     required_argument, NULL, 'l'},
		{"no-landlock",  no_argument,       NULL, 256},
#endif
		{"seccomp",      required_argument, NULL, 's'},
		{"seccomp-syscalls", required_argument, NULL, 'k'},
		{"domain",       required_argument, NULL, 'g'},
		{"cidr",          required_argument, NULL, 'i'},
		{"share-net",    no_argument,       NULL, 257},
		{"tmpfs-size",   required_argument, NULL, 'z'},
		{"policy",       required_argument, NULL, 'p'},
		{"dump-config",  no_argument,       NULL, 'D'},
		{0, 0, 0, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "c:D", long_opts, NULL)) != -1) {
		/* 前向：--policy 后不允许其他选项 */
		if (opt != 'p' && opt != 'D' && cfg->policy_loaded) {
			fprintf(stderr, "--policy is mutually exclusive with other options\n");
			return -1;
		}
		/* 反向：其他选项后不允许 --policy */
		if (opt == 'p' && cfg->cli_used) {
			fprintf(stderr, "--policy is mutually exclusive with other options\n");
			return -1;
		}

		if (opt == 'p') {
			cfg->policy_loaded = 1;
		} else if (opt != 'D') {
			cfg->cli_used = 1;
		}

		switch (opt) {
		case 'c':
			/* S5: 重复 -c = 冲突 (不 last-wins). workdir 是单值标量旋钮,
			 * 重复写即静默丢前值 → 歧义配置, 让用户写清楚 (与 S4/S6 一致) */
			if (cfg->workdir_set) {
				fprintf(stderr,
					"conflicting -c workdir (%s): -c may be set only once\n",
					cfg->workdir);
				return -1;
			}
			cfg->workdir_set = 1;
			strncpy(cfg->workdir, optarg, sizeof(cfg->workdir) - 1);
			break;

		case 'm':
			if (parse_mount(cfg, optarg) < 0) return -1;
			break;

		case 't':
			if (parse_mount_tmpfs(cfg, optarg) < 0)
				return -1;
			break;

#ifdef CONFIG_LANDLOCK_ENABLE
		case 'l':
			if (cfg->no_landlock) {
				fprintf(stderr, "--landlock and --no-landlock are mutually exclusive\n");
				return -1;
			}
			if (parse_landlock(cfg, optarg) < 0)
				return -1;
			break;

		case 256: /* --no-landlock */
			if (cfg->nlandlock > 0) {
				fprintf(stderr, "--landlock and --no-landlock are mutually exclusive\n");
				return -1;
			}
			cfg->no_landlock = 1;
			break;
#endif

		case 's':
			if (cfg->seccomp_syscalls[0]) {
				fprintf(stderr, "--seccomp and --seccomp-syscalls are mutually exclusive\n");
				return -1;
			}
			/* S6: 重复 --seccomp = 冲突 (不 last-wins). parse_args 开头的
			 * 前向/反向互斥检查已保证 --policy 不与 CLI 选项同现, 故这里
			 * profile 非空必是前一个 CLI --seccomp 所写.
			 * 与 --seccomp-syscalls 的互斥同构: 单值旋钮只设一次 */
			if (cfg->seccomp_profile[0]) {
				fprintf(stderr,
					"conflicting --seccomp profile (%s): --seccomp may be set only once\n",
					cfg->seccomp_profile);
				return -1;
			}
			if (!seccomp_valid_profile(optarg)) {
				fprintf(stderr, "unknown seccomp profile: %s\n", optarg);
				return -1;
			}
			strncpy(cfg->seccomp_profile, optarg,
				sizeof(cfg->seccomp_profile) - 1);
			break;

		case 'k':
			if (cfg->seccomp_profile[0]) {
				fprintf(stderr, "--seccomp and --seccomp-syscalls are mutually exclusive\n");
				return -1;
			}
			if (optarg[0] == '\0') {
				fprintf(stderr, "--seccomp-syscalls cannot be empty\n");
				return -1;
			}
			/* S7: 重复 = 追加 union (对齐 YAML append_joined), 非 last-wins */
			if (append_seccomp_syscalls(cfg, optarg) < 0)
				return -1;
			break;

		case 'g':
			if (parse_domains(cfg, optarg) < 0)
				return -1;
			break;

		case 'i':
			if (parse_cidrs(cfg, optarg) < 0)
				return -1;
			break;

		case 257: /* --share-net */
			cfg->network_mode = NET_MODE_SHARE;
			break;

		case 'z': {
			/* 严格校验: strtol 拒绝非数字/尾随垃圾 (atol 会把 abc 静默当 0) */
			char *end;
			long s;
			errno = 0;
			s = strtol(optarg, &end, 10);
			if (errno == ERANGE || end == optarg || *end != '\0' ||
			    s < 0) {
				fprintf(stderr, "invalid --tmpfs-size: %s (must be a non-negative integer, 0 = default 256)\n",
					optarg);
				return -1;
			}
			/* /tmp 大小旋钮只能设置一次 — 任一拼写重复或两拼写混用都报错 */
			if (cfg->tmpfs_size_src != 0) {
				fprintf(stderr,
					"conflicting /tmp size (--tmpfs-size / --mount-tmpfs /tmp): /tmp size may be set only once\n");
				return -1;
			}
			cfg->tmpfs_size_src = 1;
			cfg->tmpfs_size_mb = s > 0 ? s : 256;
			break;
		}

		case 'D':
			cfg->dump_config = 1;
			break;

		case 'p':
			if (parse_policy_file(cfg, optarg) < 0)
				return -1;
			cfg->policy_loaded = 1;
			break;

		default:
			return -1;
		}
	}

	if (optind >= argc && !cfg->dump_config) {
		fprintf(stderr, "error: no command specified\n");
		return -1;
	}

	cfg->cmd_argv = argv + optind;
	cfg->cmd_argc = argc - optind;

	/* --share-net 与 --domain/--cidr 互斥 */
	if (cfg->network_mode == NET_MODE_SHARE &&
	    (cfg->ndomains > 0 || cfg->ncidrs > 0)) {
		fprintf(stderr, "--share-net is mutually exclusive with --domain/--cidr\n");
		return -1;
	}
	/* CLI 路径推导: --domain/--cidr 升级白名单; isolate 为默认.
	 * (policy 路径已在 parse_policy_file 收尾定档, 这里不再重复) */
	if (cfg->network_mode != NET_MODE_SHARE &&
	    (cfg->ndomains > 0 || cfg->ncidrs > 0))
		cfg->network_mode = NET_MODE_WHITELIST;

	/* 同 dest 重复挂载 = 歧义配置, 拒绝 (不采纳 bwrap 内核叠挂语义: 同目标两层
	 * 只有顶层可见, 下层白占资源且易误配). CLI 逗号展开 / 选项重复 / YAML mount
	 * 列表产生的重复在这里统一兜住; /tmp 大小改写不占条目, 不参与. */
	for (int i = 0; i < cfg->nmounts; i++)
		for (int j = i + 1; j < cfg->nmounts; j++)
			if (strcmp(cfg->mounts[i].dest, cfg->mounts[j].dest) == 0) {
				fprintf(stderr,
					"duplicate mount destination: %s (each dest may only be mounted once)\n",
					cfg->mounts[i].dest);
				return -1;
			}

	return 0;
}

void print_usage(const char *prog)
{
	fprintf(stderr, "用法: %s [选项...] -- command [args...]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "  选项:\n");
	fprintf(stderr, "    --mount /src[:ro|rw]       bind mount (默认 ro; 逗号分隔多值)\n");
	fprintf(stderr, "    --mount-tmpfs /path[:MB]   tmpfs 挂载  (默认 256M; 逗号分隔多值)\n");
	fprintf(stderr, "                               bind+tmpfs 合计最多 32 条, 同一 dest 只能挂一次\n");
	fprintf(stderr, "    --tmpfs-size MB            /tmp tmpfs 大小 (默认 256)\n");
#ifdef CONFIG_LANDLOCK_ENABLE
	fprintf(stderr, "    --landlock '/p:perm1+perm2'  Landlock 规则\n");
	fprintf(stderr, "    --no-landlock              跳过 Landlock 完全\n");
#endif
	fprintf(stderr, "    --seccomp profile          seccomp profile (default/file_access/script)\n");
	fprintf(stderr, "    --seccomp-syscalls list    custom syscall whitelist (逗号分隔多值)\n");
	fprintf(stderr, "    --domain domain            DNS 域名白名单, 逗号分隔多值\n");
	fprintf(stderr, "    --cidr x.x.x.x/prefix      CIDR 白名单, 逗号分隔多值\n");
	fprintf(stderr, "    --share-net                共享宿主网络命名空间与 DNS\n");
	fprintf(stderr, "    --policy file              从 YAML 策略文件加载配置\n");
	fprintf(stderr, "    -c /path                   工作目录\n");
	fprintf(stderr, "    -D, --dump-config          打印配置后退出\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  示例:\n");
	fprintf(stderr, "    %s --mount /usr:ro -- ls /\n", prog);
	fprintf(stderr, "    %s --seccomp script -c /tmp -- bash -c 'echo ok'\n", prog);
}

void dump_config(const struct sandbox_config *cfg)
{
	printf("=== sandbox_config dump ===\n");
	printf("workdir: %s\n", cfg->workdir);
	printf("tmpfs_size_mb: %ld\n", cfg->tmpfs_size_mb);
	{
		static const char *const net_modes[] = {
			"isolate", "share", "filter"
		};
		int nm = cfg->network_mode;
		if (nm >= 0 && nm <= 2)
			printf("network_mode: %s\n", net_modes[nm]);
		else
			printf("network_mode: %d (invalid)\n", nm);
	}

	/* mount */
	printf("\nmounts (%d):\n", cfg->nmounts);
	for (int i = 0; i < cfg->nmounts; i++) {
		const struct mount_entry *e = &cfg->mounts[i];
		printf("  [%d] type=%s src=%s dest=%s rw=%d size=%lu\n",
		       i, e->is_tmpfs ? "tmpfs" : "bind",
		       e->src, e->dest, e->rw, e->size);
	}

	/* landlock */
	printf("\nlandlock, nolandlock %d, rules (%d):\n", cfg->no_landlock, cfg->nlandlock);
	for (int i = 0; i < cfg->nlandlock; i++) {
		const struct landlock_entry *e = &cfg->landlock_rules[i];
		printf("  [%d] path=%s perms=%s\n", i, e->path, e->perms);
	}

	/* seccomp */
	printf("\nseccomp:\n");
	printf("  profile: %s\n", cfg->seccomp_profile);
	printf("  syscalls: %s\n", cfg->seccomp_syscalls);

	/* network */
	printf("\nnetwork:\n");
	printf("  domains (%d):\n", cfg->ndomains);
	for (int i = 0; i < cfg->ndomains; i++)
		printf("    [%d] %s\n", i, cfg->domains[i]);
	printf("  cidrs (%d):\n", cfg->ncidrs);
	for (int i = 0; i < cfg->ncidrs; i++) {
		char buf[INET_ADDRSTRLEN];
		struct in_addr a = { .s_addr = cfg->cidrs[i].addr };
		inet_ntop(AF_INET, &a, buf, sizeof(buf));
		/* show prefix from mask */
		int pfx = 0;
		__u32 m = ntohl(cfg->cidrs[i].mask);
		while (m & 0x80000000) { pfx++; m <<= 1; }
		printf("    [%d] %s/%d\n", i, buf, pfx);
	}

	printf("\ncommand:\n");
	if (cfg->cmd_argv && cfg->cmd_argc > 0) {
		printf("  argc=%d argv:", cfg->cmd_argc);
		for (int i = 0; i < cfg->cmd_argc; i++)
			printf(" %s", cfg->cmd_argv[i]);
		printf("\n");
	} else {
		printf("  (none)\n");
	}
}

void config_free(struct sandbox_config *cfg)
{
	(void)cfg;
	/* 当前无动态资源, 预留 */
}
