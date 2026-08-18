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
#include <getopt.h>
#include <arpa/inet.h>

#include "param_parse.h"
#include "seccomp_profiles.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static int parse_mount(struct sandbox_config *cfg, const char *arg)
{
	if (cfg->nmounts >= MAX_MOUNTS) {
		fprintf(stderr, "too many --mount entries\n");
		return -1;
	}
	struct mount_entry *e = &cfg->mounts[cfg->nmounts++];

	char buf[512];
	strncpy(buf, arg, sizeof(buf) - 1);
	char *colon = strchr(buf, ':');
	if (colon) {
		*colon = '\0';
		if (strcmp(colon + 1, "rw") == 0)
			e->rw = 1;
		else if (strcmp(colon + 1, "ro") != 0) {
			fprintf(stderr, "invalid mount option: %s"
				" (use ro or rw)\n", colon + 1);
			cfg->nmounts--;
			return -1;
		}
	}
	strncpy(e->src, buf, sizeof(e->src) - 1);
	strncpy(e->dest, buf, sizeof(e->dest) - 1);
	return 0;
}

static int parse_mount_tmpfs(struct sandbox_config *cfg, const char *arg)
{
	char buf[512];
	strncpy(buf, arg, sizeof(buf) - 1);
	char *colon = strchr(buf, ':');
	unsigned long size = 0;
	if (colon) {
		*colon = '\0';
		long s = atol(colon + 1);
		if (s <= 0) {
			fprintf(stderr, "invalid tmpfs size: %ld\n", s);
			return -1;
		}
		size = s;
	}

	/* /tmp 已由系统挂载，只修改大小即可 */
	if (strcmp(buf, "/tmp") == 0) {
		cfg->tmpfs_size_mb = size > 0 ? size : 256;
		return 0;
	}

	if (cfg->nmounts >= MAX_MOUNTS) {
		fprintf(stderr, "too many --mount entries\n");
		return -1;
	}
	struct mount_entry *e = &cfg->mounts[cfg->nmounts++];
	e->is_tmpfs = 1;
	e->size = size;
	strncpy(e->dest, buf, sizeof(e->dest) - 1);
	return 0;
}

#ifdef CONFIG_LANDLOCK_ENABLE
static int parse_landlock(struct sandbox_config *cfg, const char *arg)
{
	if (cfg->nlandlock >= MAX_LANDLOCK) {
		fprintf(stderr, "too many --landlock entries\n");
		return -1;
	}
	struct landlock_entry *e = &cfg->landlock_rules[cfg->nlandlock++];

	char *colon = strchr(arg, ':');
	if (colon) {
		size_t plen = colon - arg;
		if (plen > sizeof(e->path) - 1)
			plen = sizeof(e->path) - 1;
		memcpy(e->path, arg, plen);
		e->path[plen] = '\0';
		strncpy(e->perms, colon + 1, sizeof(e->perms) - 1);
	} else {
		strncpy(e->path, arg, sizeof(e->path) - 1);
	}
	return 0;
}
#endif

static int parse_domains(struct sandbox_config *cfg, const char *arg)
{
	if (arg[0] == '\0') {
		fprintf(stderr, "empty domain name\n");
		return -1;
	}
	char dom_buf[4096];
	strncpy(dom_buf, arg, sizeof(dom_buf) - 1);
	char *tok = strtok(dom_buf, ",");
	while (tok) {
		if (cfg->ndomains >= SANDBOX_MAX_DOMAINS) {
			fprintf(stderr, "too many --domain entries (max %d)\n",
				SANDBOX_MAX_DOMAINS);
			return -1;
		}
		strncpy(cfg->domains[cfg->ndomains], tok,
			SANDBOX_DOMAIN_MAX_LEN - 1);
		cfg->ndomains++;
		tok = strtok(NULL, ",");
	}
	return 0;
}

static int parse_cidrs(struct sandbox_config *cfg, const char *arg)
{
	char cidr_buf[4096];
	strncpy(cidr_buf, arg, sizeof(cidr_buf) - 1);
	char *tok = strtok(cidr_buf, ",");
	while (tok) {
		if (cfg->ncidrs >= SANDBOX_MAX_CIDRS) {
			fprintf(stderr, "too many --cidr entries (max %d)\n",
				SANDBOX_MAX_CIDRS);
			return -1;
		}
		char buf[64];
		strncpy(buf, tok, sizeof(buf) - 1);
		char *slash = strchr(buf, '/');
		if (!slash) {
			fprintf(stderr, "invalid CIDR: %s (need /prefix)\n", tok);
			return -1;
		}
		*slash = '\0';
		int pfx = atoi(slash + 1);
		if (pfx < 0 || pfx > 32) {
			fprintf(stderr, "invalid prefix: %d\n", pfx);
			return -1;
		}
		struct sandbox_cidr *c = &cfg->cidrs[cfg->ncidrs++];
		c->addr = inet_addr(buf);
		c->mask = htonl(pfx ? (~0U << (32 - pfx)) : 0);
		tok = strtok(NULL, ",");
	}
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
			strncpy(cfg->workdir, optarg, sizeof(cfg->workdir) - 1);
			break;

		case 'm':
			if (parse_mount(cfg, optarg) < 0) return -1;
			break;

		case 't':
			if (parse_mount_tmpfs(cfg, optarg) < 0) return -1;
			break;

#ifdef CONFIG_LANDLOCK_ENABLE
		case 'l':
			if (cfg->no_landlock) {
				fprintf(stderr, "--landlock and --no-landlock are mutually exclusive\n");
				return -1;
			}
			if (parse_landlock(cfg, optarg) < 0) return -1;
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
			strncpy(cfg->seccomp_syscalls, optarg,
				sizeof(cfg->seccomp_syscalls) - 1);
			break;

		case 'g':
			if (parse_domains(cfg, optarg) < 0) return -1;
			break;

		case 'i':
			if (parse_cidrs(cfg, optarg) < 0) return -1;
			break;

		case 257: /* --share-net */
			cfg->network_mode = NET_MODE_SHARE;
			break;

		case 'z': {
			long s = atol(optarg);
			if (s < 0) {
				fprintf(stderr, "invalid --tmpfs-size: %ld (must be >= 0, 0 = default 256)\n", s);
				return -1;
			}
			cfg->tmpfs_size_mb = s;
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

	return 0;
}

void print_usage(const char *prog)
{
	fprintf(stderr, "用法: %s [选项...] -- command [args...]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "  选项:\n");
	fprintf(stderr, "    --mount /src[:ro|rw]       bind mount (默认 ro)\n");
	fprintf(stderr, "    --mount-tmpfs /path[:MB]  tmpfs 挂载\n");
	fprintf(stderr, "    --tmpfs-size MB            /tmp tmpfs 大小 (默认 256)\n");
#ifdef CONFIG_LANDLOCK_ENABLE
	fprintf(stderr, "    --landlock '/p:perm1+perm2'  Landlock 规则\n");
	fprintf(stderr, "    --no-landlock              跳过 Landlock 完全\n");
#endif
	fprintf(stderr, "    --seccomp profile          seccomp profile (default/file_access/script)\n");
	fprintf(stderr, "    --seccomp-syscalls list   custom seccomp syscall whitelist (comma-separated names)\n");
	fprintf(stderr, "    --domain domain            DNS 域名白名单 (可重复)\n");
	fprintf(stderr, "    --cidr x.x.x.x/prefix      CIDR 白名单 (可重复)\n");
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
