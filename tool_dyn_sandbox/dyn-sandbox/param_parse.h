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
 * param_parse.h — 参数解析（CLI + YAML policy）
 */
#ifndef PARAM_PARSE_H
#define PARAM_PARSE_H

#include "../driver/sandbox_dev.h"

#define MAX_MOUNTS     32
#define MAX_LANDLOCK   64

/* 网络模式 */
enum {
	NET_MODE_ISOLATE   = 0,  /* 默认: 完全隔离, 无网络 (policy mode: isolate) */
	NET_MODE_SHARE     = 1,  /* --share-net / policy mode: share: 共享宿主网络 */
	NET_MODE_WHITELIST = 2,  /* --domain/--cidr / policy mode: filter: 白名单过滤 */
};

struct mount_entry {
	char src[256];     /* host path, empty for tmpfs */
	char dest[256];    /* sandbox path */
	int  rw;             /* 0 = ro (default), 1 = rw */
	int  is_tmpfs;     /* 1 = tmpfs mount */
	unsigned long size; /* tmpfs size in MB, 0 = default */
};

struct landlock_entry {
	char path[256];    /* path pattern */
	char perms[64];    /* permission string */
};

struct sandbox_config {
	/* mount */
	struct mount_entry mounts[MAX_MOUNTS];
	int nmounts;

	/* landlock */
	struct landlock_entry landlock_rules[MAX_LANDLOCK];
	int nlandlock;

	/* seccomp */
	char seccomp_profile[32];
	char seccomp_syscalls[512];  /* custom syscall list (comma-separated) */

	/* network */
	char domains[SANDBOX_MAX_DOMAINS][SANDBOX_DOMAIN_MAX_LEN];
	int  ndomains;
	struct sandbox_cidr cidrs[SANDBOX_MAX_CIDRS];
	int  ncidrs;

	/* work dir */
	char workdir[256];

	/* command */
	char **cmd_argv;
	int cmd_argc;

	/* /tmp tmpfs size in MB, 0 = default 256; 有符号: 负数在解析期拒绝, 防 -1 回绕成 ULONG_MAX */
	long tmpfs_size_mb;

	/* flags */
	int no_landlock;     /* --no-landlock: skip all landlock */
	int network_mode;    /* NET_MODE_ISOLATE / SHARE / WHITELIST; -1 = 未显式设置 (policy 缺省) */
	int policy_loaded;   /* loaded from --policy YAML file */
	int cli_used;        /* any non-policy CLI option was used */
	int dump_config;     /* --dump-config: print config and exit */
};

/* 解析参数, 填充 config, 返回 argv 剩余位置 (command) */
int parse_args(struct sandbox_config *cfg, int argc, char **argv);

/* 打印用法 */
void print_usage(const char *prog);

/* 从 YAML 策略文件加载配置（libyaml） */
int parse_policy_file(struct sandbox_config *cfg, const char *path);

/* 打印 config 所有字段（用于调试） */
void dump_config(const struct sandbox_config *cfg);

/* 释放 config 中的动态资源 */
void config_free(struct sandbox_config *cfg);

#endif /* PARAM_PARSE_H */
