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
 * landlock.c — Landlock 系统调用封装
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/landlock.h>

#include "landlock.h"

int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                      size_t size, uint32_t flags)
{
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

int ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                const void *attr, uint32_t flags)
{
	return syscall(SYS_landlock_add_rule, ruleset_fd, type, attr, flags);
}

int ll_restrict_self(int ruleset_fd, uint32_t flags)
{
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

uint64_t get_all_fs_access(void)
{
	uint64_t mask = 0;
	mask |= LANDLOCK_ACCESS_FS_EXECUTE;
	mask |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	mask |= LANDLOCK_ACCESS_FS_READ_FILE;
	mask |= LANDLOCK_ACCESS_FS_READ_DIR;
	mask |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
	mask |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
	mask |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
	mask |= LANDLOCK_ACCESS_FS_MAKE_DIR;
	mask |= LANDLOCK_ACCESS_FS_MAKE_REG;
	mask |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
	mask |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
	mask |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	mask |= LANDLOCK_ACCESS_FS_MAKE_SYM;
	mask |= LANDLOCK_ACCESS_FS_REFER;
	mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	return mask;
}

/*
 * 权限名 ↔ Landlock 标志位对照表
 *
 * | 权限名    | 标志位                        | 文件意义               | 目录意义                              |
 * |-----------|-------------------------------|------------------------|---------------------------------------|
 * | read      | READ_FILE + READ_DIR          | 可读打开               | 可列出目录内容；子树文件可读          |
 * | write     | WRITE_FILE + MAKE_REG + MAKE_DIR | 可写打开             | 可创建文件和目录；子树文件可写        |
 * | execute   | EXECUTE                       | 可执行                 | 子树文件可执行；目录自身无效果        |
 * | remove    | REMOVE_FILE + REMOVE_DIR      | 不可对文件设(内核拒绝) | 可删除目录下的文件和子目录            |
 * | truncate  | TRUNCATE                      | 可截断                 | 子树文件可截断；目录自身无效果        |
 *
 * 目录规则为路径前缀匹配，权限向下覆盖子树。
 */
uint64_t parse_landlock_access(const char *perm_str)
{
	uint64_t access = 0;
	char buf[256];
	char *p, *tok;

	strncpy(buf, perm_str, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	p = buf;
	while ((tok = strsep(&p, "+")) != NULL) {
		if (strcmp(tok, "read") == 0)
			access |= LANDLOCK_ACCESS_FS_READ_FILE |
				  LANDLOCK_ACCESS_FS_READ_DIR;
		else if (strcmp(tok, "write") == 0)
			access |= LANDLOCK_ACCESS_FS_WRITE_FILE |
				  LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_MAKE_DIR;
		else if (strcmp(tok, "execute") == 0)
			access |= LANDLOCK_ACCESS_FS_EXECUTE;
		else if (strcmp(tok, "remove") == 0)
			access |= LANDLOCK_ACCESS_FS_REMOVE_FILE |
				  LANDLOCK_ACCESS_FS_REMOVE_DIR;
		else if (strcmp(tok, "truncate") == 0)
			access |= LANDLOCK_ACCESS_FS_TRUNCATE;
		else
			fprintf(stderr, "landlock: unknown permission '%s'\n", tok);
	}
	return access;
}

/* 从 "/path:perm1+perm2" 格式的字符串添加规则 */
int ll_add_rule_str(int ruleset_fd, const char *rule_str)
{
	char buf[1024];
	char *colon;
	int dir_fd, ret;

	strncpy(buf, rule_str, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	colon = strchr(buf, ':');
	if (!colon) {
		fprintf(stderr, "landlock: rule missing ':' separator: %s\n", rule_str);
		return -1;
	}
	*colon = '\0';

	const char *path = buf;
	const char *perms = colon + 1;

	dir_fd = open(path, O_PATH | O_CLOEXEC);
	if (dir_fd < 0) {
		perror(path);
		return -1;
	}

	uint64_t access = parse_landlock_access(perms);

	/* 非目录路径只能使用文件级权限位 */
	struct stat st;
	if (fstat(dir_fd, &st) == 0 && !S_ISDIR(st.st_mode)) {
		access &= (LANDLOCK_ACCESS_FS_EXECUTE |
			   LANDLOCK_ACCESS_FS_WRITE_FILE |
			   LANDLOCK_ACCESS_FS_READ_FILE |
			   LANDLOCK_ACCESS_FS_TRUNCATE);
	}

	struct landlock_path_beneath_attr attr = {
		.allowed_access = access,
		.parent_fd = dir_fd,
	};

	ret = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
	close(dir_fd);
	return ret;
}
