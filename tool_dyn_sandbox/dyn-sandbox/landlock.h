/*
 * landlock.h — Landlock 系统调用封装
 */
#ifndef SANDBOX_LANDLOCK_H
#define SANDBOX_LANDLOCK_H

#include <stdint.h>
#include <linux/landlock.h>

/* 创建 ruleset, 返回 fd */
int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                      size_t size, uint32_t flags);

/* 添加路径规则 */
int ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                const void *attr, uint32_t flags);

/* 锁定当前进程 */
int ll_restrict_self(int ruleset_fd, uint32_t flags);

/* 获取所有已知 FS 访问位 */
uint64_t get_all_fs_access(void);

/* 从字符串解析权限 (如 "read+write") */
uint64_t parse_landlock_access(const char *perm_str);

/* 从路径+权限字符串添加规则 (如 "/usr/bin/**:execute+read") */
int ll_add_rule_str(int ruleset_fd, const char *rule_str);

#endif /* SANDBOX_LANDLOCK_H */
