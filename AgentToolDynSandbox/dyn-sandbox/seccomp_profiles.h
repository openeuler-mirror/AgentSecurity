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
 * seccomp_profiles.h — 预置 seccomp profile 声明
 *
 * 每个 profile 定义为一个 syscall 号数组 + 一个构建函数。
 * BPF 过滤器在运行时由 seccomp_build() 动态生成。
 */
#ifndef SECCOMP_PROFILES_H
#define SECCOMP_PROFILES_H

#include <linux/filter.h>
#include <linux/seccomp.h>

/* 构建 BPF 过滤器: 白名单 syscalls, 默认 kill
 * 返回的 sock_fprog 在 seccomp() 后可释放
 */
struct sock_fprog seccomp_build(const int *syscalls, int count);

/* 通过 profile 名称查找并构建 */
struct sock_fprog seccomp_lookup(const char *name);

/* 从逗号分隔的 syscall 名称列表构建自定义 profile */
struct sock_fprog seccomp_build_from_names(const char *names);

/* 校验 profile 名称是否合法 */
int seccomp_valid_profile(const char *name);

#endif /* SECCOMP_PROFILES_H */
