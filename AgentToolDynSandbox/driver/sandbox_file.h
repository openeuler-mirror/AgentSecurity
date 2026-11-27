// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_file.h
 *
 * File runtime authorization interface
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */
#ifndef _SANDBOX_FILE_H
#define _SANDBOX_FILE_H

#include <linux/types.h>

struct sandbox_instance;

int  sandbox_file_init(void);
void sandbox_file_exit(void);

int  sandbox_file_handle_set_pid(struct sandbox_instance *inst, void __user *uarg);
int  sandbox_file_handle_get_blocked(struct sandbox_instance *inst, void __user *uarg);
int  sandbox_file_handle_decision(struct sandbox_instance *inst, void __user *uarg);

void sandbox_file_release(struct sandbox_instance *inst);

#endif /* _SANDBOX_FILE_H */
