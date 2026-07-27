/*
 * sandbox_file.h
 *
 * File runtime authorization interface
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
