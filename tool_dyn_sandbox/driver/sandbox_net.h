// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_net.h
 *
 * Network module interface
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */
#ifndef _SANDBOX_NET_H
#define _SANDBOX_NET_H

#include <linux/types.h>

struct sandbox_instance;
struct sandbox_net_create;
struct sandbox_dns_report;

/* IOCTL handlers */
int net_init(void);
int net_create(struct sandbox_instance *inst,
	       struct sandbox_net_create __user *uarg);
int net_report_dns(struct sandbox_dns_report __user *uarg);
int net_destroy(struct sandbox_instance *inst);
int net_set_dns_port(struct sandbox_dns_port __user *uarg);

/* Module exit - clean up the MASQUERADE nft rule */
void net_cleanup_nat(void);

#endif /* _SANDBOX_NET_H */
