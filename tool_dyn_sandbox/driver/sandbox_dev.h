// SPDX-License-Identifier: GPL-2.0-only
/*
 * sandbox_dev.h
 *
 * UAPI protocol header for /dev/dyn-sandbox
 *
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.

 */
#ifndef _SANDBOX_DEV_H
#define _SANDBOX_DEV_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* ------------------------------------------------------------------ */
/*  Naming constants                                                    */
/* ------------------------------------------------------------------ */
#define SANDBOX_DEVICE    "/dev/dyn-sandbox"
#define SANDBOX_NS_DIR    "/var/run/netns"
#define SANDBOX_PREFIX    "nsp_"

#define SANDBOX_MAX_ENVS      64
#define SANDBOX_IFNAME_SZ     24
#define SANDBOX_MAX_DOMAINS   16
#define SANDBOX_DOMAIN_MAX_LEN 128
#define SANDBOX_MAX_IPS       32
#define SANDBOX_MAX_CIDRS     16
#define SANDBOX_PATH_MAX      512   /* max path length in ABI buffers */
#define SANDBOX_DNS_NAME_MAX  256   /* max DNS query domain name length */

/* ------------------------------------------------------------------ */
/*  Network: CIDR entry                                                */
/* ------------------------------------------------------------------ */
struct sandbox_cidr {
	__u32 addr;        /* network byte order */
	__u32 mask;        /* network byte order */
};

/* ------------------------------------------------------------------ */
/*  Network: DNS report (dyn-sandbox-dns -> kernel)                    */
/* ------------------------------------------------------------------ */
struct sandbox_dns_report {
	__be32 src_ip;              /* child IP that originated the DNS query */
	char   domain[SANDBOX_DNS_NAME_MAX];         /* queried domain name */
	__be32 ips[SANDBOX_MAX_IPS]; /* resolved IPs (network byte order) */
	int    ip_count;
};

/* ------------------------------------------------------------------ */
/*  Network: SET_DNS_PORT                                              */
/* ------------------------------------------------------------------ */
struct sandbox_dns_port {
	__u16 port;
};

/* ------------------------------------------------------------------ */
/*  Network: CREATE request/response                                   */
/* ------------------------------------------------------------------ */
struct sandbox_net_create {
	/* input fields */
	__u32 flags;
	char  domains[SANDBOX_MAX_DOMAINS][SANDBOX_DOMAIN_MAX_LEN];
	int   ndomains;
	struct sandbox_cidr cidrs[SANDBOX_MAX_CIDRS];
	int   ncidrs;

	/* output fields */
	int   env_id;
	char  veth_host[SANDBOX_IFNAME_SZ];   /* kernel-generated */
	char  veth_child[SANDBOX_IFNAME_SZ];  /* kernel-generated */
	__u32 host_ip;       /* host-side veth IP */
	__u32 child_ip;      /* child-side veth IP */
	__u32 gateway;
	__u8  prefix;
	__u16 dns_port;      /* dns-proxy actual listening port */
};

/* ------------------------------------------------------------------ */
/*  File: decision constants                                          */
/* ------------------------------------------------------------------ */
#define DECISION_UNDECIDED	0
#define DECISION_ALLOW		1
#define DECISION_DENY		2

/* ------------------------------------------------------------------ */
/*  File: GET_BLOCKED response                                         */
/* ------------------------------------------------------------------ */
struct sandbox_file_blocked {
	char filename[SANDBOX_PATH_MAX];      /* raw path as given by the user */
	char resolved[SANDBOX_PATH_MAX];      /* absolute path via kern_path + d_path */
};

/* ------------------------------------------------------------------ */
/*  File: DECISION request (ALLOW or DENY)                             */
/* ------------------------------------------------------------------ */
struct sandbox_file_decision {
	char   path[SANDBOX_PATH_MAX];     /* path to allow (ignored for DENY) */
	int    decision;      /* DECISION_ALLOW or DECISION_DENY */
};

/* ------------------------------------------------------------------ */
/*  IOCTL definitions                                                  */
/* ------------------------------------------------------------------ */
#define SANDBOX_IOCTL_MAGIC 'S'

/* Network management */
#define SANDBOX_NET_CREATE        _IOWR(SANDBOX_IOCTL_MAGIC, 1, struct sandbox_net_create)
#define SANDBOX_NET_REPORT_DNS    _IOW(SANDBOX_IOCTL_MAGIC, 2, struct sandbox_dns_report)
#define SANDBOX_NET_SET_DNS_PORT  _IOW(SANDBOX_IOCTL_MAGIC, 3, struct sandbox_dns_port)

/* File runtime authorization */
#define SANDBOX_FILE_GET_BLOCKED  _IOR(SANDBOX_IOCTL_MAGIC, 5, struct sandbox_file_blocked)
#define SANDBOX_FILE_DECISION     _IOW(SANDBOX_IOCTL_MAGIC, 6, struct sandbox_file_decision)
#define SANDBOX_FILE_SET_PID      _IOW(SANDBOX_IOCTL_MAGIC, 7, int)

#endif /* _SANDBOX_DEV_H */
