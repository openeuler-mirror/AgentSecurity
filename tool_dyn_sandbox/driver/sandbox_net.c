/*
 * sandbox_net.c
 *
 * Network isolation - veth + netns + nftables
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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include <linux/kmod.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "sandbox.h"
#include "sandbox_dev.h"
#include "sandbox_net.h"

#define SANDBOX_CMD_MAX       1024  /* max call_usermodehelper command length */
#define MAX_SUBNET_OCTETS     256   /* number of /16 subnets in 10.0.0.0/8 */

/* ====================================================================== */
/*  Utilities — call_usermodehelper wrappers                              */
/* ====================================================================== */

static int run_cmd(const char *fmt, ...)
{
	char *cmd;
	va_list args;
	int ret;

	cmd = kmalloc(SANDBOX_CMD_MAX, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	va_start(args, fmt);
	vsnprintf(cmd, SANDBOX_CMD_MAX, fmt, args);
	va_end(args);

	char *argv[] = { "/bin/bash", "-c", cmd, NULL };
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	kfree(cmd);
	return ret ? -EIO : 0;
}

static int run_cmd_ns(const char *ns_path, const char *fmt, ...)
{
	char *cmd, *nscmd;
	va_list args;
	int ret;

	cmd = kmalloc(SANDBOX_CMD_MAX, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	va_start(args, fmt);
	vsnprintf(cmd, SANDBOX_CMD_MAX, fmt, args);
	va_end(args);

	nscmd = kmalloc(strlen(ns_path) + strlen(cmd) + 32, GFP_KERNEL);
	if (!nscmd) {
		kfree(cmd);
		return -ENOMEM;
	}

	snprintf(nscmd, strlen(ns_path) + strlen(cmd) + 32, "nsenter --net=%s -- %s", ns_path, cmd);

	char *argv[] = { "/bin/bash", "-c", nscmd, NULL };
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	kfree(nscmd);
	kfree(cmd);
	return ret ? -EIO : 0;
}

/* ====================================================================== */
/*  Subnet auto-detection & MASQUERADE                                    */
/* ====================================================================== */

#define IP4(a,b,c,d) cpu_to_be32((((a) << 24) | ((b) << 16) | ((c) << 8) | (d)))

static const struct {
	__be32 net;
	int    prefix;
} probe_subnets[] = {
	{ .net = IP4(10,99,0,0),   .prefix = 16 },
	{ .net = IP4(10,88,0,0),   .prefix = 16 },
	{ .net = IP4(172,18,0,0),  .prefix = 16 },
	{ .net = IP4(172,19,0,0),  .prefix = 16 },
	{ .net = IP4(192,168,99,0), .prefix = 24 },
};

static __be32 subnet_base;
static int    subnet_prefix;
static bool   nat_added;
static __be16 dns_proxy_port;  /* 0 = not set */
static DEFINE_MUTEX(subnet_lock);

static int mask_to_prefix(__be32 mask)
{
	unsigned int m = ntohl(mask);
	int c = 0;
	while (m) { c++; m &= m - 1; }
	return c;
}

static __be32 prefix_to_mask(int prefix)
{
	if (prefix <= 0) return 0;
	return htonl(~0U << (32 - prefix));
}

static int env_acquire_subnet(void)
{
	struct net_device *dev;
	unsigned long probe_used = 0;
	DECLARE_BITMAP(dyn_used, MAX_SUBNET_OCTETS) = { 0 };
	int i;

	rcu_read_lock();
	for_each_netdev(&init_net, dev) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (!in_dev)
			continue;

		for (struct in_ifaddr *ifa = in_dev->ifa_list; ifa;
		     ifa = ifa->ifa_next) {
			__be32 addr = ifa->ifa_address;

			/* Phase 1: check against each probe subnet */
			for (i = 0; i < ARRAY_SIZE(probe_subnets); i++) {
				__be32 mask = prefix_to_mask(
					probe_subnets[i].prefix);
				if ((addr & mask) == probe_subnets[i].net)
					__set_bit(i, &probe_used);
			}

			/* Phase 2: record used /16 in 10.0.0.0/8 */
			if ((ntohl(addr) >> 24) == 10) {
				int octet2 = (ntohl(addr) >> 16) & 0xFF;
				__set_bit(octet2, dyn_used);
			}
		}
	}
	rcu_read_unlock();

	/* Phase 1: first unused probe subnet */
	for (i = 0; i < ARRAY_SIZE(probe_subnets); i++) {
		if (!test_bit(i, &probe_used)) {
			subnet_base   = probe_subnets[i].net;
			subnet_prefix = probe_subnets[i].prefix;
			pr_info("dyn-sandbox: selected subnet %pI4/%d (probe)\n",
				&subnet_base, subnet_prefix);
			return 0;
		}
	}

	/* Phase 2: dynamic scan — first unused 10.x.0.0/16 */
	i = find_first_zero_bit(dyn_used, MAX_SUBNET_OCTETS);
	if (i >= MAX_SUBNET_OCTETS) {
		pr_err("dyn-sandbox: no free subnet found in 10.0.0.0/8\n");
		return -ENOSPC;
	}

	subnet_base   = htonl((10 << 24) | (i << 16));
	subnet_prefix = 16;
	pr_info("dyn-sandbox: selected subnet %pI4/%d (dynamic)\n",
		&subnet_base, subnet_prefix);
	return 0;
}

static int env_add_masquerade(void)
{
	int ret = 0;

	mutex_lock(&subnet_lock);
	if (nat_added)
		goto out_unlock;

	ret = run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>/dev/null; true");

	ret = run_cmd("nft add table ip netpolicy_nat 2>/dev/null; true");
	if (ret)
		goto err_unlock;

	ret = run_cmd("nft add chain netpolicy_nat postrouting "
		      "{ type nat hook postrouting priority srcnat \\; }");
	if (ret)
		goto err_unlock;

	ret = run_cmd("nft add rule netpolicy_nat postrouting "
		      "ip saddr %pI4/%d masquerade",
		      &subnet_base, subnet_prefix);
	if (ret)
		goto err_unlock;

	nat_added = true;
	pr_info("dyn-sandbox: MASQUERADE added via nftables\n");

out_unlock:
	mutex_unlock(&subnet_lock);
	return 0;

err_unlock:
	pr_err("dyn-sandbox: nftables MASQUERADE setup failed: %d\n", ret);
	mutex_unlock(&subnet_lock);
	return ret;
}

/* ====================================================================== */
/*  Module-level net init / exit                                           */
/* ====================================================================== */

static void env_add_filter_accept(void)
{
	char cidr[32];
	int ret;

	snprintf(cidr, sizeof(cidr), "%pI4/%d", &subnet_base, subnet_prefix);

	ret = run_cmd("nft add rule inet firewalld "
		      "filter_IN_public_pre "
		      "ip saddr %s accept", cidr);
	if (ret) {
		pr_warn("dyn-sandbox: nftables rule insert failed"
			" (sandbox DNS may be blocked by firewall)\n");
		return;
	}

	pr_info("dyn-sandbox: filter_IN_public_pre accept rule added for %s\n", cidr);
}

int net_init(void)
{
	int ret;

	ret = env_acquire_subnet();
	if (ret) {
		pr_err("dyn-sandbox: subnet auto-detection failed, networking unavailable\n");
		return ret;
	}

	ret = env_add_masquerade();
	if (ret)
		pr_warn("dyn-sandbox: MASQUERADE setup failed (NAT may not work)\n");

	env_add_filter_accept();

	return 0;
}

/* ====================================================================== */
/*  nftables ruleset deployment                                           */
/* ====================================================================== */

/* env_setup_nftables removed — replaced by inline nft -f - in net_create */

/* ====================================================================== */
/*  Instance lookup by child IP                                           */
/* ====================================================================== */

static LIST_HEAD(net_inst_list);
static DEFINE_SPINLOCK(net_inst_lock);

static struct sandbox_instance *inst_find_by_child_ip(__be32 child_ip)
{
	struct sandbox_instance *inst;
	unsigned long flags;
	spin_lock_irqsave(&net_inst_lock, flags);
	list_for_each_entry(inst, &net_inst_list, net_node) {
		if (inst->net && inst->net->child_ip == child_ip) {
			spin_unlock_irqrestore(&net_inst_lock, flags);
			return inst;
		}
	}
	spin_unlock_irqrestore(&net_inst_lock, flags);
	return NULL;
}

static bool domain_allowed(struct sandbox_net_env *env, const char *domain)
{
	int i;
	for (i = 0; i < env->ndomains; i++) {
		if (strcasecmp(env->domains[i], domain) == 0)
			return true;
	}
	return false;
}

/* ====================================================================== */
/*  env_id allocation                                                     */
/* ====================================================================== */

static DECLARE_BITMAP(env_id_bitmap, MAX_ENV_IDS);
static DEFINE_SPINLOCK(env_id_lock);

/**
 * net_alloc_env - Allocate sandbox_net_env, assign an env_id, copy args in
 * @args: validated network config from userspace
 * @inst: sandbox instance the env is attached to
 */

static struct sandbox_net_env *net_alloc_env(struct sandbox_net_create *args,
					      struct sandbox_instance *inst)
{
	int __id;
	struct sandbox_net_env *env;

	env = kzalloc(sizeof(*env), GFP_KERNEL);
	if (!env)
		return ERR_PTR(-ENOMEM);

	spin_lock(&env_id_lock);
	__id = find_first_zero_bit(env_id_bitmap, MAX_ENV_IDS);
	if (__id >= MAX_ENV_IDS) {
		spin_unlock(&env_id_lock);
		kfree(env);
		return ERR_PTR(-ENOSPC);
	}
	__set_bit(__id, env_id_bitmap);
	spin_unlock(&env_id_lock);
	env->id = __id;

	env->ndomains = args->ndomains;
	env->ncidrs = args->ncidrs;
	memcpy(env->domains, args->domains,
	       SANDBOX_DOMAIN_MAX_LEN * args->ndomains);
	memcpy(env->cidrs, args->cidrs,
	       sizeof(struct sandbox_cidr) * args->ncidrs);

	/* veth 名由内核基于唯一的 env->id 生成（而非用户态传入），保证接口名
	 * 合法且不含 shell 元字符——这些名字会拼进 run_cmd 的 bash 命令 */
	snprintf(env->veth_host, sizeof(env->veth_host), "vp-h-%d", env->id);
	snprintf(env->veth_child, sizeof(env->veth_child), "vp-c-%d", env->id);

	snprintf(env->ns_path, sizeof(env->ns_path), "%s/%s%d",
		 SANDBOX_NS_DIR, SANDBOX_PREFIX, env->id);

	inst->net = env;
	return env;
}

/**
 * net_setup_veth - Create a veth pair and persist the child netns
 * @env: network env with ns_path and env_id
 * @args: veth host/child names from userspace
 */

static int net_setup_veth(struct sandbox_net_env *env,
			   struct sandbox_net_create *args)
{
	char ns_name[32];
	__u32 off = env->id * 4;
	int ret;

	/* Pre-cleanup any stale state */
	run_cmd("ip link delete %s 2>/dev/null; true", env->veth_host);
	run_cmd_ns(env->ns_path, "nft delete table netpolicy 2>/dev/null; true");
	run_cmd("umount %s 2>/dev/null; rm -f %s 2>/dev/null; true",
		env->ns_path, env->ns_path);

	/* Allocate IPs -- /30 per env */
	mutex_lock(&subnet_lock);
	args->host_ip  = subnet_base + htonl(1 + off);
	args->child_ip = subnet_base + htonl(2 + off);
	args->gateway  = args->host_ip;
	mutex_unlock(&subnet_lock);
	args->prefix   = 30;

	env->child_ip = args->child_ip;
	env->host_ip  = args->host_ip;

	/* Persist netns + create veth pair */
	snprintf(ns_name, sizeof(ns_name), "%s%d", SANDBOX_PREFIX, env->id);
	__be32 hip = args->host_ip;
	ret = run_cmd(
		"mkdir -p %s && touch %s && mount --bind /proc/%d/ns/net %s && "
		"ip link add %s type veth peer name %s && "
		"ip link set %s netns %s && "
		"ip addr add %pI4/%d dev %s 2>/dev/null && "
		"ip link set %s up",
		SANDBOX_NS_DIR, env->ns_path,
		task_tgid_nr(current), env->ns_path,
		env->veth_host, env->veth_child,
		env->veth_child, ns_name,
		&hip, args->prefix, env->veth_host,
		env->veth_host);
	if (ret) {
		pr_err("dyn-sandbox: persist+veth setup failed: %d\n", ret);
		return ret;
	}

	return 0;
}

/**
 * net_deploy_nftables - Deploy the nftables ruleset into the child netns
 * @env: network env whose ns_path receives the ruleset
 */

/*
 * nft_append - Append a formatted segment to the nft ruleset script
 * @script: PAGE_SIZE ruleset buffer
 * @slen: in/out accumulated would-be length
 * @fmt: kernel printf format (supports %pI4 etc.)
 *
 * snprintf()/vsnprintf() return the number of bytes they would have written
 * even when the size argument truncates them, so the accumulated @slen can
 * grow past PAGE_SIZE.  Re-feeding that as "PAGE_SIZE - *slen" makes a
 * negative count which, promoted to size_t, becomes huge and lets the next
 * write run past @script.  We therefore (1) refuse to append once *slen has
 * reached PAGE_SIZE, and (2) report -ENOSPC if the segment was truncated, so
 * a caller with a 0 return always has a complete, in-bounds script.
 *
 * Return: 0 on success, -EINVAL on format error, -ENOSPC if the ruleset
 *         would exceed PAGE_SIZE
 */
static int nft_append(char *script, int *slen, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*slen < 0 || *slen >= PAGE_SIZE)
		return -ENOSPC;

	va_start(ap, fmt);
	n = vsnprintf(script + *slen, PAGE_SIZE - *slen, fmt, ap);
	va_end(ap);

	if (n < 0)
		return -EINVAL;
	*slen += n;
	if (*slen >= PAGE_SIZE)
		return -ENOSPC;
	return 0;
}

static int net_deploy_nftables(struct sandbox_net_env *env)
{
	char *script;
	int slen = 0, ret;

	script = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!script)
		return -ENOMEM;

	ret = nft_append(script, &slen,
		"nsenter --net=%s -- nft -f - <<'RULESET'\n"
		"add table ip netpolicy\n"
		"add set netpolicy allowed { type ipv4_addr; flags interval; }\n",
		env->ns_path);
	if (ret)
		goto too_large;

	for (int i = 0; i < env->ncidrs; i++) {
		__be32 addr = env->cidrs[i].addr & env->cidrs[i].mask;
		int pfx = mask_to_prefix(env->cidrs[i].mask);
		ret = nft_append(script, &slen,
			"add element netpolicy allowed { %pI4/%d }\n", &addr, pfx);
		if (ret)
			goto too_large;
	}

	ret = nft_append(script, &slen,
		"add element netpolicy allowed { %pI4/32 }\n", &env->child_ip);
	if (ret)
		goto too_large;

	ret = nft_append(script, &slen,
		"add chain netpolicy output { type filter hook output priority filter; }\n"
		"add rule netpolicy output ip daddr @allowed accept\n");
	if (ret)
		goto too_large;

	/* 快照一次，避免 check 与 dnat 规则读到不同的 port（daemon 重启换端口） */
	__be16 dns_port = READ_ONCE(dns_proxy_port);
	if (dns_port) {
		ret = nft_append(script, &slen,
			"add chain netpolicy dns_nat { type nat hook output priority -100; policy accept; }\n"
			"add rule netpolicy dns_nat udp dport 53 dnat to %pI4:%d\n"
			"add rule netpolicy output ip daddr %pI4 accept\n",
			&env->host_ip, be16_to_cpu(dns_port), &env->host_ip);
		if (ret)
			goto too_large;
	}

	ret = nft_append(script, &slen,
		"add rule netpolicy output reject\n"
		"RULESET\n");
	if (ret)
		goto too_large;

	ret = run_cmd("%s", script);
	kfree(script);
	if (ret)
		pr_err("dyn-sandbox: nftables setup failed: %d\n", ret);
	return ret;

too_large:
	pr_err("dyn-sandbox: nft ruleset too large\n");
	kfree(script);
	return -ENOSPC;
}

/**
 * net_create - Create veth pair, netns and nftables ruleset
 * @inst: sandbox instance to attach the network env to
 * @uarg: userspace SANDBOX_NET_CREATE request
 */

int net_create(struct sandbox_instance *inst, struct sandbox_net_create __user *uarg)
{
	struct sandbox_net_create *args;
	struct sandbox_net_env *env;
	int ret;

	if (!inst)
		return -EBADFD;

	/* Phase 1: copy + validate args from userspace */
	args = kzalloc(sizeof(*args), GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	if (copy_from_user(args, uarg, sizeof(*args))) {
		kfree(args);
		return -EFAULT;
	}

	if (args->ndomains < 0 || args->ndomains > SANDBOX_MAX_DOMAINS) {
		kfree(args);
		return -EINVAL;
	}
	if (args->ncidrs < 0 || args->ncidrs > SANDBOX_MAX_CIDRS) {
		kfree(args);
		return -EINVAL;
	}

	/* Phase 2: allocate sandbox_net_env + env_id, copy params */
	env = net_alloc_env(args, inst);
	if (IS_ERR(env)) {
		kfree(args);
		return PTR_ERR(env);
	}

	/* Phase 3: create veth pair + persist netns */
	ret = net_setup_veth(env, args);
	if (ret)
		goto err_free_env;

	/* Phase 4: deploy nftables ruleset in child netns */
	ret = net_deploy_nftables(env);
	if (ret)
		goto err_del_veth;

	/* Phase 5: writeback results to userspace */
	pr_info("dyn-sandbox: CREATE env=%d host=%pI4 child=%pI4\n",
		env->id, &args->host_ip, &args->child_ip);
	args->env_id = env->id;
	/* 回写内核生成的 veth 名——用户态子进程需用 veth_child 配 IP */
	strscpy(args->veth_host, env->veth_host, sizeof(args->veth_host));
	strscpy(args->veth_child, env->veth_child, sizeof(args->veth_child));
	if (args->ndomains > 0 && !dns_proxy_port) {
		pr_err("dyn-sandbox: dyn-sandbox-dns not registered, but domains configured\n");
		ret = -EAGAIN;
		goto err_del_veth;
	}
	args->dns_port = dns_proxy_port ?
			 be16_to_cpu(dns_proxy_port) : 53;
	if (copy_to_user(uarg, args, sizeof(*args))) {
		kfree(args);
		return -EFAULT;
	}

	/* Register for REPORT_DNS lookup by child IP */
	{
		unsigned long __flags;
		spin_lock_irqsave(&net_inst_lock, __flags);
		list_add(&inst->net_node, &net_inst_list);
		inst->in_net_inst_list = true;
		spin_unlock_irqrestore(&net_inst_lock, __flags);
	}

	kfree(args);
	return 0;

err_del_veth:
	run_cmd("ip link delete %s 2>/dev/null; true", env->veth_host);
	run_cmd("umount %s 2>/dev/null; rm -f %s 2>/dev/null; true",
		env->ns_path, env->ns_path);
err_free_env:
	{
		int __id = env->id;
		spin_lock(&env_id_lock);
		__clear_bit(__id, env_id_bitmap);
		spin_unlock(&env_id_lock);
	}
	kfree(env);
	inst->net = NULL;
	kfree(args);
	return ret;
}
/**
 * net_report_dns - Add DNS resolution results to the allowed set
 * @uarg: userspace DNS report (domain -> IP list)
 */

int net_report_dns(struct sandbox_dns_report __user *uarg)
{
	struct sandbox_dns_report report;
	struct sandbox_net_env *env;
	int i;

	if (copy_from_user(&report, uarg, sizeof(report)))
		return -EFAULT;

	pr_info("dyn-sandbox: REPORT_DNS src_ip=%pI4 domain='%s' ips=%d\n",
		&report.src_ip, report.domain, report.ip_count);

	if (report.ip_count <= 0 || report.ip_count > SANDBOX_MAX_IPS)
		return -EINVAL;
	if (report.domain[0] == '\0')
		return -EINVAL;

	{
		struct sandbox_instance *inst = inst_find_by_child_ip(report.src_ip);
		if (!inst || !inst->net) {
			pr_info("dyn-sandbox: no env found for src_ip %pI4\n", &report.src_ip);
			return -ENOENT;
		}
		env = inst->net;
	}

	if (!domain_allowed(env, report.domain)) {
		pr_info("dyn-sandbox: domain '%s' not in whitelist for env=%d\n",
			report.domain, env->id);
		return -EACCES;
	}

	for (i = 0; i < report.ip_count; i++) {
		__be32 ip = report.ips[i];
		int ret;
		pr_info("dyn-sandbox: adding IP %pI4 to allowed set (env=%d)\n", &ip, env->id);
		ret = run_cmd_ns(env->ns_path, "nft add element netpolicy allowed "
				"{ %pI4 }", &ip);
		if (ret)
			pr_info("dyn-sandbox: nft add element %pI4 failed: %d\n", &ip, ret);
	}

	pr_info("dyn-sandbox: env=%d domain='%s' added %d IP(s) to allowed set\n",
		 env->id, report.domain, report.ip_count);
	return 0;
}

/**
 * net_set_dns_port - Set the dyn-sandbox-dns listening port
 * @uarg: userspace DNS port setting
 */

int net_set_dns_port(struct sandbox_dns_port __user *uarg)
{
	struct sandbox_dns_port p;

	if (copy_from_user(&p, uarg, sizeof(p)))
		return -EFAULT;
	if (p.port == 0)
		return -EINVAL;

	dns_proxy_port = cpu_to_be16(p.port);
	pr_info("dyn-sandbox: dyn-sandbox-dns port set to %d\n", p.port);
	return 0;
}

/**
 * net_destroy - Tear down the sandbox network environment
 * @inst: sandbox instance whose network env is freed
 */

int net_destroy(struct sandbox_instance *inst)
{
	struct sandbox_net_env *env;

	if (!inst)
		return -EINVAL;

	env = inst->net;
	if (!env)
		return -ENOENT;

	if (env->veth_host[0])
		run_cmd_ns(env->ns_path, "nft delete table netpolicy 2>/dev/null; true");

	run_cmd("umount %s 2>/dev/null; rm -f %s 2>/dev/null; true",
		env->ns_path, env->ns_path);

	if (env->veth_host[0])
		run_cmd("ip link delete %s 2>/dev/null; true", env->veth_host);

	spin_lock(&env_id_lock);
	__clear_bit(env->id, env_id_bitmap);
	spin_unlock(&env_id_lock);

	kfree(env);
	inst->net = NULL;

	/* Remove from net_inst_list */
	if (inst->in_net_inst_list) {
		unsigned long __flags;
		spin_lock_irqsave(&net_inst_lock, __flags);
		list_del(&inst->net_node);
		spin_unlock_irqrestore(&net_inst_lock, __flags);
		inst->in_net_inst_list = false;
	}

	return 0;
}

/**
 * net_cleanup_nat - Clean up the MASQUERADE rule on module exit
 */

void net_cleanup_nat(void)
{
	if (nat_added)
		run_cmd("nft delete table netpolicy_nat 2>/dev/null; true");

	run_cmd("nft flush chain inet firewalld filter_IN_public_pre 2>/dev/null; true");
}
