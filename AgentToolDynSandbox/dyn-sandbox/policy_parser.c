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
 * policy_parser.c — YAML policy file parser using libyaml
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <yaml.h>

#include "param_parse.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void append_joined(char *buf, size_t size, const char *sep,
			   const char *item)
{
	if (buf[0])
		strncat(buf, sep, size - strlen(buf) - 1);
	strncat(buf, item, size - strlen(buf) - 1);
}

static int yaml_known_key(const char *k)
{
	static const char *const known[] = {
		"name", "version",
		"mount", "landlock", "network", "seccomp",
		"type", "src", "dest", "readonly", "size",
		"path", "access",
		"mode", "domains", "cidrs",
		"profile", "syscalls",
	};
	for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
		if (strcmp(k, known[i]) == 0)
			return 1;
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Parser state                                                       */
/* ------------------------------------------------------------------ */

enum elem { ELEM_MAP, ELEM_SEQ };

struct frame {
	enum elem type;
	int  key_wanted;   /* 1 = next scalar in this MAP is a key;
	                     0 = next scalar in this MAP is a value;
	                     meaningless for SEQ */
	char key[64];      /* last mapping key seen in this frame */
};

#define STACK_MAX 32

struct pctx {
	struct sandbox_config *cfg;
	struct frame stack[STACK_MAX];
	int sp;

	char section[32];     /* mount | landlock | network | seccomp */
	char field[64];       /* current field name within the section */
	int  item_idx;        /* index into mount[] or landlock_rules[] */
	char mount_type[16];  /* bind | tmpfs for current mount item */
	/* 每个 mount 条目是否显式给出 src/dest: bind 禁 dest (恒 = src),
	 * tmpfs 禁 src (无源). 由 handle_mapping_value 置位, finalize 消费. */
	unsigned char src_given[MAX_MOUNTS];
	unsigned char dest_given[MAX_MOUNTS];
};

static struct frame *top(struct pctx *ctx)
{
	return ctx->sp > 0 ? &ctx->stack[ctx->sp - 1] : NULL;
}

static int push(struct pctx *ctx, enum elem type)
{
	if (ctx->sp >= STACK_MAX) {
		fprintf(stderr, "policy: nesting too deep\n");
		return -1;
	}
	struct frame *f = &ctx->stack[ctx->sp++];
	f->type = type;
	f->key_wanted = (type == ELEM_MAP);
	f->key[0] = '\0';
	return 0;
}

static void pop(struct pctx *ctx)
{
	if (ctx->sp > 0) {
		ctx->sp--;
		/* After finishing a complex value (SEQ or MAP),
		 * restore the parent MAP's key_wanted to 1 */
		if (ctx->sp > 0) {
			struct frame *f = &ctx->stack[ctx->sp - 1];
			if (f->type == ELEM_MAP && !f->key_wanted)
				f->key_wanted = 1;
		}
	}
}

/* ================================================================== */
/*  Value handlers                                                     */
/* ================================================================== */

static int handle_mapping_value(struct pctx *ctx, const char *val)
{
	const char *f = ctx->field;

	if (strcmp(ctx->section, "mount") == 0) {
		struct mount_entry *e = (ctx->item_idx >= 0 && ctx->item_idx < MAX_MOUNTS)
					? &ctx->cfg->mounts[ctx->item_idx] : NULL;
		if (!e) return 0;

		if (strcmp(f, "type") == 0) {
			/* S12: type 值必须 bind|tmpfs. 此前任意字符串都静默按 bind 处理
			 * (is_tmpfs = strcmp=="tmpfs"), type: invalid_type 会静默绑成 src,
			 * 策略作者以为 tmpfs 挂载实则 bind. 缺省仍为 bind (usage-guide) */
			if (strcmp(val, "bind") != 0 && strcmp(val, "tmpfs") != 0) {
				fprintf(stderr,
					"policy: invalid mount type '%s' (bind|tmpfs)\n",
					val);
				return -1;
			}
			strncpy(ctx->mount_type, val, sizeof(ctx->mount_type) - 1);
			e->is_tmpfs = (strcmp(val, "tmpfs") == 0);
		} else if (strcmp(f, "src") == 0) {
			strncpy(e->src, val, sizeof(e->src) - 1);
			ctx->src_given[ctx->item_idx] = 1;
		} else if (strcmp(f, "dest") == 0) {
			strncpy(e->dest, val, sizeof(e->dest) - 1);
			ctx->dest_given[ctx->item_idx] = 1;
		} else if (strcmp(f, "readonly") == 0) {
			e->rw = !(strcmp(val, "true") == 0 ||
				       strcmp(val, "yes") == 0);
		} else if (strcmp(f, "size") == 0) {
			long s = atol(val);
			if (s < 0) {
				fprintf(stderr,
					"policy: negative tmpfs size not allowed: %s\n", val);
				return -1;
			}
			e->size = (unsigned long)s;
		}

	} else if (strcmp(ctx->section, "landlock") == 0) {
		if (strcmp(f, "path") == 0) {
			struct landlock_entry *e = (ctx->item_idx >= 0 && ctx->item_idx < MAX_LANDLOCK)
						  ? &ctx->cfg->landlock_rules[ctx->item_idx] : NULL;
			if (e)
				strncpy(e->path, val, sizeof(e->path) - 1);
		}

	} else if (strcmp(ctx->section, "network") == 0) {
		if (strcmp(f, "mode") == 0) {
			int m = -1;
			if (strcmp(val, "filter") == 0)
				m = NET_MODE_WHITELIST;
			else if (strcmp(val, "isolate") == 0)
				m = NET_MODE_ISOLATE;
			else if (strcmp(val, "share") == 0)
				m = NET_MODE_SHARE;
			if (m < 0) {
				fprintf(stderr, "policy: invalid network mode '%s' (filter|isolate|share)\n",
					val);
				return -1;
			}
			ctx->cfg->network_mode = m;
		}

	} else if (strcmp(ctx->section, "seccomp") == 0) {
		if (strcmp(f, "profile") == 0) {
			strncpy(ctx->cfg->seccomp_profile, val,
				sizeof(ctx->cfg->seccomp_profile) - 1);
		}

	} else if (strcmp(ctx->section, "name") == 0 ||
		   strcmp(ctx->section, "version") == 0) {
		/* ignored */
	}
	return 0;
}

static int handle_seq_value(struct pctx *ctx, const char *val)
{
	const char *f = ctx->field;

	/* network domains / cidrs */
	if (strcmp(ctx->section, "network") == 0) {
		if (strcmp(f, "domains") == 0) {
			if (ctx->cfg->ndomains >= SANDBOX_MAX_DOMAINS) {
				fprintf(stderr, "policy: too many domains (max %d)\n",
					SANDBOX_MAX_DOMAINS);
				return -1;
			}
			strncpy(ctx->cfg->domains[ctx->cfg->ndomains], val,
				SANDBOX_DOMAIN_MAX_LEN - 1);
			ctx->cfg->ndomains++;
		} else if (strcmp(f, "cidrs") == 0) {
			if (ctx->cfg->ncidrs >= SANDBOX_MAX_CIDRS) {
				fprintf(stderr, "policy: too many CIDRs (max %d)\n",
					SANDBOX_MAX_CIDRS);
				return -1;
			}

			const char *slash = strchr(val, '/');
			if (!slash) {
				fprintf(stderr, "policy: invalid CIDR '%s' (need /prefix)\n",
					val);
				return -1;
			}
			size_t iplen = (size_t)(slash - val);
			if (iplen == 0 || iplen >= INET_ADDRSTRLEN) {
				fprintf(stderr, "policy: invalid CIDR '%s'\n", val);
				return -1;
			}
			char ip[INET_ADDRSTRLEN];
			memcpy(ip, val, iplen);
			ip[iplen] = '\0';
			char *end;
			long pfx;
			errno = 0;
			pfx = strtol(slash + 1, &end, 10); /* slash+1 已 NUL 结尾 */
			if (errno == ERANGE || end == slash + 1 || *end != '\0' ||
			    pfx < 1 || pfx > 32) {
				fprintf(stderr, "policy: invalid CIDR prefix: %s\n", slash + 1);
				return -1;
			}

			struct in_addr ia;
			if (inet_pton(AF_INET, ip, &ia) != 1) {
				fprintf(stderr, "policy: invalid CIDR address '%s'\n", ip);
				return -1;
			}
			struct sandbox_cidr *c = &ctx->cfg->cidrs[ctx->cfg->ncidrs++];
			c->addr = ia.s_addr;
			c->mask = htonl(~0U << (32 - pfx)); /* pfx 已保证 1..32 */
		}
		return 0;
	}

	/* landlock access list */
	if (strcmp(ctx->section, "landlock") == 0 && strcmp(f, "access") == 0) {
		struct landlock_entry *e = (ctx->item_idx >= 0 && ctx->item_idx < MAX_LANDLOCK)
					  ? &ctx->cfg->landlock_rules[ctx->item_idx] : NULL;
		if (e)
			append_joined(e->perms, sizeof(e->perms), "+", val);
		return 0;
	}

	/* seccomp syscalls list */
	if (strcmp(ctx->section, "seccomp") == 0 && strcmp(f, "syscalls") == 0) {
		append_joined(ctx->cfg->seccomp_syscalls,
			      sizeof(ctx->cfg->seccomp_syscalls), ",", val);
		return 0;
	}

	return 0;
}

/* ================================================================== */
/*  Main entry                                                         */
/* ================================================================== */

int parse_policy_file(struct sandbox_config *cfg, const char *path)
{
	FILE *fh;
	yaml_parser_t parser;
	yaml_event_t event = {0};   /* 零初始化，out: 处 yaml_event_delete 幂等 */

	int saved_dump = cfg->dump_config;
	memset(cfg, 0, sizeof(*cfg));
	strcpy(cfg->workdir, "/");
	cfg->dump_config = saved_dump;
	cfg->network_mode = -1;   /* 未显式设置哨兵: 缺省由列表推导 (见收尾) */
#ifndef CONFIG_LANDLOCK_ENABLE
	/* 无 Landlock 构建: memset 已清零 no_landlock, 这里恢复默认关闭,
	 * 否则 --policy 路径会误开 Landlock (setup_landlock_base 被调用) */
	cfg->no_landlock = 1;
#endif

	fh = fopen(path, "r");
	if (!fh) {
		perror(path);
		return -1;
	}

	if (!yaml_parser_initialize(&parser)) {
		fprintf(stderr, "policy: yaml_parser_initialize failed\n");
		fclose(fh);
		return -1;
	}
	yaml_parser_set_input_file(&parser, fh);

	struct pctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;
	ctx.item_idx = -1;

	int ret = -1;
	int done = 0;

	while (!done) {
		if (!yaml_parser_parse(&parser, &event)) {
			fprintf(stderr, "policy: YAML parse error at line %zu\n",
				parser.problem_mark.line + 1);
			goto out;
		}

		switch (event.type) {
		case YAML_STREAM_START_EVENT:
		case YAML_DOCUMENT_START_EVENT:
		case YAML_DOCUMENT_END_EVENT:
		case YAML_STREAM_END_EVENT:
			if (event.type == YAML_STREAM_END_EVENT)
				done = 1;
			break;

		case YAML_MAPPING_START_EVENT:
			if (push(&ctx, ELEM_MAP) < 0)
				goto out;

			/* Entering a mapping inside a sequence — mount/landlock item */
			if (ctx.sp >= 3) {
				struct frame *below = &ctx.stack[ctx.sp - 2];
				if (below->type == ELEM_SEQ) {
					if (strcmp(ctx.section, "mount") == 0) {
						if (ctx.cfg->nmounts >= MAX_MOUNTS) {
							fprintf(stderr, "policy: too many mounts (max %d)\n",
								MAX_MOUNTS);
							goto out;
						}
						ctx.item_idx = ctx.cfg->nmounts;
						ctx.cfg->nmounts++;
						memset(ctx.mount_type, 0, sizeof(ctx.mount_type));
					} else if (strcmp(ctx.section, "landlock") == 0) {
						ctx.item_idx = ctx.cfg->nlandlock;
						if (ctx.item_idx < MAX_LANDLOCK)
							ctx.cfg->nlandlock++;
					}
				}
			}
			break;

		case YAML_MAPPING_END_EVENT:
			/* Finalize mount item */
			if (strcmp(ctx.section, "mount") == 0 &&
			    ctx.item_idx >= 0 && ctx.item_idx < MAX_MOUNTS) {
				struct mount_entry *e = &ctx.cfg->mounts[ctx.item_idx];
				if (!e->is_tmpfs) {
					/* bind: 只收 src, dest 恒 = src. 显式 dest 是
					 * /oldroot 停泊根逃逸的输入面 (见 reports/②). */
					if (ctx.dest_given[ctx.item_idx]) {
						fprintf(stderr,
							"policy: bind mount takes only 'src'; "
							"'dest' is not allowed (dest is always = src)\n");
						goto out;
					}
					if (e->dest[0] == '\0')
						strncpy(e->dest, e->src, sizeof(e->dest) - 1);
				} else {
					/* tmpfs: 只收 dest, 无 src */
					if (ctx.src_given[ctx.item_idx]) {
						fprintf(stderr,
							"policy: tmpfs mount takes only 'dest'; "
							"'src' is not allowed\n");
						goto out;
					}
					if (e->dest[0] == '\0') {
						fprintf(stderr,
							"policy: tmpfs mount requires 'dest'\n");
						goto out;
					}
				}
			}
			pop(&ctx);
			break;

		case YAML_SEQUENCE_START_EVENT:
			if (push(&ctx, ELEM_SEQ) < 0)
				goto out;
			break;

		case YAML_SEQUENCE_END_EVENT:
			pop(&ctx);
			break;

		case YAML_SCALAR_EVENT: {
			const char *val = (const char *)event.data.scalar.value;
			struct frame *f = top(&ctx);

			if (!f) break;

			if (f->type == ELEM_MAP && f->key_wanted) {
				/* This scalar is a mapping KEY */
				if (!yaml_known_key(val)) {
					fprintf(stderr,
						"policy: unknown key '%s'\n", val);
					goto out;
				}
				strncpy(f->key, val, sizeof(f->key) - 1);
				f->key_wanted = 0;
				strncpy(ctx.field, val, sizeof(ctx.field) - 1);

				/* Top-level key sets the section */
				if (ctx.sp == 1) {
					strncpy(ctx.section, val, sizeof(ctx.section) - 1);
#ifndef CONFIG_LANDLOCK_ENABLE
					/* 无 Landlock 构建: 忽略 landlock 段 (section 置空 → 所有分支 no-op) */
					if (strcmp(val, "landlock") == 0)
						ctx.section[0] = '\0';
#endif
				}

			} else if (f->type == ELEM_MAP) {
				/* This scalar is a mapping VALUE */
				f->key_wanted = 1;
				if (handle_mapping_value(&ctx, val) < 0)
					goto out;

			} else {
				/* We're in a SEQUENCE — list item */
				if (handle_seq_value(&ctx, val) < 0)
					goto out;
			}
			break;
		}

		default:
			break;
		}

		yaml_event_delete(&event);
	}

	for (int i = 0; i < cfg->nmounts; i++) {
		struct mount_entry *e = &cfg->mounts[i];
		const char *p = e->is_tmpfs ? e->dest : e->src;

		if (p[0] == '\0') {
			fprintf(stderr, e->is_tmpfs
				? "policy: tmpfs mount requires 'dest'\n"
				: "policy: bind mount requires 'src'\n");
			goto out;
		}
		if (sandbox_validate_mount_path(p) < 0) {
			fprintf(stderr,
				"policy: invalid mount path '%s' "
				"(absolute, not /oldroot, no '..'/'.'/'//')\n",
				p);
			goto out;
		}
	}

	/* mode 定档与互斥校验 (sentinel -1 = 未写 mode):
	 *   - 未写 mode: 有 domains/cidrs → filter; 否则 isolate
	 *   - 显式 mode: isolate/share 不接受 domains/cidrs
	 * (CLI 路径的 --share-net 与列表互斥由 param_parse.c 检查;
	 *  policy 路径在此统一定档/校验, 与 YAML 键顺序无关) */
	if (cfg->network_mode < 0) {
		cfg->network_mode = (cfg->ndomains > 0 || cfg->ncidrs > 0)
				   ? NET_MODE_WHITELIST : NET_MODE_ISOLATE;
	} else if ((cfg->network_mode == NET_MODE_ISOLATE ||
		    cfg->network_mode == NET_MODE_SHARE) &&
		   (cfg->ndomains > 0 || cfg->ncidrs > 0)) {
		fprintf(stderr,
			"policy: network mode '%s' is mutually exclusive with domains/cidrs\n",
			cfg->network_mode == NET_MODE_ISOLATE ? "isolate" : "share");
		goto out;
	}

	/* seccomp: profile 与 syscalls 互斥 (S11 — CLI 路径 --seccomp/--seccomp-syscalls
	 * 已有互斥, policy 路径此前漏检: 两字段都写时静默双设, 运行期 seccomp_syscalls
	 * 优先盖掉 profile, 策略作者以为 profile 生效实则没有). 收尾统一兜住, 对齐 usage-guide. */
	if (cfg->seccomp_profile[0] && cfg->seccomp_syscalls[0]) {
		fprintf(stderr,
			"policy: 'profile' and 'syscalls' are mutually exclusive in seccomp section\n");
		goto out;
	}

	ret = 0;

out:
	/* 统一释放尚未 delete 的 event（幂等 no-op） */
	yaml_event_delete(&event);
	yaml_parser_delete(&parser);
	fclose(fh);
	return ret;
}
