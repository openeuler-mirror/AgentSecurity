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
 * dyn-sandbox-dns.c — DNS proxy for sandbox network isolation
 *
 * Listens on a UDP port, forwards DNS queries to upstream,
 * extracts resolved A record IPs, and reports them to dyn_sandbox.ko
 * via SANDBOX_NET_REPORT_DNS ioctl so the kernel can dynamically
 * allowlist the resolved IPs for the originating sandbox.
 *
 * Build: gcc -o dyn-sandbox-dns dyn-sandbox-dns.c -lldns
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <sys/random.h>
#include <ldns/ldns.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "../driver/sandbox_dev.h"

/* DNS header (RFC 1035) — 12 bytes */
struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

#define DNS_BUF_SIZE 4096
#define UPSTREAM_PORT 53

/*
 * Pending query table — tracks in-flight DNS queries so responses
 * from upstream can be matched back to the original client.
 */
#define MAX_PENDING 256
#define PENDING_TIMEOUT 5 /* seconds */

/* Monotonic ms — NTP wall-clock steps must not rewind timeouts */
static int64_t mono_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct pending_query {
	uint16_t orig_id;                /* original client DNS ID, restored on reply */
	uint16_t new_id;                 /* dyn-sandbox-dns assigned ID, matches upstream */
	ldns_rr_type qtype;              /* query type (A, AAAA, ...) */
	struct sockaddr_in client;       /* client address for reply + ioctl source */
	char domain[256];                /* query domain, for logging + ioctl */
	int64_t timestamp_ms;            /* monotonic ms when sent, for timeout cleanup */
	int in_use;                      /* slot occupancy flag */
};

static struct pending_query pending[MAX_PENDING];

/* new_id -> pending slot index (O(1) lookup), ID_FREE = not in use.
 * new_id is 16-bit (0-65535); slot indices fit in int16_t. */
#define ID_FREE  (-1)
static int16_t id_to_idx[65536];
static int listen_fd = -1;
static int upstream_fd = -1;
static struct sockaddr_in upstream_addr;

static int sandbox_fd = -1;
static char upstream_dns[64] = "8.8.8.8";

/* Read upstream DNS server from /etc/resolv.conf */
static void read_upstream_dns(void)
{
	FILE *f = fopen("/etc/resolv.conf", "r");
	if (!f) {
		fprintf(stderr, "[dyn-sandbox-dns] warning: cannot open /etc/resolv.conf, "
			"using default %s\n", upstream_dns);
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char ns[64] = {0};
		if (sscanf(line, "nameserver %63s", ns) == 1) {
			strncpy(upstream_dns, ns, sizeof(upstream_dns) - 1);
			printf("[dyn-sandbox-dns] upstream DNS: %s\n", upstream_dns);
			fclose(f);
			return;
		}
	}
	fclose(f);
	fprintf(stderr, "[dyn-sandbox-dns] warning: no nameserver in /etc/resolv.conf\n");
}

/* Quick header validation before passing to ldns_wire2pkt
 * Follows dnsmasq's approach: reject obviously malformed packets
 * that could cause OOM from crafted ancount/qdcount fields */
static int validate_dns_query(const struct dns_header *hdr, size_t len)
{
	if (len < sizeof(struct dns_header))
		return -1;

	uint16_t flags = ntohs(hdr->flags);
	uint16_t qdcount = ntohs(hdr->qdcount);
	uint16_t ancount = ntohs(hdr->ancount);
	uint16_t nscount = ntohs(hdr->nscount);
	uint16_t arcount = ntohs(hdr->arcount);

	/* Must be a standard query (QR=0, opcode=0) */
	if (flags & 0x8000 || (flags & 0x7800) != 0)
		return -1;

	/* A valid query has exactly one question */
	if (qdcount < 1 || qdcount > 10)
		return -1;

	/* Query should not carry answer/authority records */
	if (ancount > 0 || nscount > 0)
		return -1;

	/* EDNS (arcount > 0) adds an OPT pseudo-record; clamp arcount to
	 * prevent ldns from treating crafted additional records as real */
	if (arcount > 1)
		return -1;

	return 0;
}

/* Extract domain name and query type from raw DNS query */
static int parse_query(const uint8_t *wire, size_t wire_len,
		       char *domain, size_t domain_sz,
		       ldns_rr_type *qtype)
{
	ldns_pkt *pkt = NULL;
	ldns_rr_list *questions;
	int ret = -1;

	if (ldns_wire2pkt(&pkt, wire, wire_len) != LDNS_STATUS_OK)
		return -1;

	questions = ldns_pkt_question(pkt);
	if (ldns_rr_list_rr_count(questions) < 1)
		goto out;

	ldns_rr *q = ldns_rr_list_rr(questions, 0);
	ldns_rdf *qname = ldns_rr_owner(q);
	if (!qname)
		goto out;

	char *d = ldns_rdf2str(qname);
	if (!d)
		goto out;

	/* Strip trailing dot (FQDN) */
	size_t len = strlen(d);
	if (len > 0 && d[len - 1] == '.')
		d[len - 1] = '\0';

	snprintf(domain, domain_sz, "%s", d);

	if (qtype)
		*qtype = ldns_rr_get_type(q);

	ret = 0;
	LDNS_FREE(d);
out:
	ldns_pkt_free(pkt);
	return ret;
}

/* Extract A record IPs from DNS response */
static int extract_a_records(const uint8_t *wire, size_t wire_len,
			     __be32 *ips, int max_ips)
{
	ldns_pkt *pkt = NULL;
	ldns_rr_list *answers;
	int n = 0;

	if (ldns_wire2pkt(&pkt, wire, wire_len) != LDNS_STATUS_OK)
		return -1;

	answers = ldns_pkt_answer(pkt);
	for (size_t i = 0; i < ldns_rr_list_rr_count(answers) && n < max_ips; i++) {
		ldns_rr *rr = ldns_rr_list_rr(answers, i);
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_A)
			continue;

		ldns_rdf *rdf = ldns_rr_a_address(rr);
		if (!rdf)
			continue;

		struct in_addr addr;
		memcpy(&addr, ldns_rdf_data(rdf), sizeof(addr));
		ips[n++] = addr.s_addr;
	}

	ldns_pkt_free(pkt);
	return n;
}

/* --- Pending table helpers --- */

/* Find a free slot, returns index or -1 */
static int pending_alloc(void)
{
	for (int i = 0; i < MAX_PENDING; i++) {
		if (!pending[i].in_use)
			return i;
	}
	return -1;
}

/* Allocate a unique random 16-bit ID (0 reserved). id_to_idx gives an O(1)
 * occupancy check; draws ~1 time on average (≤256 in-use of 65535),
 * mirroring dnsmasq's get_id(). */
static uint16_t get_new_id(void)
{
	uint16_t id = 0;

	for (;;) {
		if (getrandom(&id, sizeof(id), 0) != (ssize_t)sizeof(id))
			id = (uint16_t)(rand() & 0xFFFF); /* non-crypto fallback */
		if (id != 0 && id_to_idx[id] == ID_FREE)
			return id;
	}
}

/* Release a slot */
static void pending_free(int idx)
{
	if (idx >= 0 && idx < MAX_PENDING && pending[idx].in_use) {
		id_to_idx[pending[idx].new_id] = ID_FREE;
		pending[idx].in_use = 0;
	}
}

/* Clean up timed-out entries, returns count of entries freed */
static int pending_cleanup(int64_t now_ms)
{
	int count = 0;
	for (int i = 0; i < MAX_PENDING; i++) {
		if (!pending[i].in_use)
			continue;
		if (now_ms - pending[i].timestamp_ms > PENDING_TIMEOUT * 1000) {
			printf("[dyn-sandbox-dns] timeout: %s [id=%d] dropped\n",
			       pending[i].domain, pending[i].new_id);
			pending_free(i);
			count++;
		}
	}
	return count;
}

/* Calculate poll timeout (ms), -1 = wait indefinitely */
static int calc_timeout(void)
{
	int64_t now_ms = mono_now_ms();
	int min_remaining_ms = -1;

	for (int i = 0; i < MAX_PENDING; i++) {
		if (!pending[i].in_use)
			continue;
		int64_t elapsed = now_ms - pending[i].timestamp_ms;
		int64_t remaining = (int64_t)PENDING_TIMEOUT * 1000 - elapsed;
		if (remaining <= 0)
			return 0;
		int remaining_ms = (int)remaining;
		if (min_remaining_ms == -1 || remaining_ms < min_remaining_ms)
			min_remaining_ms = remaining_ms;
	}

	return min_remaining_ms;
}

/* Create UDP listening socket, return fd and actual port */
static int create_listener(int *out_port)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	/* Let kernel assign a random high port; DNAT in child ns handles redirection */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = INADDR_ANY },
		.sin_port = htons(0),
	};

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	struct sockaddr_in actual;
	socklen_t alen = sizeof(actual);
	if (getsockname(fd, (struct sockaddr *)&actual, &alen) < 0) {
		perror("getsockname");
		close(fd);
		return -1;
	}

	*out_port = ntohs(actual.sin_port);
	return fd;
}

/* Create UDP socket connected to the upstream DNS server */
static int create_upstream_socket(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("upstream socket");
		return -1;
	}

	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	upstream_addr.sin_port = htons(UPSTREAM_PORT);
	if (inet_pton(AF_INET, upstream_dns, &upstream_addr.sin_addr) <= 0) {
		fprintf(stderr, "[dyn-sandbox-dns] invalid upstream DNS: %s\n", upstream_dns);
		close(fd);
		return -1;
	}

	/* connect() binds the upstream address so we can use send() instead of sendto() */
	if (connect(fd, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
		perror("upstream connect");
		close(fd);
		return -1;
	}

	return fd;
}

/* Handle a new DNS query from a sandbox */
static void handle_new_query(void)
{
	uint8_t buf[DNS_BUF_SIZE];
	struct sockaddr_in client;
	socklen_t client_len = sizeof(client);

	ssize_t n = recvfrom(listen_fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&client, &client_len);
	if (n < 0) {
		if (errno != EINTR)
			perror("recvfrom");
		return;
	}
	if (n < (ssize_t)sizeof(struct dns_header))
		return;

	struct dns_header *header = (struct dns_header *)buf;
	size_t query_len = (size_t)n;

	if (validate_dns_query(header, query_len) < 0)
		return;

	char domain[256];
	ldns_rr_type qtype = 0;
	if (parse_query(buf, query_len, domain, sizeof(domain), &qtype) < 0) {
		fprintf(stderr, "[dyn-sandbox-dns] failed to parse query\n");
		return;
	}

	char client_ip[64];
	inet_ntop(AF_INET, &client.sin_addr, client_ip, sizeof(client_ip));

	int idx = pending_alloc();
	if (idx < 0) {
		fprintf(stderr, "[dyn-sandbox-dns] pending table full, drop query from %s\n", client_ip);
		return;
	}

	uint16_t new_id = get_new_id();
	if (new_id == 0) {
		fprintf(stderr, "[dyn-sandbox-dns] cannot allocate new_id, drop query from %s\n", client_ip);
		return;
	}
	id_to_idx[new_id] = idx;

	pending[idx].orig_id = ntohs(header->id);
	pending[idx].new_id = new_id;
	pending[idx].qtype = qtype;
	pending[idx].client = client;
	snprintf(pending[idx].domain, sizeof(pending[idx].domain), "%s", domain);
	pending[idx].timestamp_ms = mono_now_ms();
	pending[idx].in_use = 1;

	/* Replace DNS ID and forward to upstream */
	header->id = htons(new_id);
	if (send(upstream_fd, buf, query_len, 0) < 0) {
		perror("send to upstream");
		pending_free(idx);
		return;
	}

	printf("[dyn-sandbox-dns] query from %s:%d: %s (type=%d) [id=%d→%d]\n",
	       client_ip, ntohs(client.sin_port), domain, (int)qtype,
	       pending[idx].orig_id, new_id);
}

/* Handle a DNS response from the upstream server */
static void handle_upstream_reply(void)
{
	uint8_t resp[DNS_BUF_SIZE];
	ssize_t n = recv(upstream_fd, resp, sizeof(resp), 0);
	if (n < 0) {
		if (errno != EINTR)
			perror("recv upstream");
		return;
	}
	if (n < (ssize_t)sizeof(struct dns_header))
		return;

	struct dns_header *header = (struct dns_header *)resp;
	size_t resp_len = (size_t)n;

	uint16_t resp_id = ntohs(header->id);

	/* O(1) slot lookup via the ID map; the in_use / new_id re-checks
	 * guard against a stale or reused entry (e.g. cleaned up by timeout). */
	int idx = id_to_idx[resp_id];
	if (idx < 0 || idx >= MAX_PENDING || !pending[idx].in_use ||
	    pending[idx].new_id != resp_id)
		return;  /* unknown, or already cleaned up by timeout */

	/* Only extract and report IPs for A-record queries */
	if (pending[idx].qtype == LDNS_RR_TYPE_A) {
		__be32 ips[SANDBOX_MAX_IPS];
		int ip_count = extract_a_records(resp, resp_len, ips, SANDBOX_MAX_IPS);

		if (ip_count > 0) {
			struct sandbox_dns_report report;
			memset(&report, 0, sizeof(report));
			report.src_ip = pending[idx].client.sin_addr.s_addr;
			report.ip_count = ip_count;
			memcpy(report.ips, ips, sizeof(__be32) * ip_count);
			snprintf(report.domain, sizeof(report.domain), "%s",
				 pending[idx].domain);

			printf("[dyn-sandbox-dns] REPORT_DNS: %s (%d IPs) [id=%d]\n",
			       pending[idx].domain, ip_count, resp_id);

			if (ioctl(sandbox_fd, SANDBOX_NET_REPORT_DNS, &report) < 0)
				perror("  REPORT_DNS");
		}
	}

	/* Restore original DNS ID before sending back to client */
	header->id = htons(pending[idx].orig_id);

	char client_ip[64];
	inet_ntop(AF_INET, &pending[idx].client.sin_addr, client_ip, sizeof(client_ip));

	if (sendto(listen_fd, resp, resp_len, 0,
		   (struct sockaddr *)&pending[idx].client,
		   sizeof(pending[idx].client)) < 0) {
		perror("sendto client");
	}

	printf("[dyn-sandbox-dns] reply to %s:%d: %s [id=%d→%d]\n",
	       client_ip, ntohs(pending[idx].client.sin_port),
	       pending[idx].domain, resp_id, pending[idx].orig_id);

	pending_free(idx);
}

int main(int argc, char **argv)
{
	const char *listen_addr = "0.0.0.0";
	int listen_port = 0;

	signal(SIGPIPE, SIG_IGN);

	/* Parse --listen IP:PORT */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
			char *colon = strchr(argv[++i], ':');
			if (colon) {
				char *end;
				long p;
				*colon = '\0';
				listen_addr = argv[i];
				errno = 0;
				p = strtol(colon + 1, &end, 10);
				if (errno == ERANGE || end == colon + 1 || *end != '\0' ||
				    p < 0 || p > 65535) {
					fprintf(stderr, "[dyn-sandbox-dns] invalid --listen port: %s\n",
						colon + 1);
					return 1;
				}
				listen_port = (int)p;
			} else {
				listen_addr = argv[i];
			}
		}
	}

	read_upstream_dns();

	/* Open /dev/dyn-sandbox */
	sandbox_fd = open(SANDBOX_DEVICE, O_RDWR);
	if (sandbox_fd < 0) {
		perror("open " SANDBOX_DEVICE);
		fprintf(stderr, "[dyn-sandbox-dns] is dyn_sandbox.ko loaded?\n");
		return 1;
	}
	printf("[dyn-sandbox-dns] opened %s (fd=%d)\n", SANDBOX_DEVICE, sandbox_fd);

	/* Create UDP listener */
	listen_fd = create_listener(&listen_port);
	if (listen_fd < 0) {
		close(sandbox_fd);
		return 1;
	}
	printf("[dyn-sandbox-dns] listening on %s:%d\n", listen_addr, listen_port);

	/* Create upstream socket */
	upstream_fd = create_upstream_socket();
	if (upstream_fd < 0) {
		close(listen_fd);
		close(sandbox_fd);
		return 1;
	}
	printf("[dyn-sandbox-dns] upstream %s:%d (fd=%d)\n",
	       upstream_dns, UPSTREAM_PORT, upstream_fd);

	/* Report our port to kernel */
	struct sandbox_dns_port port_req = { .port = listen_port };
	if (ioctl(sandbox_fd, SANDBOX_NET_SET_DNS_PORT, &port_req) < 0)
		perror("SET_DNS_PORT (non-fatal)");
	else
		printf("[dyn-sandbox-dns] reported port %d to kernel\n", listen_port);

#ifdef HAVE_SYSTEMD
	sd_notify(0, "READY=1");
#endif

	/* Main poll loop: ID map starts fully free (0xFF bytes => -1) */
	srand((unsigned int)time(NULL));   /* seed rand() fallback in get_new_id() */
	memset(id_to_idx, 0xff, sizeof(id_to_idx));
	memset(pending, 0, sizeof(pending));

	for (;;) {
		struct pollfd fds[2];
		fds[0].fd = listen_fd;
		fds[0].events = POLLIN;
		fds[1].fd = upstream_fd;
		fds[1].events = POLLIN;

		int timeout = calc_timeout();
		int ret = poll(fds, 2, timeout);

		if (ret < 0) {
			if (errno == EINTR)
				continue;	/* 信号打断/暂停恢复: 重新阻塞, 不做退出决策 */
			perror("poll");
			break;
		}

		if (fds[0].revents & POLLIN)
			handle_new_query();

		if (fds[1].revents & POLLIN)
			handle_upstream_reply();

		pending_cleanup(mono_now_ms());
	}

	close(upstream_fd);
	close(listen_fd);
	close(sandbox_fd);
	return 0;
}
