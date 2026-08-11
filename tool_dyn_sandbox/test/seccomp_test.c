/*
 * seccomp_test.c — Seccomp filter verification tool
 *
 * Verifies a seccomp BPF filter by attempting specific syscalls and
 * checking whether each is allowed or blocked (EPERM).
 *
 * Usage: seccomp_test --allow syscall1,syscall2,... --block syscall1,...
 *
 * Compile: gcc -static -O2 -o seccomp_test seccomp_test.c
 *
 * Exit code: 0 = all passed, 1 = any test failed
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>

/* aarch64 compat: map missing SYS_* macros */
#ifdef __aarch64__
#ifndef SYS_access
#define SYS_access SYS_faccessat
#endif
#ifndef SYS_dup2
#define SYS_dup2 SYS_dup3
#endif
#ifndef SYS_mkdir
#define SYS_mkdir SYS_mkdirat
#endif
#ifndef SYS_readlink
#define SYS_readlink SYS_readlinkat
#endif
#endif


#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 1
#endif

#define NR_TEST_SYSCALLS 64
#define MAX_RESULT_LINE  128
#define MAX_RESULTS      128

/* ------------------------------------------------------------------ */
/*  Syscall table — name-to-number + test function                     */
/* ------------------------------------------------------------------ */
struct test_entry {
	const char *name;
	long nr;
	long (*call)(void);
};

static long do_syscall0(long nr) { return syscall(nr); }
static long do_syscall1(long nr, long a1) { return syscall(nr, a1); }
static long do_syscall2(long nr, long a1, long a2) { return syscall(nr, a1, a2); }
static long do_syscall3(long nr, long a1, long a2, long a3) { return syscall(nr, a1, a2, a3); }
static long do_syscall4(long nr, long a1, long a2, long a3, long a4) { return syscall(nr, a1, a2, a3, a4); }
static long do_syscall5(long nr, long a1, long a2, long a3, long a4, long a5) { return syscall(nr, a1, a2, a3, a4, a5); }
static long do_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) { return syscall(nr, a1, a2, a3, a4, a5, a6); }

static long t_read(void)       { return do_syscall3(SYS_read, 0, (long)NULL, 0L); }
static long t_write(void)      { return do_syscall3(SYS_write, 2, (long)"", 0L); }
static long t_openat(void)     { return do_syscall4(SYS_openat, AT_FDCWD, (long)"/dev/null", O_RDONLY, 0L); }
static long t_close(void)      { return do_syscall1(SYS_close, 999L); }
static long t_mmap(void)       { return do_syscall6(SYS_mmap, 0L, 4096L, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0L); }
static long t_mprotect(void)   { return do_syscall3(SYS_mprotect, -1L, 4096L, PROT_READ); }
static long t_munmap(void)     { return do_syscall2(SYS_munmap, -1L, 4096L); }
static long t_brk(void)        { return do_syscall1(SYS_brk, 0L); }
static long t_exit(void)       { return do_syscall1(SYS_exit, 0L); }
static long t_newfstatat(void) { return do_syscall4(SYS_newfstatat, AT_FDCWD, (long)"/dev/null", (long)NULL, 0L); }
static long t_lseek(void)      { return do_syscall3(SYS_lseek, -1, 0L, SEEK_SET); }
static long t_pread64(void)    { return do_syscall4(SYS_pread64, -1, (long)NULL, 0L, 0L); }
static long t_pwrite64(void)   { return do_syscall4(SYS_pwrite64, -1, (long)"", 0L, 0L); }
static long t_access(void)     { return do_syscall2(SYS_access, (long)"/dev/null", R_OK); }
static long t_faccessat(void)  { return do_syscall4(SYS_faccessat, AT_FDCWD, (long)"/dev/null", R_OK, 0L); }
static long t_getdents64(void) { return do_syscall3(SYS_getdents64, -1, (long)NULL, 0L); }
static long t_dup(void)        { return do_syscall1(SYS_dup, 999L); }
static long t_dup2(void)       { return do_syscall3(SYS_dup2, 999L, -1L, 0L); }
static long t_nanosleep(void)  { return do_syscall2(SYS_nanosleep, (long)NULL, (long)NULL); }
static long t_rt_sigaction(void)     { return do_syscall4(SYS_rt_sigaction, SIGTERM, (long)NULL, (long)NULL, 8L); }
static long t_rt_sigprocmask(void)   { return do_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)NULL, (long)NULL, 8L); }
static long t_ioctl(void)      { return do_syscall3(SYS_ioctl, -1, 0L, 0L); }
static long t_writev(void)     { return do_syscall3(SYS_writev, -1, (long)NULL, 0L); }
static long t_execve(void)     { return do_syscall3(SYS_execve, (long)"/nonexistent_xyz_test", (long)NULL, (long)NULL); }
static long t_socket(void)     { return do_syscall3(SYS_socket, AF_INET, SOCK_STREAM, 0L); }
static long t_connect(void)    { struct sockaddr_in a={0}; a.sin_family=AF_INET; return do_syscall3(SYS_connect, -1L, (long)&a, sizeof(a)); }
static long t_clone(void)      { return do_syscall5(SYS_clone, 0L, (long)NULL, (long)NULL, (long)NULL, 0L); }
static long t_pipe2(void)      { return do_syscall2(SYS_pipe2, (long)NULL, 0L); }
static long t_fcntl(void)      { return do_syscall2(SYS_fcntl, -1L, F_GETFD); }
static long t_getpid(void)     { return do_syscall0(SYS_getpid); }
static long t_getuid(void)     { return do_syscall0(SYS_getuid); }
static long t_uname(void)      { return do_syscall1(SYS_uname, (long)NULL); }
static long t_getcwd(void)     { return do_syscall2(SYS_getcwd, (long)NULL, 0L); }
static long t_chdir(void)      { return do_syscall1(SYS_chdir, (long)"/"); }
static long t_clock_gettime(void) { return do_syscall2(SYS_clock_gettime, CLOCK_MONOTONIC, (long)NULL); }
static long t_mkdir(void)      { return do_syscall3(SYS_mkdir, AT_FDCWD, (long)"/tmp/.sc_test", 0755L); }
static long t_statx(void)      { return do_syscall5(SYS_statx, AT_FDCWD, (long)"/dev/null", 0L, 0L, (long)NULL); }
static long t_readlink(void)   { return do_syscall4(SYS_readlink, AT_FDCWD, (long)"/nonexistent", (long)NULL, 0L); }
static long t_wait4(void)      { return do_syscall4(SYS_wait4, -1, (long)NULL, WNOHANG, (long)NULL); }
static long t_getrandom(void)  { return do_syscall3(SYS_getrandom, (long)NULL, 0L, GRND_NONBLOCK); }

static const struct test_entry test_table[] = {
	{"read",         SYS_read,         t_read},
	{"write",        SYS_write,        t_write},
	{"openat",       SYS_openat,       t_openat},
	{"close",        SYS_close,        t_close},
	{"mmap",         SYS_mmap,         t_mmap},
	{"mprotect",     SYS_mprotect,     t_mprotect},
	{"munmap",       SYS_munmap,       t_munmap},
	{"brk",          SYS_brk,          t_brk},
	{"exit",         SYS_exit,         t_exit},
	{"newfstatat",   SYS_newfstatat,   t_newfstatat},
	{"lseek",        SYS_lseek,        t_lseek},
	{"pread64",      SYS_pread64,      t_pread64},
	{"pwrite64",     SYS_pwrite64,     t_pwrite64},
	{"access",       SYS_access,       t_access},
	{"faccessat",    SYS_faccessat,    t_faccessat},
	{"getdents64",   SYS_getdents64,   t_getdents64},
	{"dup",          SYS_dup,          t_dup},
	{"dup2",         SYS_dup2,         t_dup2},
	{"nanosleep",    SYS_nanosleep,    t_nanosleep},
	{"rt_sigaction", SYS_rt_sigaction, t_rt_sigaction},
	{"rt_sigprocmask", SYS_rt_sigprocmask, t_rt_sigprocmask},
	{"ioctl",        SYS_ioctl,        t_ioctl},
	{"writev",       SYS_writev,       t_writev},
	{"execve",       SYS_execve,       t_execve},
	{"socket",       SYS_socket,       t_socket},
	{"connect",      SYS_connect,      t_connect},
	{"clone",        SYS_clone,        t_clone},
	{"pipe2",        SYS_pipe2,        t_pipe2},
	{"fcntl",        SYS_fcntl,        t_fcntl},
	{"getpid",       SYS_getpid,       t_getpid},
	{"getuid",       SYS_getuid,       t_getuid},
	{"uname",        SYS_uname,        t_uname},
	{"getcwd",       SYS_getcwd,       t_getcwd},
	{"chdir",        SYS_chdir,        t_chdir},
	{"clock_gettime", SYS_clock_gettime, t_clock_gettime},
	{"mkdir",        SYS_mkdir,        t_mkdir},
	{"statx",        SYS_statx,        t_statx},
	{"readlink",     SYS_readlink,     t_readlink},
	{"wait4",        SYS_wait4,        t_wait4},
	{"getrandom",    SYS_getrandom,    t_getrandom},
};
#define NTESTS (sizeof(test_table) / sizeof(test_table[0]))

static const struct test_entry *find_test(const char *name)
{
	for (size_t i = 0; i < NTESTS; i++)
		if (strcmp(name, test_table[i].name) == 0)
			return &test_table[i];
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Result buffer                                                      */
/* ------------------------------------------------------------------ */
static char result_buf[MAX_RESULTS][MAX_RESULT_LINE];
static int nresults;

static void add_result(const char *line)
{
	if (nresults < MAX_RESULTS)
		strncpy(result_buf[nresults++], line, MAX_RESULT_LINE - 1);
}

static void flush_results(void)
{
	for (int i = 0; i < nresults; i++) {
		long ignored = syscall(SYS_write, 1, result_buf[i], strlen(result_buf[i]));
		(void)ignored;
	}
	syscall(SYS_write, 2, "\n", 1);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
	int pass = 0, fail = 0, total = 0;

	if (argc < 3) {
		syscall(SYS_write, 2, "Usage: seccomp_test --allow s1,... [--block s1,...]\n", 52);
		return 1;
	}

	const char *allow_str = NULL;
	const char *block_str = NULL;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc)
			allow_str = argv[++i];
		else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc)
			block_str = argv[++i];
	}
	if (!allow_str && !block_str) {
		syscall(SYS_write, 2, "seccomp_test: need --allow and/or --block\n", 42);
		return 1;
	}

	const char *names[NR_TEST_SYSCALLS];
	int expected[NR_TEST_SYSCALLS];
	int nnames = 0;

	if (allow_str) {
		char buf[2048];
		strncpy(buf, allow_str, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;
		char *p = buf, *tok;
		while ((tok = strsep(&p, ",")) != NULL) {
			if (*tok == '\0' || nnames >= NR_TEST_SYSCALLS) continue;
			names[nnames] = strdup(tok);
			expected[nnames] = 1;
			nnames++;
		}
	}
	if (block_str) {
		char buf[2048];
		strncpy(buf, block_str, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;
		char *p = buf, *tok;
		while ((tok = strsep(&p, ",")) != NULL) {
			if (*tok == '\0' || nnames >= NR_TEST_SYSCALLS) continue;
			names[nnames] = strdup(tok);
			expected[nnames] = 0;
			nnames++;
		}
	}

	char line[MAX_RESULT_LINE];

	/* Check if exit_group is in the test list — handle last */
	int has_exit_group = 0;
	int exit_group_expect = 0;
	for (int i = 0; i < nnames; i++) {
		if (strcmp(names[i], "exit_group") == 0) {
			has_exit_group = 1;
			exit_group_expect = expected[i];
			break;
		}
	}

	/* Run all tests except exit_group */
	for (int i = 0; i < nnames; i++) {
		if (strcmp(names[i], "exit_group") == 0)
			continue;
		const struct test_entry *t = find_test(names[i]);
		if (!t) {
			snprintf(line, sizeof(line), "[SKIP] %s: unknown\n", names[i]);
			add_result(line);
			continue;
		}
		errno = 0;
		long ret = t->call();
		int blocked = (ret < 0 && errno == EPERM);
		int ok = (expected[i] && !blocked) || (!expected[i] && blocked);
		if (ok) pass++; else fail++;
		snprintf(line, sizeof(line), "[%s] %s: %s (expect %s, ret=%ld, errno=%d)\n",
			ok ? "PASS" : "FAIL", t->name,
			blocked ? "BLOCK" : "ALLOW",
			expected[i] ? "ALLOW" : "BLOCK", ret, errno);
		add_result(line);
		total++;
	}

	/* Flush all non-exit_group results first */
	snprintf(line, sizeof(line), "\nResults: %d/%d passed, %d failed\n", pass, total, fail);
	add_result(line);
	flush_results();

	/* Now test exit_group — if ALLOWED, process exits here */
	if (has_exit_group) {
		errno = 0;
		long ret = syscall(SYS_exit_group, 0L);
		/* Reached here only if blocked */
		int ok = (exit_group_expect == 0); /* expected BLOCKED → PASS */
		if (!ok) fail++; else pass++;
		snprintf(line, sizeof(line), "[%s] exit_group: BLOCK (expect %s, ret=%ld, errno=%d)\n",
			ok ? "PASS" : "FAIL",
			exit_group_expect ? "ALLOW" : "BLOCK", ret, errno);
		syscall(SYS_write, 1, line, strlen(line));
	}

	_exit(fail > 0 ? 1 : 0);
}
