/*
 * Copyright (c) 2019 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#include <stddef.h>
#include <sched.h>

#include "kore.h"
#include "seccomp.h"
#include "platform.h"

#if defined(KORE_DEBUG)
#define SECCOMP_KILL_POLICY		SECCOMP_RET_TRAP
#else
#define SECCOMP_KILL_POLICY		SECCOMP_RET_KILL
#endif

/*
 * The bare minimum to be able to run kore. These are added last and can
 * be overwritten by a filter program that is added before hand.
 */
static struct sock_filter filter_kore[] = {
	/* Deny these, but with EACCESS instead of dying. */
	KORE_SYSCALL_DENY(ioctl, EACCES),

	/* File related. */
	KORE_SYSCALL_ALLOW(open),
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(stat),
	KORE_SYSCALL_ALLOW(lstat),
	KORE_SYSCALL_ALLOW(fstat),
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(fcntl),
	KORE_SYSCALL_ALLOW(lseek),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(openat),
	KORE_SYSCALL_ALLOW(access),
	KORE_SYSCALL_ALLOW(writev),
	KORE_SYSCALL_ALLOW(getcwd),
	KORE_SYSCALL_ALLOW(unlink),
	KORE_SYSCALL_ALLOW(readlink),

	/* Process related. */
	KORE_SYSCALL_ALLOW(exit),
	KORE_SYSCALL_ALLOW(kill),
	KORE_SYSCALL_ALLOW(getpid),
	KORE_SYSCALL_ALLOW(getuid),
	KORE_SYSCALL_ALLOW(geteuid),
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(nanosleep),

	/* Memory related. */
	KORE_SYSCALL_ALLOW(brk),
	KORE_SYSCALL_ALLOW(munmap),

	/* Deny mmap/mprotect calls with PROT_EXEC/PROT_WRITE protection. */
	KORE_SYSCALL_DENY_WITH_FLAG(mmap, 2, PROT_EXEC | PROT_WRITE, EINVAL),
	KORE_SYSCALL_DENY_WITH_FLAG(mprotect, 2, PROT_EXEC, EINVAL),

	KORE_SYSCALL_ALLOW(mmap),
	KORE_SYSCALL_ALLOW(madvise),
	KORE_SYSCALL_ALLOW(mprotect),

	/* Net related. */
	KORE_SYSCALL_ALLOW(poll),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(accept),
	KORE_SYSCALL_ALLOW(sendfile),
	KORE_SYSCALL_ALLOW(recvfrom),
	KORE_SYSCALL_ALLOW(epoll_ctl),
	KORE_SYSCALL_ALLOW(setsockopt),
	KORE_SYSCALL_ALLOW(epoll_wait),
	KORE_SYSCALL_ALLOW(epoll_pwait),

	/* Signal related. */
	KORE_SYSCALL_ALLOW(sigaltstack),
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(rt_sigaction),
	KORE_SYSCALL_ALLOW(rt_sigprocmask),

	/* "Other" without clear category. */
	KORE_SYSCALL_ALLOW(futex),
	KORE_SYSCALL_ALLOW(clock_gettime),

#if defined(__NR_getrandom)
	KORE_SYSCALL_ALLOW(getrandom),
#endif
};

/* bpf program prologue. */
static struct sock_filter filter_prologue[] = {
	/* Load arch member into accumulator (A) (arch is __u32). */
	KORE_BPF_LOAD(arch, 0),

	/* Compare accumulator against constant, if false jump over kill. */
	KORE_BPF_CMP(SECCOMP_AUDIT_ARCH, 1, 0),
	KORE_BPF_RET(SECCOMP_RET_KILL),

	/* Load the system call number into the accumulator. */
	KORE_BPF_LOAD(nr, 0),
};

/* bpf program epilogue. */
static struct sock_filter filter_epilogue[] = {
	/* Return hit if no system calls matched our list. */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_KILL_POLICY)
};

#define filter_prologue_len	KORE_FILTER_LEN(filter_prologue)
#define filter_epilogue_len	KORE_FILTER_LEN(filter_epilogue)

#if defined(KORE_DEBUG)
static void	seccomp_trap(int sig, siginfo_t *, void *);
#endif

struct filter {
	char			*name;
	struct sock_filter	*prog;
	size_t			instructions;
	TAILQ_ENTRY(filter)	list;
};

static TAILQ_HEAD(, filter)	filters;
static struct filter		*ufilter = NULL;

void
kore_seccomp_init(void)
{
	TAILQ_INIT(&filters);
}

void
kore_seccomp_drop(void)
{
	struct filter		*filter;

	while ((filter = TAILQ_FIRST(&filters)) != NULL) {
		if (!kore_quiet) {
			kore_log(LOG_INFO,
			    "seccomp filter '%s' dropped", filter->name);
		}
		TAILQ_REMOVE(&filters, filter, list);
		kore_free(filter->name);
		kore_free(filter);
	}

	TAILQ_INIT(&filters);
}

void
kore_seccomp_enable(void)
{
#if defined(KORE_DEBUG)
	struct sigaction		sa;
#endif
	struct sock_filter		*sf;
	struct sock_fprog		prog;
	struct kore_runtime_call	*rcall;
	struct filter			*filter;
	size_t				prog_len, off, i;

#if defined(KORE_DEBUG)
	memset(&sa, 0, sizeof(sa));

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = seccomp_trap;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);
	if (sigaction(SIGSYS, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
#endif

	/* Allow application to add its own filters. */
	if ((rcall = kore_runtime_getcall("kore_seccomp_hook")) != NULL) {
		ufilter = TAILQ_FIRST(&filters);
		kore_runtime_execute(rcall);
		kore_free(rcall);
		ufilter = NULL;
	}

	if (worker->id != KORE_WORKER_KEYMGR) {
		/* Add worker required syscalls. */
		kore_seccomp_filter("worker", filter_kore,
		    KORE_FILTER_LEN(filter_kore));
	}

	/* Start with the prologue. */
	prog_len = filter_prologue_len;

	/* Now account for all enabled filters. */
	TAILQ_FOREACH(filter, &filters, list)
		prog_len += filter->instructions;

	/* Finally add the epilogue. */
	prog_len += filter_epilogue_len;

	/* Build the entire bpf program now. */
	if ((sf = calloc(prog_len, sizeof(*sf))) == NULL)
		fatal("calloc");

	off = 0;
	for (i = 0; i < filter_prologue_len; i++)
		sf[off++] = filter_prologue[i];

	TAILQ_FOREACH(filter, &filters, list) {
		for (i = 0; i < filter->instructions; i++)
			sf[off++] = filter->prog[i];

		if (!kore_quiet) {
			kore_log(LOG_INFO,
			    "seccomp filter '%s' added", filter->name);
		}
	}

	for (i = 0; i < filter_epilogue_len; i++)
		sf[off++] = filter_epilogue[i];

	/* Lock and load it. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal("prctl: %s", errno_s);

	prog.filter = sf;
	prog.len = prog_len;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		fatal("prctl: %s", errno_s);

	if (!kore_quiet)
		kore_log(LOG_INFO, "seccomp sandbox activated");
}

int
kore_seccomp_filter(const char *name, void *prog, size_t len)
{
	struct filter		*filter;

	TAILQ_FOREACH(filter, &filters, list) {
		if (!strcmp(filter->name, name))
			return (KORE_RESULT_ERROR);
	}

	filter = kore_calloc(1, sizeof(*filter));

	filter->prog = prog;
	filter->instructions = len;
	filter->name = kore_strdup(name);

	if (ufilter) {
		TAILQ_INSERT_BEFORE(ufilter, filter, list);
	} else {
		TAILQ_INSERT_TAIL(&filters, filter, list);
	}

	return (KORE_RESULT_OK);
}

#if defined(KORE_DEBUG)
static void
seccomp_trap(int sig, siginfo_t *info, void *ucontext)
{
	kore_log(LOG_INFO, "sandbox violation - syscall=%d", info->si_syscall);
}
#endif
