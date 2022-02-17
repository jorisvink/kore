/*
 * Copyright (c) 2019-2022 Joris Vink <joris@coders.se>
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
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#include <stddef.h>
#include <sched.h>

#include "kore.h"
#include "seccomp.h"
#include "platform.h"

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

#if !defined(SECCOMP_KILL_POLICY)
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
#if defined(SYS_open)
	KORE_SYSCALL_ALLOW(open),
#endif
	KORE_SYSCALL_ALLOW(read),
#if defined(SYS_stat)
	KORE_SYSCALL_ALLOW(stat),
#endif
#if defined(SYS_stat64)
	KORE_SYSCALL_ALLOW(stat64),
#endif
#if defined(SYS_lstat)
	KORE_SYSCALL_ALLOW(lstat),
#endif
	KORE_SYSCALL_ALLOW(fstat),
#if defined(SYS_fstat64)
	KORE_SYSCALL_ALLOW(fstat64),
#endif
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(fcntl),
#if defined(SYS_fcntl64)
	KORE_SYSCALL_ALLOW(fcntl64),
#endif
	KORE_SYSCALL_ALLOW(lseek),
#if defined(SYS__llseek)
	KORE_SYSCALL_ALLOW(_llseek),
#endif
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(openat),
#if defined(SYS_access)
	KORE_SYSCALL_ALLOW(access),
#endif
	KORE_SYSCALL_ALLOW(writev),
	KORE_SYSCALL_ALLOW(getcwd),
#if defined(SYS_unlink)
	KORE_SYSCALL_ALLOW(unlink),
#endif
#if defined(SYS_readlink)
	KORE_SYSCALL_ALLOW(readlink),
#endif
#if defined(SYS_readlinkat)
	KORE_SYSCALL_ALLOW(readlinkat),
#endif

	/* Process related. */
	KORE_SYSCALL_ALLOW(exit),
	KORE_SYSCALL_ALLOW(kill),
	KORE_SYSCALL_ALLOW(getpid),
	KORE_SYSCALL_ALLOW(getuid),
	KORE_SYSCALL_ALLOW(geteuid),
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(nanosleep),
#if defined(SYS_clock_nanosleep)
	KORE_SYSCALL_ALLOW(clock_nanosleep),
#endif
#if defined(SYS_sigreturn)
	KORE_SYSCALL_ALLOW(sigreturn),
#endif

	/* Memory related. */
	KORE_SYSCALL_ALLOW(brk),
	KORE_SYSCALL_ALLOW(munmap),

	/* Deny mmap/mprotect calls with PROT_EXEC/PROT_WRITE protection. */
#if defined(SYS_mmap)
	KORE_SYSCALL_DENY_WITH_FLAG(mmap, 2, PROT_EXEC | PROT_WRITE, EINVAL),
#endif
#if defined(SYS_mmap2)
	KORE_SYSCALL_DENY_WITH_FLAG(mmap2, 2, PROT_EXEC | PROT_WRITE, EINVAL),
#endif
	KORE_SYSCALL_DENY_WITH_FLAG(mprotect, 2, PROT_EXEC, EINVAL),

#if defined(SYS_mmap)
	KORE_SYSCALL_ALLOW(mmap),
#endif
#if defined(SYS_mmap2)
	KORE_SYSCALL_ALLOW(mmap2),
#endif
	KORE_SYSCALL_ALLOW(madvise),
	KORE_SYSCALL_ALLOW(mprotect),

	/* Net related. */
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
	KORE_SYSCALL_ALLOW(ppoll),
#if defined(SYS_send)
	KORE_SYSCALL_ALLOW(send),
#endif
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(accept),
	KORE_SYSCALL_ALLOW(sendfile),
#if defined(SYS_recv)
	KORE_SYSCALL_ALLOW(recv),
#endif
	KORE_SYSCALL_ALLOW(recvfrom),
	KORE_SYSCALL_ALLOW(epoll_ctl),
	KORE_SYSCALL_ALLOW(setsockopt),
#if defined(SYS_epoll_wait)
	KORE_SYSCALL_ALLOW(epoll_wait),
#endif
	KORE_SYSCALL_ALLOW(epoll_pwait),

	/* Signal related. */
	KORE_SYSCALL_ALLOW(sigaltstack),
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(rt_sigaction),
	KORE_SYSCALL_ALLOW(rt_sigprocmask),

	/* "Other" without clear category. */
	KORE_SYSCALL_ALLOW(futex),
#if defined(SYS_clock_gettime)
	KORE_SYSCALL_ALLOW(clock_gettime),
#endif

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

static struct sock_filter	*seccomp_filter_update(struct sock_filter *,
				    const char *, size_t);

#define filter_prologue_len	KORE_FILTER_LEN(filter_prologue)
#define filter_epilogue_len	KORE_FILTER_LEN(filter_epilogue)

static void	seccomp_register_violation(pid_t);

struct filter {
	char			*name;
	struct sock_filter	*prog;
	size_t			instructions;
	TAILQ_ENTRY(filter)	list;
};

static TAILQ_HEAD(, filter)	filters;
static struct filter		*ufilter = NULL;

/*
 * If enabled will instruct the parent process to ptrace its children and
 * log any seccomp SECCOMP_RET_TRACE rule.
 */
int	kore_seccomp_tracing = 0;

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
	struct sock_filter		*sf;
	struct sock_fprog		prog;
	struct kore_runtime_call	*rcall;
	struct filter			*filter;
	size_t				prog_len, off, i;

	/*
	 * If kore_seccomp_tracing is turned on, set the default policy to
	 * SECCOMP_RET_TRACE so we can log the system calls.
	 */
	if (kore_seccomp_tracing) {
		filter_epilogue[0].k = SECCOMP_RET_TRACE;
		kore_log(LOG_NOTICE, "seccomp tracing enabled");
	}

#if defined(KORE_USE_PYTHON)
	ufilter = TAILQ_FIRST(&filters);
	kore_python_seccomp_hook("koreapp.seccomp");
	ufilter = NULL;
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
		fatalx("calloc");

	off = 0;
	for (i = 0; i < filter_prologue_len; i++)
		sf[off++] = filter_prologue[i];

	TAILQ_FOREACH(filter, &filters, list) {
		for (i = 0; i < filter->instructions; i++)
			sf[off++] = filter->prog[i];
	}

	for (i = 0; i < filter_epilogue_len; i++)
		sf[off++] = filter_epilogue[i];

	/* Lock and load it. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatalx("prctl: %s", errno_s);

	prog.filter = sf;
	prog.len = prog_len;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		fatalx("prctl: %s", errno_s);

#if defined(KORE_USE_PYTHON)
	kore_python_seccomp_cleanup();
#endif
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

void
kore_seccomp_traceme(void)
{
	if (kore_seccomp_tracing == 0)
		return;

	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		fatalx("ptrace: %s", errno_s);
	if (kill(worker->pid, SIGSTOP) == -1)
		fatalx("kill: %s", errno_s);
}

int
kore_seccomp_trace(pid_t pid, int status)
{
	int	evt;

	if (kore_seccomp_tracing == 0)
		return (KORE_RESULT_ERROR);

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
		if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
		    PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE |
		    PTRACE_O_TRACEFORK) == -1)
			fatal("ptrace: %s", errno_s);
		if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
			fatal("ptrace: %s", errno_s);
		return (KORE_RESULT_OK);
	}

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		evt = status >> 8;
		if (evt == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)))
			seccomp_register_violation(pid);
		if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
			fatal("ptrace: %s", errno_s);
		return (KORE_RESULT_OK);
	}

	if (WIFSTOPPED(status)) {
		if (ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status)) == -1)
			fatal("ptrace: %s", errno_s);
		return (KORE_RESULT_OK);
	}

	return (KORE_RESULT_ERROR);
}

int
kore_seccomp_syscall_resolve(const char *name)
{
	int		i;

	for (i = 0; kore_syscall_map[i].name != NULL; i++) {
		if (!strcmp(name, kore_syscall_map[i].name))
			return (kore_syscall_map[i].nr);
	}

	return (-1);
}

const char *
kore_seccomp_syscall_name(long sysnr)
{
	int		i;

	for (i = 0; kore_syscall_map[i].name != NULL; i++) {
		if (kore_syscall_map[i].nr == sysnr)
			return (kore_syscall_map[i].name);
	}

	return ("unknown");
}

struct sock_filter *
kore_seccomp_syscall_filter(const char *name, int action)
{
	struct sock_filter	filter[] = {
		KORE_SYSCALL_FILTER(exit, action),
		KORE_BPF_GUARD
	};

	return (seccomp_filter_update(filter, name, KORE_FILTER_LEN(filter)));
}

struct sock_filter *
kore_seccomp_syscall_arg(const char *name, int action, int arg, int value)
{
	struct sock_filter	filter[] = {
		KORE_SYSCALL_ARG(exit, arg, value, action),
		KORE_BPF_GUARD
	};

	return (seccomp_filter_update(filter, name, KORE_FILTER_LEN(filter)));
}

struct sock_filter *
kore_seccomp_syscall_mask(const char *name, int action, int arg, int value)
{
	struct sock_filter	filter[] = {
		KORE_SYSCALL_MASK(exit, arg, value, action),
		KORE_BPF_GUARD
	};

	return (seccomp_filter_update(filter, name, KORE_FILTER_LEN(filter)));
}

struct sock_filter *
kore_seccomp_syscall_flag(const char *name, int action, int arg, int value)
{
	struct sock_filter	filter[] = {
		KORE_SYSCALL_WITH_FLAG(exit, arg, value, action),
		KORE_BPF_GUARD
	};

	return (seccomp_filter_update(filter, name, KORE_FILTER_LEN(filter)));
}

static void
seccomp_register_violation(pid_t pid)
{
	int				idx;
	struct kore_worker		*kw;
	struct iovec			iov;
#if defined(__arm__)
	struct pt_regs			regs;
#else
	struct user_regs_struct		regs;
#endif
	long				sysnr;
	const char			*name;

	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);

	if (ptrace(PTRACE_GETREGSET, pid, 1, &iov) == -1)
		fatal("ptrace: %s", errno_s);

#if SECCOMP_AUDIT_ARCH == AUDIT_ARCH_X86_64
	sysnr = regs.orig_rax;
#elif SECCOMP_AUDIT_ARCH == AUDIT_ARCH_AARCH64
	sysnr = regs.regs[8];
#elif SECCOMP_AUDIT_ARCH == AUDIT_ARCH_ARM
	sysnr = regs.uregs[7];
#else
#error "platform not supported"
#endif

	name = NULL;
	for (idx = 0; idx < worker_count; idx++) {
		kw = kore_worker_data(idx);
		if (kw->pid == pid) {
			name = kore_worker_name(kw->id);
			break;
		}
	}

	if (name == NULL)
		name = "<child>";

	kore_log(LOG_INFO, "seccomp violation, %s pid=%d, syscall=%ld:%s",
	    name, pid, sysnr, kore_seccomp_syscall_name(sysnr));
}

static struct sock_filter *
seccomp_filter_update(struct sock_filter *filter, const char *name, size_t elm)
{
	int			nr;
	struct sock_filter	*result;

	if ((nr = kore_seccomp_syscall_resolve(name)) == -1)
		return (NULL);

	result = kore_calloc(elm, sizeof(struct sock_filter));
	memcpy(result, filter, elm * sizeof(struct sock_filter));

	/* Update the syscall number to the one specified. */
	result[0].k = nr;

	return (result);
}
