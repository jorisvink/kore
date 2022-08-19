/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include "kore.h"

#if defined(KORE_USE_ACME)
#include "acme.h"
#endif

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

#if defined(KORE_USE_CURL)
#include "curl.h"
#endif

#if defined(__linux__)
#include "seccomp.h"
#endif

#define WORKER_SOLO_COUNT	3

#define WORKER(id)						\
	(struct kore_worker *)((u_int8_t *)kore_workers +	\
	    (sizeof(struct kore_worker) * id))

struct wlock {
	volatile int		lock;
	pid_t			current;
};

static int	worker_trylock(void);
static void	worker_unlock(void);
static void	worker_reaper(pid_t, int);
static void	worker_runtime_teardown(void);
static void	worker_runtime_configure(void);
static void	worker_domain_check(struct kore_domain *);

static struct kore_runtime_call	*worker_runtime_signal(void);

static inline int	worker_acceptlock_obtain(void);
static inline void	worker_acceptlock_release(void);
static void		worker_accept_avail(struct kore_msg *, const void *);

static void	worker_entropy_recv(struct kore_msg *, const void *);
static void	worker_keymgr_response(struct kore_msg *, const void *);

static pid_t				worker_pgrp;
static int				accept_avail;
static struct kore_worker		*kore_workers;
static int				worker_no_lock;
static int				shm_accept_key;
static struct wlock			*accept_lock;

struct kore_worker		*worker = NULL;
u_int8_t			worker_set_affinity = 1;
u_int32_t			worker_accept_threshold = 16;
u_int32_t			worker_rlimit_nofiles = 768;
u_int32_t			worker_max_connections = 512;
u_int32_t			worker_active_connections = 0;
int				worker_policy = KORE_WORKER_POLICY_RESTART;

int
kore_worker_init(void)
{
	size_t			len;
	struct kore_worker	*kw;
	u_int16_t		idx, id, cpu;

	worker_no_lock = 0;

	if (worker_count == 0)
		worker_count = cpu_count;

	/* Account for the keymgr/acme even if we don't end up starting it. */
	worker_count += 2;

	len = sizeof(*accept_lock) +
	    (sizeof(struct kore_worker) * worker_count);

	shm_accept_key = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);
	if (shm_accept_key == -1)
		fatal("kore_worker_init(): shmget() %s", errno_s);
	if ((accept_lock = shmat(shm_accept_key, NULL, 0)) == (void *)-1)
		fatal("kore_worker_init(): shmat() %s", errno_s);

	accept_lock->lock = 0;
	accept_lock->current = 0;

	kore_workers = (struct kore_worker *)((u_int8_t *)accept_lock +
	    sizeof(*accept_lock));
	memset(kore_workers, 0, sizeof(struct kore_worker) * worker_count);

	if (worker_count > cpu_count)
		kore_log(LOG_NOTICE, "more worker processes than cpu cores");

	/* Setup log buffers. */
	for (idx = KORE_WORKER_BASE; idx < worker_count; idx++) {
		kw = WORKER(idx);
		kw->lb.offset = 0;
	}

	if (!kore_quiet)
		kore_log(LOG_INFO, "starting worker processes");

	if ((worker_pgrp = getpgrp()) == -1)
		fatal("%s: getpgrp(): %s", __func__, errno_s);

	/* Now start all the workers. */
	id = 1;
	cpu = 1;
	for (idx = KORE_WORKER_BASE; idx < worker_count; idx++) {
		if (cpu >= cpu_count)
			cpu = 0;
		if (!kore_worker_spawn(idx, id++, cpu++))
			return (KORE_RESULT_ERROR);
	}

	if (kore_keymgr_active) {
#if defined(KORE_USE_ACME)
		/* The ACME process is only started if we need it. */
		if (acme_domains) {
			if (!kore_worker_spawn(KORE_WORKER_ACME_IDX,
			    KORE_WORKER_ACME, 0))
				return (KORE_RESULT_ERROR);
		}
#endif

		/* Now we can start the keymgr. */
		if (!kore_worker_spawn(KORE_WORKER_KEYMGR_IDX,
		    KORE_WORKER_KEYMGR, 0))
			return (KORE_RESULT_ERROR);
	}

	if (!kore_quiet)
		kore_log(LOG_INFO, "all worker processes started");

	return (KORE_RESULT_OK);
}

int
kore_worker_spawn(u_int16_t idx, u_int16_t id, u_int16_t cpu)
{
	int			cnt;
	struct kore_worker	*kw;
#if defined(__linux__)
	int			status;
#endif

	kw = WORKER(idx);
	kw->id = id;
	kw->cpu = cpu;
	kw->running = 1;

	kw->ready = 0;
	kw->has_lock = 0;
	kw->active_route = NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, kw->pipe) == -1)
		fatal("socketpair(): %s", errno_s);

	if (!kore_connection_nonblock(kw->pipe[0], 0) ||
	    !kore_connection_nonblock(kw->pipe[1], 0))
		fatal("could not set pipe fds to nonblocking: %s", errno_s);

	switch (id) {
	case KORE_WORKER_KEYMGR:
		kw->ps = &keymgr_privsep;
		break;
#if defined(KORE_USE_ACME)
	case KORE_WORKER_ACME:
		kw->ps = &acme_privsep;
		break;
#endif
	default:
		kw->ps = &worker_privsep;
		break;
	}

	kw->pid = fork();
	if (kw->pid == -1)
		fatal("could not spawn worker child: %s", errno_s);

	if (kw->pid == 0) {
		kw->pid = getpid();
		kore_worker_entry(kw);
		exit(1);
	} else {
		for (cnt = 0; cnt < 50; cnt++) {
			if (kw->ready == 1)
				break;
			usleep(100000);
#if defined(__linux__)
			/*
			 * If seccomp_tracing is enabled, make sure we
			 * handle the SIGSTOP from the child processes.
			 */
			if (kore_seccomp_tracing) {
				if (waitpid(kw->pid, &status, WNOHANG) > 0)
					kore_seccomp_trace(kw->pid, status);
			}
#endif
		}

		if (kw->ready == 0) {
			kore_log(LOG_NOTICE,
			    "worker %d failed to start, shutting down",
			    kw->id);

			return (KORE_RESULT_ERROR);
		}
	}

	return (KORE_RESULT_OK);
}

struct kore_worker *
kore_worker_data(u_int8_t idx)
{
	if (idx >= worker_count)
		fatal("idx %u too large for worker count", idx);

	return (WORKER(idx));
}

struct kore_worker *
kore_worker_data_byid(u_int16_t id)
{
	struct kore_worker	*kw;
	u_int16_t		idx;

	for (idx = 0; idx < worker_count; idx++) {
		kw = WORKER(idx);
		if (kw->id == id)
			return (kw);
	}

	return (NULL);
}

void
kore_worker_shutdown(void)
{
	struct kore_worker	*kw;
	pid_t			pid;
	int			status;
	u_int16_t		idx, done;

	if (!kore_quiet) {
		kore_log(LOG_NOTICE,
		    "waiting for workers to drain and shutdown");
	}

	for (;;) {
		for (idx = 0; idx < worker_count; idx++) {
			kw = WORKER(idx);
			if (kw->running == 0)
				continue;

			if (kw->pid != 0) {
				pid = waitpid(kw->pid, &status, 0);
				if (pid == -1 && errno != ECHILD)
					continue;

#if defined(__linux__)
				kore_seccomp_trace(kw->pid, status);
#endif

				kw->pid = 0;
				kw->running = 0;

				kw->msg[0]->evt.flags |= KORE_EVENT_READ;
				net_recv_flush(kw->msg[0]);

				if (!kore_quiet) {
					kore_log(LOG_NOTICE,
					    "worker %s exited (%d)",
					    kore_worker_name(kw->id), status);
				}
			}
		}

		done = 0;
		for (idx = 0; idx < worker_count; idx++) {
			kw = WORKER(idx);
			if (kw->running == 0) {
				done++;
				continue;
			}
		}

		if (done == worker_count)
			break;
	}

	if (shmctl(shm_accept_key, IPC_RMID, NULL) == -1) {
		kore_log(LOG_NOTICE,
		    "failed to deleted shm segment: %s", errno_s);
	}
}

void
kore_worker_dispatch_signal(int sig)
{
	u_int16_t		idx;
	struct kore_worker	*kw;

	for (idx = 0; idx < worker_count; idx++) {
		kw = WORKER(idx);

		if (kw->pid == -1 || kw->pid == 0)
			continue;

		if (kill(kw->pid, sig) == -1) {
			kore_log(LOG_WARNING, "kill(%d, %d): %s",
			    kw->pid, sig, errno_s);
		}
	}
}

void
kore_worker_privsep(void)
{
	rlim_t			fd;
	struct rlimit		rl;
	struct passwd		*pw;

	if (worker == NULL)
		fatalx("%s called with no worker", __func__);

	pw = NULL;

	/* Must happen before chroot. */
	if (worker->ps->skip_runas == 0) {
		if (worker->ps->runas == NULL) {
			fatalx("no runas user given for %s",
			    kore_worker_name(worker->id));
		}

		if ((pw = getpwnam(worker->ps->runas)) == NULL) {
			fatalx("cannot getpwnam(\"%s\") for user: %s",
			    worker->ps->runas, errno_s);
		}
	}

	if (worker->ps->skip_chroot == 0) {
		if (chroot(worker->ps->root) == -1) {
			fatalx("cannot chroot(\"%s\"): %s",
			    worker->ps->root, errno_s);
		}

		if (chdir("/") == -1)
			fatalx("cannot chdir(\"/\"): %s", errno_s);
	} else {
		if (chdir(worker->ps->root) == -1) {
			fatalx("cannot chdir(\"%s\"): %s",
			    worker->ps->root, errno_s);
		}
	}

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
		kore_log(LOG_WARNING, "getrlimit(RLIMIT_NOFILE): %s", errno_s);
	} else {
		for (fd = 0; fd < rl.rlim_cur; fd++) {
			if (fcntl(fd, F_GETFD, NULL) != -1) {
				worker_rlimit_nofiles++;
			}
		}
	}

	rl.rlim_cur = worker_rlimit_nofiles;
	rl.rlim_max = worker_rlimit_nofiles;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		kore_log(LOG_ERR, "setrlimit(RLIMIT_NOFILE, %u): %s",
		    worker_rlimit_nofiles, errno_s);
	}

	if (worker->ps->skip_runas == 0) {
		if (setgroups(1, &pw->pw_gid) ||
#if defined(__MACH__) || defined(NetBSD)
		    setgid(pw->pw_gid) || setegid(pw->pw_gid) ||
		    setuid(pw->pw_uid) || seteuid(pw->pw_uid))
#else
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
#endif
			fatalx("cannot drop privileges (%s)", errno_s);
	}

	kore_platform_sandbox();
}

void
kore_worker_entry(struct kore_worker *kw)
{
	struct kore_runtime_call	*sigcall;
	u_int64_t			last_seed;
	int				quit, had_lock, sig;
	u_int64_t			netwait, now, next_timeo;

	worker = kw;

	if (!kore_foreground)
		closelog();

#if defined(__linux__)
	kore_seccomp_traceme();
#endif

	kore_platform_proctitle(kore_worker_name(kw->id));

	if (worker_set_affinity == 1)
		kore_platform_worker_setcpu(kw);

	kore_pid = kw->pid;
	kore_signal_setup();

	if (kw->id == KORE_WORKER_KEYMGR) {
		kore_keymgr_run();
		exit(0);
	}

#if defined(KORE_USE_ACME)
	if (kw->id == KORE_WORKER_ACME) {
		kore_acme_run();
		exit(0);
	}
#endif

	net_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_worker_init();

#if defined(KORE_USE_TASKS)
	kore_task_init();
#endif

	kore_worker_privsep();

#if !defined(KORE_NO_HTTP)
	http_init();
	kore_filemap_resolve_paths();
	kore_accesslog_worker_init();
#endif
	kore_timer_init();
	kore_fileref_init();
	kore_tls_keymgr_init();

	quit = 0;
	had_lock = 0;
	next_timeo = 0;
	accept_avail = 1;
	worker_active_connections = 0;

	last_seed = 0;

	if (kore_keymgr_active) {
		kore_msg_register(KORE_MSG_CRL, worker_keymgr_response);
		kore_msg_register(KORE_MSG_ENTROPY_RESP, worker_entropy_recv);
		kore_msg_register(KORE_MSG_CERTIFICATE, worker_keymgr_response);

		if (worker->restarted) {
			kore_msg_send(KORE_WORKER_KEYMGR,
			    KORE_MSG_CERTIFICATE_REQ, NULL, 0);
		}
#if defined(KORE_USE_ACME)
		kore_msg_register(KORE_ACME_CHALLENGE_SET_CERT,
		    worker_keymgr_response);
		kore_msg_register(KORE_ACME_CHALLENGE_CLEAR_CERT,
		    worker_keymgr_response);
#endif
	}

	kore_msg_register(KORE_MSG_ACCEPT_AVAILABLE, worker_accept_avail);

	if (nlisteners == 0)
		worker_no_lock = 1;

	worker_runtime_configure();

	kore_module_onload();
	kore_domain_callback(worker_domain_check);

	kore_worker_started();
	worker->restarted = 0;

	sigcall = worker_runtime_signal();

	for (;;) {
		now = kore_time_ms();

		if (kore_keymgr_active &&
		    (now - last_seed) > KORE_RESEED_TIME) {
			kore_msg_send(KORE_WORKER_KEYMGR,
			    KORE_MSG_ENTROPY_REQ, NULL, 0);
			last_seed = now;
		}

		if (!worker->has_lock && accept_avail) {
			if (worker_acceptlock_obtain()) {
				accept_avail = 0;
				if (had_lock == 0) {
					kore_platform_enable_accept();
					had_lock = 1;
				}
			}
		}

		netwait = kore_timer_next_run(now);

		if (netwait == KORE_WAIT_INFINITE) {
			if (sig_recv != 0)
				netwait = 10;
#if !defined(KORE_NO_HTTP)
			if (http_request_count > 0)
				netwait = 100;
#endif
		}

#if defined(KORE_USE_PYTHON)
		if (kore_python_coro_pending())
			netwait = 0;
#endif

		kore_platform_event_wait(netwait);
		now = kore_time_ms();

		if (worker->has_lock)
			worker_acceptlock_release();

		if (!worker->has_lock) {
			if (had_lock == 1) {
				had_lock = 0;
				kore_platform_disable_accept();
			}
		}

		sig = sig_recv;
		if (sig != 0) {
			switch (sig) {
			case SIGHUP:
				kore_module_reload(1);
				break;
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;
			case SIGCHLD:
#if defined(KORE_USE_PYTHON)
				kore_python_proc_reap();
#endif
				break;
			default:
				break;
			}

			if (sigcall != NULL)
				kore_runtime_signal(sigcall, sig);

			if (sig == sig_recv)
				sig_recv = 0;
		}

		if (quit)
			break;

		kore_timer_run(now);
#if defined(KORE_USE_CURL)
		kore_curl_run_scheduled();
		kore_curl_do_timeout();
#endif
#if !defined(KORE_NO_HTTP)
		http_process();
#endif
#if defined(KORE_USE_PYTHON)
		kore_python_coro_run();
#endif
		if (next_timeo <= now) {
			kore_connection_check_timeout(now);
			next_timeo = now + 500;
		}

		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	}

	worker_runtime_teardown();
	kore_server_cleanup();

	kore_platform_event_cleanup();
	kore_connection_cleanup();
	kore_domain_cleanup();
	kore_tls_cleanup();
	kore_module_cleanup();
#if !defined(KORE_NO_HTTP)
	http_cleanup();
#endif
	net_cleanup();

#if defined(KORE_USE_PYTHON)
	kore_python_cleanup();
#endif

#if defined(KORE_USE_PGSQL)
	kore_pgsql_sys_cleanup();
#endif

	kore_mem_cleanup();
	exit(0);
}

void
kore_worker_reap(void)
{
	pid_t			pid;
	int			status;

	for (;;) {
		pid = waitpid(-worker_pgrp, &status, WNOHANG);

		if (pid == -1) {
			if (errno != ECHILD && errno != EINTR) {
				kore_log(LOG_ERR,
				    "%s: waitpid(): %s", __func__, errno_s);
			}
			break;
		}

		if (pid == 0)
			break;

		worker_reaper(pid, status);
	}
}

void
kore_worker_make_busy(void)
{
	if (worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1)
		return;

	if (worker->has_lock) {
		worker_unlock();
		worker->has_lock = 0;
		kore_msg_send(KORE_MSG_WORKER_ALL,
		    KORE_MSG_ACCEPT_AVAILABLE, NULL, 0);
	}
}

int
kore_worker_keymgr_response_verify(struct kore_msg *msg, const void *data,
    struct kore_domain **out)
{
	struct kore_server		*srv;
	struct kore_domain		*dom;
	const struct kore_x509_msg	*req;

	if (msg->length < sizeof(*req)) {
		kore_log(LOG_WARNING,
		    "short keymgr message (%zu)", msg->length);
		return (KORE_RESULT_ERROR);
	}

	req = (const struct kore_x509_msg *)data;
	if (msg->length != (sizeof(*req) + req->data_len)) {
		kore_log(LOG_WARNING,
		    "invalid keymgr payload (%zu)", msg->length);
		return (KORE_RESULT_ERROR);
	}

	if (req->domain[KORE_DOMAINNAME_LEN] != '\0') {
		kore_log(LOG_WARNING, "domain not NUL-terminated");
		return (KORE_RESULT_ERROR);

	}

	if (out == NULL)
		return (KORE_RESULT_OK);

	dom = NULL;

	LIST_FOREACH(srv, &kore_servers, list) {
		dom = NULL;

		if (srv->tls == 0)
			continue;

		TAILQ_FOREACH(dom, &srv->domains, list) {
			if (!strcmp(dom->domain, req->domain))
				break;
		}

		if (dom != NULL)
			break;
	}

	if (dom == NULL) {
		kore_log(LOG_WARNING,
		    "got keymgr response for domain that does not exist");
		return (KORE_RESULT_ERROR);
	}

	*out = dom;

	return (KORE_RESULT_OK);
}

void
kore_worker_started(void)
{
	const char	*chroot;

	if (worker->ps->skip_chroot)
		chroot = "root";
	else
		chroot = "chroot";

	if (!kore_quiet) {
		kore_log(LOG_NOTICE,
		    "started (#%d %s=%s%s%s)",
		    getpid(), chroot, worker->ps->root,
		    worker->ps->skip_runas ? "" : " user=",
		    worker->ps->skip_runas ? "" : worker->ps->runas);
	}

	worker->ready = 1;
}

static void
worker_runtime_configure(void)
{
	struct kore_runtime_call	*rcall;

	rcall = NULL;

#if defined(KORE_USE_PYTHON)
	rcall = kore_runtime_getcall(KORE_PYTHON_WORKER_START_HOOK);
#endif

	if (rcall == NULL)
		rcall = kore_runtime_getcall("kore_worker_configure");

	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}
}

static struct kore_runtime_call *
worker_runtime_signal(void)
{
	struct kore_runtime_call	*rcall;

	rcall = NULL;

#if defined(KORE_USE_PYTHON)
	rcall = kore_runtime_getcall(KORE_PYTHON_SIGNAL_HOOK);
#endif

	if (rcall == NULL)
		rcall = kore_runtime_getcall("kore_worker_signal");

	return (rcall);
}

static void
worker_runtime_teardown(void)
{
	struct kore_runtime_call	*rcall;

	rcall = NULL;

#if defined(KORE_USE_PYTHON)
	rcall = kore_runtime_getcall(KORE_PYTHON_WORKER_STOP_HOOK);
#endif

	if (rcall == NULL)
		rcall = kore_runtime_getcall("kore_worker_teardown");

	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}
}

static void
worker_domain_check(struct kore_domain *dom)
{
	struct stat	st;

	if (dom->cafile != NULL) {
		if (stat(dom->cafile, &st) == -1)
			fatalx("'%s': %s", dom->cafile, errno_s);
		if (access(dom->cafile, R_OK) == -1)
			fatalx("'%s': not readable", dom->cafile);
	}
}

static void
worker_reaper(pid_t pid, int status)
{
	u_int16_t		idx;
	struct kore_worker	*kw;
	const char		*func;

#if defined(__linux__)
	if (kore_seccomp_trace(pid, status))
		return;
#endif

	for (idx = 0; idx < worker_count; idx++) {
		kw = WORKER(idx);
		if (kw->pid != pid)
			continue;

		kw->msg[0]->evt.flags |= KORE_EVENT_READ;
		net_recv_flush(kw->msg[0]);

		if (!kore_quiet) {
			kore_log(LOG_NOTICE,
			    "worker %s (%d) exited with status %d",
			    kore_worker_name(kw->id), pid, status);
		}

		kw->running = 0;

		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			kw->pid = 0;
			break;
		}

		func = "none";
#if !defined(KORE_NO_HTTP)
		if (kw->active_route != NULL)
			func = kw->active_route->func;
#endif
		kore_log(LOG_NOTICE,
		    "worker %d (pid: %d) (hdlr: %s) gone",
		    kw->id, kw->pid, func);

#if defined(__linux__)
		if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
			kore_log(LOG_NOTICE,
			    "worker %d died from sandbox violation", kw->id);
		}
#endif

		if (kw->id == KORE_WORKER_KEYMGR ||
		    kw->id == KORE_WORKER_ACME) {
			kore_log(LOG_CRIT,
			    "keymgr or acme process gone, stopping");
			kw->pid = 0;
			kore_quit = KORE_QUIT_FATAL;
			break;
		}

		if (kw->pid == accept_lock->current &&
		    worker_no_lock == 0)
			worker_unlock();

#if !defined(KORE_NO_HTTP)
		if (kw->active_route != NULL) {
			kw->active_route->errors++;
			kore_log(LOG_NOTICE,
			    "hdlr %s has caused %d error(s)",
			    kw->active_route->func,
			    kw->active_route->errors);
		}
#endif

		if (worker_policy == KORE_WORKER_POLICY_TERMINATE) {
			kw->pid = 0;
			kore_log(LOG_NOTICE,
			    "worker policy is 'terminate', stopping");
			kore_quit = KORE_QUIT_FATAL;
			break;
		}

		if (kore_quit == KORE_QUIT_NONE) {
			kore_log(LOG_NOTICE, "restarting worker %d", kw->id);
			kw->restarted = 1;
			kore_msg_parent_remove(kw);

			if (!kore_worker_spawn(idx, kw->id, kw->cpu)) {
				kore_quit = KORE_QUIT_FATAL;
				kore_log(LOG_ERR, "failed to restart worker");
			} else {
				kore_msg_parent_add(kw);
			}

			break;
		}
	}
}

static inline void
worker_acceptlock_release(void)
{
	if (worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1)
		return;

	if (worker->has_lock != 1)
		return;

	if (worker_active_connections < worker_max_connections) {
#if !defined(KORE_NO_HTTP)
		if (http_request_count < http_request_limit)
			return;
#else
		return;
#endif
	}

#if defined(WORKER_DEBUG)
	kore_log(LOG_DEBUG, "worker busy, releasing lock");
#endif

	worker_unlock();
	worker->has_lock = 0;

	kore_msg_send(KORE_MSG_WORKER_ALL, KORE_MSG_ACCEPT_AVAILABLE, NULL, 0);
}

static inline int
worker_acceptlock_obtain(void)
{
	int		r;

	if (worker->has_lock == 1)
		return (1);

	if (worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1) {
		worker->has_lock = 1;
		return (1);
	}

	if (worker_active_connections >= worker_max_connections)
		return (0);

#if !defined(KORE_NO_HTTP)
	if (http_request_count >= http_request_limit)
		return (0);
#endif

	r = 0;
	if (worker_trylock()) {
		r = 1;
		worker->has_lock = 1;
#if defined(WORKER_DEBUG)
		kore_log(LOG_DEBUG, "got lock");
#endif
	}

	return (r);
}

static int
worker_trylock(void)
{
	if (!__sync_bool_compare_and_swap(&(accept_lock->lock), 0, 1))
		return (0);

	accept_lock->current = worker->pid;

	return (1);
}

static void
worker_unlock(void)
{
	accept_lock->current = 0;
	if (!__sync_bool_compare_and_swap(&(accept_lock->lock), 1, 0))
		kore_log(LOG_NOTICE, "worker_unlock(): wasn't locked");
}

static void
worker_accept_avail(struct kore_msg *msg, const void *data)
{
	accept_avail = 1;
}

static void
worker_entropy_recv(struct kore_msg *msg, const void *data)
{
	if (msg->length != 1024) {
		kore_log(LOG_WARNING,
		    "invalid entropy response (got:%zu - wanted:1024)",
		    msg->length);
	}

	kore_tls_seed(data, msg->length);
}

static void
worker_keymgr_response(struct kore_msg *msg, const void *data)
{
	struct kore_domain		*dom;
	const struct kore_x509_msg	*req;

	if (!kore_worker_keymgr_response_verify(msg, data, &dom))
		return;

	req = (const struct kore_x509_msg *)data;

	switch (msg->id) {
	case KORE_MSG_CERTIFICATE:
		kore_tls_domain_setup(dom, KORE_PEM_CERT_CHAIN,
		    req->data, req->data_len);
		break;
	case KORE_MSG_CRL:
		kore_tls_domain_crl(dom, req->data, req->data_len);
		break;
#if defined(KORE_USE_ACME)
	case KORE_ACME_CHALLENGE_SET_CERT:
		if (dom->tls_ctx == NULL) {
			kore_tls_domain_setup(dom, KORE_DER_CERT_DATA,
			    req->data, req->data_len);
		}

		kore_free(dom->acme_cert);
		dom->acme_cert_len = req->data_len;
		dom->acme_cert = kore_calloc(1, req->data_len);
		memcpy(dom->acme_cert, req->data, req->data_len);

		kore_log(LOG_NOTICE, "[%s] tls-alpn-01 challenge active",
		    dom->domain);
		dom->acme_challenge = 1;
		break;
	case KORE_ACME_CHALLENGE_CLEAR_CERT:
		dom->acme_cert_len = 0;
		dom->acme_challenge = 0;

		kore_free(dom->acme_cert);
		dom->acme_cert = NULL;

		kore_log(LOG_NOTICE, "[%s] tls-alpn-01 challenge disabled",
		    dom->domain);
		break;
#endif
	default:
		kore_log(LOG_WARNING, "unknown keymgr request %u", msg->id);
		break;
	}
}
