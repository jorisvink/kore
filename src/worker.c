/*
 * Copyright (c) 2013-2018 Joris Vink <joris@coders.se>
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
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>

#if !defined(KORE_NO_TLS)
#include <openssl/rand.h>
#endif

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>

#include "kore.h"

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

#if !defined(WAIT_ANY)
#define WAIT_ANY		(-1)
#endif

#define WORKER_LOCK_TIMEOUT	500

#if !defined(KORE_NO_TLS)
#define WORKER_SOLO_COUNT	2
#else
#define WORKER_SOLO_COUNT	1
#endif

#define WORKER(id)						\
	(struct kore_worker *)((u_int8_t *)kore_workers +	\
	    (sizeof(struct kore_worker) * id))

struct wlock {
	volatile int		lock;
	pid_t			current;
};

static int	worker_trylock(void);
static void	worker_unlock(void);

static inline int	worker_acceptlock_obtain(u_int64_t);
static inline int	worker_acceptlock_release(u_int64_t);

#if !defined(KORE_NO_TLS)
static void	worker_entropy_recv(struct kore_msg *, const void *);
static void	worker_certificate_recv(struct kore_msg *, const void *);
#endif

static struct kore_worker		*kore_workers;
static int				worker_no_lock;
static int				shm_accept_key;
static struct wlock			*accept_lock;

extern volatile sig_atomic_t	sig_recv;
struct kore_worker		*worker = NULL;
u_int8_t			worker_set_affinity = 1;
u_int32_t			worker_accept_threshold = 0;
u_int32_t			worker_rlimit_nofiles = 1024;
u_int32_t			worker_max_connections = 250;
u_int32_t			worker_active_connections = 0;

void
kore_worker_init(void)
{
	size_t			len;
	u_int16_t		i, cpu;

	worker_no_lock = 0;

	if (worker_count == 0)
		worker_count = 1;

#if !defined(KORE_NO_TLS)
	/* account for the key manager. */
	worker_count += 1;
#endif

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

	kore_debug("kore_worker_init(): system has %d cpu's", cpu_count);
	kore_debug("kore_worker_init(): starting %d workers", worker_count);

	if (worker_count > cpu_count) {
		kore_debug("kore_worker_init(): more workers than cpu's");
	}

	cpu = 0;
	for (i = 0; i < worker_count; i++) {
		kore_worker_spawn(i, cpu++);
		if (cpu == cpu_count)
			cpu = 0;
	}
}

void
kore_worker_spawn(u_int16_t id, u_int16_t cpu)
{
	struct kore_worker	*kw;

	kw = WORKER(id);
	kw->id = id;
	kw->cpu = cpu;
	kw->has_lock = 0;
	kw->active_hdlr = NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, kw->pipe) == -1)
		fatal("socketpair(): %s", errno_s);

	if (!kore_connection_nonblock(kw->pipe[0], 0) ||
	    !kore_connection_nonblock(kw->pipe[1], 0))
		fatal("could not set pipe fds to nonblocking: %s", errno_s);

	kw->pid = fork();
	if (kw->pid == -1)
		fatal("could not spawn worker child: %s", errno_s);

	if (kw->pid == 0) {
		kw->pid = getpid();
		kore_worker_entry(kw);
		/* NOTREACHED */
	}
}

struct kore_worker *
kore_worker_data(u_int8_t id)
{
	if (id >= worker_count)
		fatal("id %u too large for worker count", id);

	return (WORKER(id));
}

void
kore_worker_shutdown(void)
{
	struct kore_worker	*kw;
	u_int16_t		id, done;

	kore_log(LOG_NOTICE, "waiting for workers to drain and shutdown");
	for (;;) {
		done = 0;
		for (id = 0; id < worker_count; id++) {
			kw = WORKER(id);
			if (kw->pid != 0)
				kore_worker_wait(1);
			else
				done++;
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
	u_int16_t		id;
	struct kore_worker	*kw;

	for (id = 0; id < worker_count; id++) {
		kw = WORKER(id);
		if (kill(kw->pid, sig) == -1) {
			kore_debug("kill(%d, %d): %s", kw->pid, sig, errno_s);
		}
	}
}

void
kore_worker_privdrop(const char *runas, const char *root)
{
	rlim_t			fd;
	struct rlimit		rl;
	struct passwd		*pw = NULL;

	if (root == NULL)
		fatalx("no root directory for kore_worker_privdrop");

	/* Must happen before chroot. */
	if (skip_runas == 0) {
		if (runas == NULL)
			fatalx("no runas user given and -r not specified");
		pw = getpwnam(runas);
		if (pw == NULL) {
			fatalx("cannot getpwnam(\"%s\") for user: %s",
			    runas, errno_s);
		}
	}

	if (skip_chroot == 0) {
		if (chroot(root) == -1) {
			fatalx("cannot chroot(\"%s\"): %s",
			    root, errno_s);
		}

		if (chdir("/") == -1)
			fatalx("cannot chdir(\"/\"): %s", errno_s);
	} else {
		if (chdir(root) == -1)
			fatalx("cannot chdir(\"%s\"): %s", root, errno_s);
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
		kore_log(LOG_ERR, "setrlimit(RLIMIT_NOFILE, %d): %s",
		    worker_rlimit_nofiles, errno_s);
	}

	if (skip_runas == 0) {
		if (setgroups(1, &pw->pw_gid) ||
#if defined(__MACH__) || defined(NetBSD)
		    setgid(pw->pw_gid) || setegid(pw->pw_gid) ||
		    setuid(pw->pw_uid) || seteuid(pw->pw_uid))
#else
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
#endif
			fatalx("cannot drop privileges");
	}

#if defined(KORE_USE_PLATFORM_PLEDGE)
	kore_platform_pledge();
#endif

}

void
kore_worker_entry(struct kore_worker *kw)
{
	struct kore_runtime_call	*rcall;
	char				buf[16];
	int				quit, had_lock, r;
	u_int64_t			timerwait, netwait;
	u_int64_t			now, next_prune, next_lock;
#if !defined(KORE_NO_TLS)
	u_int64_t			last_seed;
#endif

	worker = kw;

	(void)snprintf(buf, sizeof(buf), "kore [wrk %d]", kw->id);
#if !defined(KORE_NO_TLS)
	if (kw->id == KORE_WORKER_KEYMGR)
		(void)snprintf(buf, sizeof(buf), "kore [keymgr]");
#endif
	kore_platform_proctitle(buf);

	if (worker_set_affinity == 1)
		kore_platform_worker_setcpu(kw);

	kore_pid = kw->pid;

	kore_signal_setup();

#if !defined(KORE_NO_TLS)
	if (kw->id == KORE_WORKER_KEYMGR) {
		kore_keymgr_run();
		exit(0);
	}
#endif
	net_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_worker_init();

	kore_worker_privdrop(kore_runas_user, kore_root_path);

#if !defined(KORE_NO_HTTP)
	http_init();
	kore_filemap_resolve_paths();
	kore_accesslog_worker_init();
#endif
	kore_timer_init();
	kore_fileref_init();
	kore_domain_load_crl();
	kore_domain_keymgr_init();

	quit = 0;
	had_lock = 0;
	next_lock = 0;
	next_prune = 0;
	worker_active_connections = 0;

#if defined(KORE_USE_PGSQL)
	kore_pgsql_sys_init();
#endif

#if defined(KORE_USE_TASKS)
	kore_task_init();
#endif

#if !defined(KORE_NO_TLS)
	last_seed = 0;
	kore_msg_register(KORE_MSG_ENTROPY_RESP, worker_entropy_recv);
	kore_msg_register(KORE_MSG_CERTIFICATE, worker_certificate_recv);
	if (worker->restarted) {
		kore_msg_send(KORE_WORKER_KEYMGR,
		    KORE_MSG_CERTIFICATE_REQ, NULL, 0);
	}
#endif

	if (nlisteners == 0)
		worker_no_lock = 1;

	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);

	rcall = kore_runtime_getcall("kore_worker_configure");
	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}

	kore_module_onload();
	worker->restarted = 0;

	for (;;) {
		if (sig_recv != 0) {
			switch (sig_recv) {
			case SIGHUP:
				kore_module_reload(1);
				break;
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;
			default:
				break;
			}

			sig_recv = 0;
		}

		netwait = 100;
		now = kore_time_ms();

#if !defined(KORE_NO_TLS)
		if ((now - last_seed) > KORE_RESEED_TIME) {
			kore_msg_send(KORE_WORKER_KEYMGR,
			    KORE_MSG_ENTROPY_REQ, NULL, 0);
			last_seed = now;
		}
#endif

		if (!worker->has_lock && next_lock <= now) {
			if (worker_acceptlock_obtain(now)) {
				if (had_lock == 0) {
					kore_platform_enable_accept();
					had_lock = 1;
				}
			} else {
				next_lock = now + WORKER_LOCK_TIMEOUT / 2;
			}
		}

		if (!worker->has_lock) {
			if (worker_active_connections > 0) {
				if (next_lock > now)
					netwait = next_lock - now;
			} else {
				netwait = 10;
			}
		}

		timerwait = kore_timer_run(now);
		if (timerwait < netwait)
			netwait = timerwait;

		r = kore_platform_event_wait(netwait);
		if (worker->has_lock && r > 0) {
			if (netwait > 10)
				now = kore_time_ms();
			if (worker_acceptlock_release(now))
				next_lock = now + WORKER_LOCK_TIMEOUT;
		}

		if (!worker->has_lock) {
			if (had_lock == 1) {
				had_lock = 0;
				kore_platform_disable_accept();
			}
		}

#if !defined(KORE_NO_HTTP)
		http_process();
#endif
#if defined(KORE_USE_PYTHON)
		kore_python_coro_run();
#endif

		if (next_prune <= now) {
			kore_connection_check_timeout(now);
			kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
			next_prune = now + 500;
		}

		if (quit)
			break;
	}

	kore_platform_event_cleanup();
	kore_connection_cleanup();
	kore_domain_cleanup();
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

	kore_debug("worker %d shutting down", kw->id);

	kore_mem_cleanup();
	exit(0);
}

void
kore_worker_wait(int final)
{
	u_int16_t		id;
	pid_t			pid;
	struct kore_worker	*kw;
	const char		*func;
	int			status;

	if (final)
		pid = waitpid(WAIT_ANY, &status, 0);
	else
		pid = waitpid(WAIT_ANY, &status, WNOHANG);

	if (pid == -1) {
		kore_debug("waitpid(): %s", errno_s);
		return;
	}

	if (pid == 0)
		return;

	for (id = 0; id < worker_count; id++) {
		kw = WORKER(id);
		if (kw->pid != pid)
			continue;

		kore_log(LOG_NOTICE, "worker %d (%d)-> status %d",
		    kw->id, pid, status);

		if (final) {
			kw->pid = 0;
			break;
		}

		if (WEXITSTATUS(status) || WTERMSIG(status) ||
		    WCOREDUMP(status)) {
			func = "none";
#if !defined(KORE_NO_HTTP)
			if (kw->active_hdlr != NULL)
				func = kw->active_hdlr->func;
#endif
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) (hdlr: %s) gone",
			    kw->id, kw->pid, func);

#if !defined(KORE_NO_TLS)
			if (id == KORE_WORKER_KEYMGR) {
				kore_log(LOG_CRIT, "keymgr gone, stopping");
				kw->pid = 0;
				if (raise(SIGTERM) != 0) {
					kore_log(LOG_WARNING,
					    "failed to raise SIGTERM signal");
				}
				break;
			}
#endif

			if (kw->pid == accept_lock->current &&
			    worker_no_lock == 0)
				worker_unlock();

#if !defined(KORE_NO_HTTP)
			if (kw->active_hdlr != NULL) {
				kw->active_hdlr->errors++;
				kore_log(LOG_NOTICE,
				    "hdlr %s has caused %d error(s)",
				    kw->active_hdlr->func,
				    kw->active_hdlr->errors);
			}
#endif

			kore_log(LOG_NOTICE, "restarting worker %d", kw->id);
			kw->restarted = 1;
			kore_msg_parent_remove(kw);
			kore_worker_spawn(kw->id, kw->cpu);
			kore_msg_parent_add(kw);
		} else {
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) signaled us (%d)",
			    kw->id, kw->pid, status);
		}

		break;
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
	}
}

static inline int
worker_acceptlock_release(u_int64_t now)
{
	if (worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1)
		return (0);

	if (worker->has_lock != 1)
		return (0);

	if (worker_active_connections < worker_max_connections) {
#if !defined(KORE_NO_HTTP)
		if (http_request_count < http_request_limit)
			return (0);
#else
		return (0);
#endif
	}

#if defined(WORKER_DEBUG)
	kore_log(LOG_DEBUG, "worker busy, releasing lock");
	kore_log(LOG_DEBUG, "had lock for %lu ms", now - worker->time_locked);
#endif

	worker_unlock();
	worker->has_lock = 0;

	return (1);
}

static inline int
worker_acceptlock_obtain(u_int64_t now)
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
		worker->time_locked = now;
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
		kore_log(LOG_NOTICE, "worker_unlock(): wasnt locked");
}

#if !defined(KORE_NO_TLS)
static void
worker_entropy_recv(struct kore_msg *msg, const void *data)
{
	if (msg->length != 1024) {
		kore_log(LOG_WARNING,
		    "invalid entropy response (got:%zu - wanted:1024)",
		    msg->length);
	}

	RAND_poll();
	RAND_seed(data, msg->length);
}

static void
worker_certificate_recv(struct kore_msg *msg, const void *data)
{
	struct kore_domain		*dom;
	const struct kore_x509_msg	*req;

	if (msg->length < sizeof(*req)) {
		kore_log(LOG_WARNING,
		    "short KORE_MSG_CERTIFICATE message (%zu)", msg->length);
		return;
	}

	req = (const struct kore_x509_msg *)data;
	if (msg->length != (sizeof(*req) + req->data_len)) {
		kore_log(LOG_WARNING,
		    "invalid KORE_MSG_CERTIFICATE payload (%zu)", msg->length);
		return;
	}

	if (req->domain_len > KORE_DOMAINNAME_LEN) {
		kore_log(LOG_WARNING,
		    "invalid KORE_MSG_CERTIFICATE domain (%u)",
		    req->domain_len);
		return;
	}

	dom = NULL;
	TAILQ_FOREACH(dom, &domains, list) {
		if (!strncmp(dom->domain, req->domain, req->domain_len))
			break;
	}

	if (dom == NULL) {
		kore_log(LOG_WARNING,
		    "got KORE_MSG_CERTIFICATE for domain that does not exist");
		return;
	}

	/* reinitialize the domain TLS context. */
	kore_domain_tlsinit(dom, req->data, req->data_len);
}
#endif
