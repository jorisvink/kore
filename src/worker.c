/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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

#if defined(WORKER_DEBUG)
#define worker_debug(fmt, ...)		printf(fmt, ##__VA_ARGS__)
#else
#define worker_debug(fmt, ...)
#endif

#if !defined(WAIT_ANY)
#define WAIT_ANY		(-1)
#endif

#define WORKER_LOCK_TIMEOUT	500

#define WORKER(id)						\
	(struct kore_worker *)((u_int8_t *)kore_workers +	\
	    (sizeof(struct kore_worker) * id))

struct wlock {
	volatile int		lock;
	pid_t			current;
};

static int	worker_trylock(void);
static void	worker_unlock(void);

static inline int	kore_worker_acceptlock_obtain(void);
static inline void	kore_worker_acceptlock_release(void);

static struct kore_worker		*kore_workers;
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
kore_worker_privdrop(void)
{
	rlim_t			fd;
	struct rlimit		rl;
	struct passwd		*pw = NULL;

	/* Must happen before chroot. */
	if (skip_runas == 0) {
		pw = getpwnam(runas_user);
		if (pw == NULL) {
			fatal("cannot getpwnam(\"%s\") runas user: %s",
			    runas_user, errno_s);
		}
	}

	if (skip_chroot == 0) {
		if (chroot(chroot_path) == -1) {
			fatal("cannot chroot(\"%s\"): %s",
			    chroot_path, errno_s);
		}

		if (chdir("/") == -1)
			fatal("cannot chdir(\"/\"): %s", errno_s);
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
			fatal("cannot drop privileges");
	}
}

void
kore_worker_entry(struct kore_worker *kw)
{
	char			buf[16];
	int			quit, had_lock, r;
	u_int64_t		now, idle_check, next_lock, netwait;
#if defined(KORE_SINGLE_BINARY)
	void			(*onload)(void);
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

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);
	signal(SIGTERM, kore_signal);
	signal(SIGPIPE, SIG_IGN);

	if (foreground)
		signal(SIGINT, kore_signal);
	else
		signal(SIGINT, SIG_IGN);

#if !defined(KORE_NO_TLS)
	if (kw->id == KORE_WORKER_KEYMGR) {
		kore_keymgr_run();
		exit(0);
	}
#endif

	kore_worker_privdrop();

	net_init();
#if !defined(KORE_NO_HTTP)
	http_init();
	kore_accesslog_worker_init();
#endif
	kore_timer_init();
	kore_connection_init();
	kore_domain_load_crl();
	kore_domain_keymgr_init();

	quit = 0;
	had_lock = 0;
	next_lock = 0;
	idle_check = 0;
	worker_active_connections = 0;

	kore_platform_event_init();
	kore_msg_worker_init();

#if defined(KORE_USE_PGSQL)
	kore_pgsql_init();
#endif

#if defined(KORE_USE_TASKS)
	kore_task_init();
#endif

	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);

#if defined(KORE_SINGLE_BINARY)
	*(void **)&(onload) = kore_module_getsym("kore_onload");
	if (onload != NULL)
		onload();
#else
	kore_module_onload();
#endif

	for (;;) {
		if (sig_recv != 0) {
			switch (sig_recv) {
			case SIGHUP:
#if !defined(KORE_SINGLE_BINARY)
				kore_module_reload(1);
#endif
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

		now = kore_time_ms();
		netwait = kore_timer_run(now);
		if (netwait > 100)
			netwait = 100;

		if (now > next_lock) {
			if (kore_worker_acceptlock_obtain()) {
				if (had_lock == 0) {
					kore_platform_enable_accept();
					had_lock = 1;
				}
			}
		}

		if (!worker->has_lock) {
			if (had_lock == 1) {
				had_lock = 0;
				kore_platform_disable_accept();
			}
		}

		r = kore_platform_event_wait(netwait);
		if (worker->has_lock && r > 0) {
			kore_worker_acceptlock_release();
			next_lock = now + WORKER_LOCK_TIMEOUT;
		}

#if !defined(KORE_NO_HTTP)
		http_process();
#endif

		if ((now - idle_check) >= 10000) {
			idle_check = now;
			kore_connection_check_timeout();
		}

		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);

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

	kore_debug("worker %d shutting down", kw->id);
	exit(0);
}

void
kore_worker_wait(int final)
{
	u_int16_t		id;
	pid_t			pid;
	struct kore_worker	*kw;
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
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) (hdlr: %s) gone",
			    kw->id, kw->pid,
			    (kw->active_hdlr != NULL) ? kw->active_hdlr->func :
			    "none");

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

			if (kw->pid == accept_lock->current)
				worker_unlock();

			if (kw->active_hdlr != NULL) {
				kw->active_hdlr->errors++;
				kore_log(LOG_NOTICE,
				    "hdlr %s has caused %d error(s)",
				    kw->active_hdlr->func,
				    kw->active_hdlr->errors);
			}

			kore_log(LOG_NOTICE, "restarting worker %d", kw->id);
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

static inline void
kore_worker_acceptlock_release(void)
{
	if (worker_count == 1)
		return;

	if (worker->has_lock != 1)
		return;

	worker_unlock();
	worker->has_lock = 0;
}

static inline int
kore_worker_acceptlock_obtain(void)
{
	int		r;

	if (worker->has_lock == 1)
		return (1);

	if (worker_count == 1) {
		worker->has_lock = 1;
		return (1);
	}

	if (worker_active_connections >= worker_max_connections)
		return (0);

	r = 0;
	if (worker_trylock()) {
		r = 1;
		worker->has_lock = 1;
	}

	return (r);
}

static int
worker_trylock(void)
{
	if (!__sync_bool_compare_and_swap(&(accept_lock->lock), 0, 1))
		return (0);

	worker_debug("wrk#%d grabbed lock (%d/%d)\n", worker->id,
	    worker_active_connections, worker_max_connections);
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
