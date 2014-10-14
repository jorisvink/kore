/*
 * Copyright (c) 2013-2014 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <grp.h>
#include <pwd.h>
#include <signal.h>

#include "kore.h"
#include "http.h"

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

#define KORE_SHM_KEY		15000
#define WORKER(id)						\
	(struct kore_worker *)((u_int8_t *)kore_workers +	\
	    (sizeof(struct kore_worker) * id))

struct wlock {
	volatile int		lock;
	pid_t			current;
};

static int	worker_trylock(void);
static void	worker_unlock(void);

static int	kore_worker_acceptlock_obtain(void);

static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		worker_clients;
static struct kore_worker		*kore_workers;
static int				shm_accept_key;
static struct wlock			*accept_lock;

extern volatile sig_atomic_t	sig_recv;
struct kore_worker		*worker = NULL;
u_int32_t			worker_rlimit_nofiles = 1024;
u_int32_t			worker_max_connections = 250;
u_int32_t			worker_active_connections = 0;

void
kore_worker_init(void)
{
	size_t			len;
	key_t			key;
	u_int16_t		i, cpu;

	if (worker_count == 0)
		worker_count = 1;

	len = sizeof(*accept_lock) +
	    (sizeof(struct kore_worker) * worker_count);

	shm_accept_key = -1;
	for (key = KORE_SHM_KEY; shm_accept_key == -1; key++) {
		shm_accept_key = shmget(key, len, IPC_CREAT | IPC_EXCL | 0700);
		if (shm_accept_key == -1 && errno != EEXIST)
			fatal("kore_worker_init(): shmget() %s", errno_s);
	}

	if ((accept_lock = shmat(shm_accept_key, NULL, 0)) == NULL)
		fatal("kore_worker_init(): shmat() %s", errno_s);

	accept_lock->lock = 0;
	accept_lock->current = 0;

	kore_workers = (struct kore_worker *)((u_int8_t *)accept_lock +
	    sizeof(*accept_lock));
	memset(kore_workers, 0, sizeof(struct kore_worker) * worker_count);

	kore_debug("kore_worker_init(): system has %d cpu's", cpu_count);
	kore_debug("kore_worker_init(): starting %d workers", worker_count);
	if (worker_count > cpu_count)
		kore_debug("kore_worker_init(): more workers then cpu's");

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

	kw->pid = fork();
	if (kw->pid == -1)
		fatal("could not spawn worker child: %s", errno_s);

	if (kw->pid == 0) {
		kw->pid = getpid();
		kore_worker_entry(kw);
		/* NOTREACHED */
	}
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
		if (kill(kw->pid, sig) == -1)
			kore_debug("kill(%d, %d): %s", kw->pid, sig, errno_s);
	}
}

void
kore_worker_entry(struct kore_worker *kw)
{
	struct rlimit		rl;
	char			buf[16];
	struct connection	*c, *cnext;
	int			quit, had_lock;
	u_int64_t		now, idle_check, timer;

	worker = kw;

	if (skip_chroot == 0) {
		if (chroot(chroot_path) == -1)
			fatal("cannot chroot(): %s", errno_s);
		if (chdir("/") == -1)
			fatal("cannot chdir(): %s", errno_s);
	}

	if (getuid() != pw->pw_uid) {
		if (setgroups(1, &pw->pw_gid) ||
#ifdef __MACH__
		    setgid(pw->pw_gid) || setegid(pw->pw_gid) ||
		    setuid(pw->pw_uid) || seteuid(pw->pw_uid))
#else
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
#endif
			fatal("unable to drop privileges");
	}

	rl.rlim_cur = worker_rlimit_nofiles;
	rl.rlim_max = worker_rlimit_nofiles;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		kore_log(LOG_ERR, "setrlimit(RLIMIT_NOFILE, %d): %s",
		    worker_rlimit_nofiles, errno_s);
	}

	(void)snprintf(buf, sizeof(buf), "kore [wrk %d]", kw->id);
	kore_platform_proctitle(buf);
	kore_platform_worker_setcpu(kw);

	kore_pid = kw->pid;

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);
	signal(SIGPIPE, SIG_IGN);

	if (foreground)
		signal(SIGINT, kore_signal);
	else
		signal(SIGINT, SIG_IGN);

	net_init();
	http_init();
	kore_connection_init();
	TAILQ_INIT(&disconnected);
	TAILQ_INIT(&worker_clients);

	quit = 0;
	had_lock = 0;
	idle_check = 0;
	kore_platform_event_init();
	kore_accesslog_worker_init();

#if defined(KORE_USE_PGSQL)
	kore_pgsql_init();
#endif

#if defined(KORE_USE_TASKS)
	kore_task_init();
#endif

	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);
	kore_module_onload();

	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP)
				kore_module_reload(1);
			else if (sig_recv == SIGQUIT || sig_recv == SIGINT)
				quit = 1;
			sig_recv = 0;
		}

		if (kore_worker_acceptlock_obtain()) {
			if (had_lock == 0)
				kore_platform_enable_accept();

			timer = 100;
			had_lock = 1;
		} else {
			if (had_lock == 1) {
				had_lock = 0;
				kore_platform_disable_accept();
			}

			timer = 1;
		}

		kore_platform_event_wait(timer);

		if (worker->has_lock)
			kore_worker_acceptlock_release();

		http_process();

		now = kore_time_ms();
		if ((now - idle_check) >= 1000) {
			idle_check = now;
			TAILQ_FOREACH(c, &worker_clients, list) {
				if (c->proto == CONN_PROTO_SPDY &&
				    c->idle_timer.length == 0 &&
				    !(c->flags & CONN_WRITE_BLOCK) &&
				    !(c->flags & CONN_READ_BLOCK))
					continue;
				if (!(c->flags & CONN_IDLE_TIMER_ACT))
					continue;
				kore_connection_check_idletimer(now, c);
			}
		}

		for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
			cnext = TAILQ_NEXT(c, list);
			TAILQ_REMOVE(&disconnected, c, list);
			kore_connection_remove(c);
		}

		if (quit && http_request_count == 0)
			break;
	}

	for (c = TAILQ_FIRST(&worker_clients); c != NULL; c = cnext) {
		cnext = TAILQ_NEXT(c, list);
		net_send_flush(c);
		kore_connection_disconnect(c);
	}

	for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
		cnext = TAILQ_NEXT(c, list);
		net_send_flush(c);
		TAILQ_REMOVE(&disconnected, c, list);
		kore_connection_remove(c);
	}

	kore_debug("worker %d shutting down", kw->id);
	exit(0);
}

void
kore_worker_connection_add(struct connection *c)
{
	TAILQ_INSERT_TAIL(&worker_clients, c, list);
	worker_active_connections++;
}

void
kore_worker_connection_move(struct connection *c)
{
	TAILQ_REMOVE(&worker_clients, c, list);
	TAILQ_INSERT_TAIL(&disconnected, c, list);
}

void
kore_worker_connection_remove(struct connection *c)
{
	worker_active_connections--;
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
			kore_worker_spawn(kw->id, kw->cpu);
		} else {
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) signaled us (%d)",
			    kw->id, kw->pid, status);
		}

		break;
	}
}

void
kore_worker_acceptlock_release(void)
{
	if (worker_count == 1)
		return;

	if (worker->has_lock != 1)
		return;

	worker_unlock();
	worker->has_lock = 0;
}

static int
kore_worker_acceptlock_obtain(void)
{
	int		r;

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
