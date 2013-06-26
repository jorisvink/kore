/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pwd.h>
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

#define KORE_SHM_KEY		15000

#if defined(KORE_USE_SEMAPHORE)
#define kore_trylock		sem_trywait
#define kore_unlock		sem_post
static sem_t			*kore_accept_lock;
#else
#define kore_trylock		kore_internal_trylock
#define kore_unlock		kore_internal_unlock
static int			*kore_accept_lock;
static int			kore_internal_trylock(int *);
static int			kore_internal_unlock(int *);
#endif

static void	kore_worker_acceptlock_obtain(void);
static void	kore_worker_acceptlock_release(void);

static u_int16_t			workerid = 0;
static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		worker_clients;
static TAILQ_HEAD(, kore_worker)	kore_workers;
static int				shm_accept_key;

static u_int32_t		worker_active_connections = 0;
static u_int8_t			worker_has_acceptlock = 0;

extern volatile sig_atomic_t	sig_recv;
struct kore_worker		*worker = NULL;
u_int32_t			worker_max_connections = 250;

void
kore_worker_init(void)
{
	u_int16_t		i, cpu;

	if (worker_count == 0)
		fatal("no workers specified");

	shm_accept_key = shmget(KORE_SHM_KEY,
	    sizeof(*kore_accept_lock), IPC_CREAT | IPC_EXCL | 0700);
	if (shm_accept_key == -1)
		fatal("kore_worker_init(): shmget() %s", errno_s);
	if ((kore_accept_lock = shmat(shm_accept_key, NULL, 0)) == NULL)
		fatal("kore_worker_init(): shmat() %s", errno_s);

#if defined(KORE_USE_SEMAPHORE)
	if (sem_init(kore_accept_lock, 1, 1) == -1)
		fatal("kore_worker_init(): sem_init() %s", errno_s);
#else
	*kore_accept_lock = 0;
#endif

	kore_debug("kore_worker_init(): system has %d cpu's", cpu_count);
	kore_debug("kore_worker_init(): starting %d workers", worker_count);
	if (worker_count > cpu_count)
		kore_debug("kore_worker_init(): more workers then cpu's");

	cpu = 0;
	TAILQ_INIT(&kore_workers);
	for (i = 0; i < worker_count; i++) {
		kore_worker_spawn(cpu++);
		if (cpu == cpu_count)
			cpu = 0;
	}
}

void
kore_worker_spawn(u_int16_t cpu)
{
	struct kore_worker	*kw;

	kw = (struct kore_worker *)kore_malloc(sizeof(*kw));
	kw->id = workerid++;
	kw->cpu = cpu;
	kw->pid = fork();
	if (kw->pid == -1)
		fatal("could not spawn worker child: %s", errno_s);

	if (kw->pid == 0) {
		kw->pid = getpid();
		kore_worker_entry(kw);
		/* NOTREACHED */
	}

	TAILQ_INSERT_TAIL(&kore_workers, kw, list);
}

void
kore_worker_shutdown(void)
{
	kore_log(LOG_NOTICE, "waiting for workers to drain and shutdown");
	while (!TAILQ_EMPTY(&kore_workers))
		kore_worker_wait(1);

	if (shmctl(shm_accept_key, IPC_RMID, NULL) == -1) {
		kore_log(LOG_NOTICE,
		    "failed to deleted shm segment: %s", errno_s);
	}
}

void
kore_worker_dispatch_signal(int sig)
{
	struct kore_worker	*kw;

	TAILQ_FOREACH(kw, &kore_workers, list) {
		if (kill(kw->pid, sig) == -1)
			kore_debug("kill(%d, %d): %s", kw->pid, sig, errno_s);
	}
}

void
kore_worker_entry(struct kore_worker *kw)
{
	int			quit;
	u_int32_t		lowat;
	char			buf[16];
	struct connection	*c, *cnext;
	struct kore_worker	*k, *next;

	worker = kw;

	if (chroot(chroot_path) == -1)
		fatal("cannot chroot(): %s", errno_s);
	if (chdir("/") == -1)
		fatal("cannot chdir(): %s", errno_s);
	if (setgroups(1, &pw->pw_gid) || setresgid(pw->pw_gid, pw->pw_gid,
	    pw->pw_gid) || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("unable to drop privileges");

	snprintf(buf, sizeof(buf), "kore [wrk %d]", kw->id);
	kore_platform_proctitle(buf);
	kore_platform_worker_setcpu(kw);

	for (k = TAILQ_FIRST(&kore_workers); k != NULL; k = next) {
		next = TAILQ_NEXT(k, list);
		if (k == worker)
			continue;

		TAILQ_REMOVE(&kore_workers, k, list);
		free(k);
	}

	kore_pid = kw->pid;

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);
	signal(SIGPIPE, SIG_IGN);

	http_init();
	TAILQ_INIT(&disconnected);
	TAILQ_INIT(&worker_clients);

	quit = 0;
	kore_platform_event_init();
	kore_accesslog_worker_init();

	lowat = worker_max_connections / 10;
	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);
	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP)
				kore_module_reload();
			else if (sig_recv == SIGQUIT)
				quit = 1;
			sig_recv = 0;
		}

		if (!quit && !worker_has_acceptlock &&
		    worker_active_connections < lowat)
			kore_worker_acceptlock_obtain();

		kore_platform_event_wait();

		if (worker_has_acceptlock &&
		    (worker_active_connections >= worker_max_connections ||
		    quit == 1))
			kore_worker_acceptlock_release();

		http_process();

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
		TAILQ_REMOVE(&worker_clients, c, list);
		kore_connection_remove(c);
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
	pid_t			pid;
	int			status;
	struct kore_worker	k, *kw, *next;

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

	for (kw = TAILQ_FIRST(&kore_workers); kw != NULL; kw = next) {
		next = TAILQ_NEXT(kw, list);
		if (kw->pid != pid)
			continue;

		k = *kw;
		TAILQ_REMOVE(&kore_workers, kw, list);
		kore_log(LOG_NOTICE, "worker %d (%d)-> status %d",
		    kw->id, pid, status);
		free(kw);

		if (final)
			continue;

		if (WEXITSTATUS(status) || WTERMSIG(status) ||
		    WCOREDUMP(status)) {
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) gone, respawning new one",
			    k.id, k.pid);
			kore_worker_spawn(k.cpu);
		}
	}
}

static void
kore_worker_acceptlock_obtain(void)
{
	int		ret;

	if (worker_count == 1 && !worker_has_acceptlock) {
		worker_has_acceptlock = 1;
		kore_platform_enable_accept();
		return;
	}

	ret = kore_trylock(kore_accept_lock);
	if (ret == -1) {
		if (errno == EAGAIN)
			return;
		kore_log(LOG_WARNING, "kore_worker_acceptlock(): %s", errno_s);
	} else {
		worker_has_acceptlock = 1;
		kore_platform_enable_accept();
		kore_log(LOG_NOTICE, "obtained accept lock (%d/%d)",
		    worker_active_connections, worker_max_connections);
	}
}

static void
kore_worker_acceptlock_release(void)
{
	if (worker_count == 1)
		return;

	if (worker_has_acceptlock != 1) {
		kore_log(LOG_NOTICE,
		    "kore_worker_acceptlock_release() != 1");
		return;
	}

	if (kore_unlock(kore_accept_lock) == -1) {
		kore_log(LOG_NOTICE,
		    "kore_worker_acceptlock_release(): %s", errno_s);
	} else {
		worker_has_acceptlock = 0;
		kore_platform_disable_accept();
		kore_log(LOG_NOTICE, "released %d/%d",
		    worker_active_connections, worker_max_connections);
	}
}

#if !defined(KORE_USE_SEMAPHORE)

static int
kore_internal_trylock(int *lock)
{
	errno = EAGAIN;
	if (__sync_val_compare_and_swap(lock, 0, 1) == 1)
		return (-1);

	errno = 0;
	return (0);
}

static int
kore_internal_unlock(int *lock)
{
	if (__sync_val_compare_and_swap(lock, 1, 0) != 1)
		kore_log(LOG_NOTICE, "kore_internal_unlock(): wasnt locked");

	return (0);
}

#endif
