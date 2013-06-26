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
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pwd.h>
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <zlib.h>
#include <unistd.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

static u_int16_t			workerid = 0;
static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		worker_clients;

struct kore_worker_h			kore_workers;
struct kore_worker			*worker = NULL;

extern volatile sig_atomic_t		sig_recv;

void
kore_worker_init(void)
{
	u_int16_t		i, cpu;

	if (worker_count == 0)
		fatal("no workers specified");

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
kore_worker_entry(struct kore_worker *kw)
{
	int			quit;
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

	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);
	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP)
				kore_module_reload();
			else if (sig_recv == SIGQUIT)
				quit = 1;
			sig_recv = 0;
		}

		kore_platform_event_wait(quit);
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
}

void
kore_worker_connection_move(struct connection *c)
{
	TAILQ_REMOVE(&worker_clients, c, list);
	TAILQ_INSERT_TAIL(&disconnected, c, list);
}
