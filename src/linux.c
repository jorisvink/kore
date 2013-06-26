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
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
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

#define EPOLL_EVENTS	500

static int			efd = -1;
static struct epoll_event	*events = NULL;

void
kore_platform_init(void)
{
	if ((cpu_count = sysconf(_SC_NPROCESSORS_ONLN)) == -1) {
		kore_debug("could not get number of cpu's falling back to 1");
		cpu_count = 1;
	}
}

void
kore_platform_worker_wait(int final)
{
	int			r;
	siginfo_t		info;
	struct kore_worker	k, *kw, *next;

	memset(&info, 0, sizeof(info));
	if (final)
		r = waitid(P_ALL, 0, &info, WEXITED);
	else
		r = waitid(P_ALL, 0, &info, WEXITED | WNOHANG);
	if (r == -1) {
		kore_debug("waitid(): %s", errno_s);
		return;
	}

	if (info.si_pid == 0)
		return;

	for (kw = TAILQ_FIRST(&kore_workers); kw != NULL; kw = next) {
		next = TAILQ_NEXT(kw, list);
		if (kw->pid != info.si_pid)
			continue;

		k = *kw;
		TAILQ_REMOVE(&kore_workers, kw, list);
		kore_log(LOG_NOTICE, "worker %d (%d)-> status %d (%d)",
		    kw->id, info.si_pid, info.si_status, info.si_code);
		free(kw);

		if (final)
			continue;

		if (info.si_code == CLD_EXITED ||
		    info.si_code == CLD_KILLED ||
		    info.si_code == CLD_DUMPED) {
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) gone, respawning new one",
			    k.id, k.pid);
			kore_worker_spawn(k.cpu);
		}
	}
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
	cpu_set_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
		kore_debug("kore_worker_setcpu(): %s", errno_s);
	} else {
		kore_debug("kore_worker_setcpu(): worker %d on cpu %d",
		    kw->id, kw->cpu);
	}
}

void
kore_platform_event_init(void)
{
	if ((efd = epoll_create(1000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	events = kore_calloc(EPOLL_EVENTS, sizeof(struct epoll_event));
	kore_platform_event_schedule(server.fd, EPOLLIN, 0, &server);
}

void
kore_platform_event_wait(int quit)
{
	struct connection	*c;
	int			n, i, *fd;

	n = epoll_wait(efd, events, EPOLL_EVENTS, 100);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("epoll_wait(): %s", errno_s);
	}

	if (n > 0)
		kore_debug("main(): %d sockets available", n);

	for (i = 0; i < n; i++) {
		fd = (int *)events[i].data.ptr;

		if (events[i].events & EPOLLERR ||
		    events[i].events & EPOLLHUP) {
			if (*fd == server.fd)
				fatal("error on server socket");

			c = (struct connection *)events[i].data.ptr;
			kore_connection_disconnect(c);
			continue;
		}

		if (*fd == server.fd) {
			if (!quit) {
				kore_connection_accept(&server, &c);
				if (c == NULL)
					continue;

				kore_platform_event_schedule(c->fd,
				    EPOLLIN | EPOLLOUT | EPOLLET, 0, c);
			}
		} else {
			c = (struct connection *)events[i].data.ptr;
			if (events[i].events & EPOLLIN)
				c->flags |= CONN_READ_POSSIBLE;
			if (events[i].events & EPOLLOUT)
				c->flags |= CONN_WRITE_POSSIBLE;

			if (!kore_connection_handle(c))
				kore_connection_disconnect(c);
		}
	}
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *udata)
{
	struct epoll_event	evt;

	kore_debug("kore_platform_event(%d, %d, %d, %p)",
	    fd, type, flags, udata);

	evt.events = type;
	evt.data.ptr = udata;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl() MOD: %s", errno_s);
		} else {
			fatal("epoll_ctl() ADD: %s", errno_s);
		}
	}
}

void
kore_platform_proctitle(char *title)
{
	if (prctl(PR_SET_NAME, title) == -1)
		kore_debug("prctl(): %s", errno_s);
}
