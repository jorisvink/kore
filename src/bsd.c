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

#include "spdy.h"
#include "kore.h"
#include "http.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/event.h>
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
#include <syslog.h>
#include <time.h>
#include <regex.h>
#include <zlib.h>
#include <unistd.h>

static int			kfd = -1;
static struct kevent		*events;
static int			nchanges;
static struct kevent		*changelist;
static u_int32_t		event_count = 0;

void
kore_platform_init(void)
{
	cpu_count = 0;
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
}

void
kore_platform_event_init(void)
{
	if ((kfd = kqueue()) == -1)
		fatal("kqueue(): %s", errno_s);

	nchanges = 0;
	event_count = worker_max_connections + 1;
	events = kore_calloc(event_count, sizeof(struct kevent));
	changelist = kore_calloc(event_count, sizeof(struct kevent));

	kore_platform_event_schedule(server.fd,
	    EVFILT_READ, EV_ADD | EV_DISABLE, &server);
}

int
kore_platform_event_wait(void)
{
	struct connection	*c;
	struct timespec		timeo;
	int			n, i, *fd;

	timeo.tv_sec = 0;
	timeo.tv_nsec = 100000000;
	n = kevent(kfd, changelist, nchanges, events, event_count, &timeo);
	if (n == -1) {
		if (errno == EINTR)
			return (0);
		fatal("kevent(): %s", errno_s);
	}

	nchanges = 0;
	if (n > 0)
		kore_debug("main(): %d sockets available", n);

	for (i = 0; i < n; i++) {
		fd = (int *)events[i].udata;

		if (events[i].flags & EV_EOF ||
		    events[i].flags & EV_ERROR) {
			if (*fd == server.fd)
				fatal("error on server socket");

			c = (struct connection *)events[i].udata;
			kore_connection_disconnect(c);
			continue;
		}

		if (*fd == server.fd) {
			while (worker->accepted < worker->accept_treshold) {
				kore_connection_accept(&server, &c);
				if (c == NULL)
					continue;

				worker->accepted++;
				kore_platform_event_schedule(c->fd,
				    EVFILT_READ, EV_ADD, c);
				kore_platform_event_schedule(c->fd,
				    EVFILT_WRITE, EV_ADD | EV_ONESHOT, c);
			}
		} else {
			c = (struct connection *)events[i].udata;
			if (events[i].filter == EVFILT_READ)
				c->flags |= CONN_READ_POSSIBLE;
			if (events[i].filter == EVFILT_WRITE)
				c->flags |= CONN_WRITE_POSSIBLE;

			if (!kore_connection_handle(c)) {
				kore_connection_disconnect(c);
			} else {
				if (!TAILQ_EMPTY(&(c->send_queue))) {
					kore_platform_event_schedule(c->fd,
					    EVFILT_WRITE, EV_ADD | EV_ONESHOT,
					    c);
				}
			}
		}
	}

	return (count);
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *data)
{
	if (nchanges >= KQUEUE_EVENTS) {
		kore_log(LOG_WARNING, "cannot schedule %d (%d) on %d",
		    type, flags, fd);
	} else {
		EV_SET(&changelist[nchanges], fd, type, flags, 0, 0, data);
		nchanges++;
	}
}

void
kore_platform_enable_accept(void)
{
	kore_platform_event_schedule(server.fd,
	    EVFILT_READ, EV_ENABLE, &server);
}

void
kore_platform_disable_accept(void)
{
	kore_platform_event_schedule(server.fd,
	    EVFILT_READ, EV_DISABLE, NULL);
}

void
kore_platform_proctitle(char *title)
{
	setproctitle("%s", title);
}
