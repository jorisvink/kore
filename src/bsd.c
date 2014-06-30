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
#include <sys/event.h>

#ifdef __MACH__
#include <sys/sysctl.h>
#endif

#include "kore.h"

#if defined(KORE_USE_PGSQL)
#include "kore_pgsql.h"
#endif

static int			kfd = -1;
static struct kevent		*events;
static u_int32_t		nchanges;
static struct kevent		*changelist;
static u_int32_t		event_count = 0;

void
kore_platform_init(void)
{
#ifndef __MACH__
	cpu_count = 0;
#else
	long	n;
	size_t	len = sizeof(n);
	int	mib[] = { CTL_HW, HW_AVAILCPU };

	 sysctl(mib, 2, &n, &len, NULL, 0);
	if (n < 1) {
		mib[1] = HW_NCPU;
		sysctl(mib, 2, &n, &len, NULL, 0);
	}

	if (n >= 1)
		cpu_count = (u_int16_t)n;
#endif /* !__MACH__ */
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
}

void
kore_platform_event_init(void)
{
	struct listener		*l;

	if ((kfd = kqueue()) == -1)
		fatal("kqueue(): %s", errno_s);

	nchanges = 0;
	event_count = worker_max_connections + nlisteners;
	events = kore_calloc(event_count, sizeof(struct kevent));
	changelist = kore_calloc(event_count, sizeof(struct kevent));

	LIST_FOREACH(l, &listeners, list) {
		kore_platform_event_schedule(l->fd,
		    EVFILT_READ, EV_ADD | EV_DISABLE, l);
	}
}

void
kore_platform_event_wait(void)
{
	struct listener		*l;
	struct connection	*c;
	u_int8_t		type;
	struct timespec		timeo;
	int			n, i;

	timeo.tv_sec = 0;
	timeo.tv_nsec = 100000000;
	n = kevent(kfd, changelist, nchanges, events, event_count, &timeo);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("kevent(): %s", errno_s);
	}

	nchanges = 0;
	if (n > 0)
		kore_debug("main(): %d sockets available", n);

	for (i = 0; i < n; i++) {
		if (events[i].udata == NULL)
			fatal("events[%d].udata == NULL", i);

		type = *(u_int8_t *)events[i].udata;

		if (events[i].flags & EV_EOF ||
		    events[i].flags & EV_ERROR) {
			if (type == KORE_TYPE_LISTENER)
				fatal("error on server socket");

#if defined(KORE_USE_PGSQL)
			if (type == KORE_TYPE_PGSQL_CONN) {
				kore_pgsql_handle(events[i].udata, 1);
				continue;
			}
#endif

			c = (struct connection *)events[i].udata;
			kore_connection_disconnect(c);
			continue;
		}

		switch (type) {
		case KORE_TYPE_LISTENER:
			l = (struct listener *)events[i].udata;

			while ((worker->accepted < worker->accept_treshold) &&
			    (worker_active_connections <
			    worker_max_connections)) {
				kore_connection_accept(l, &c);
				if (c == NULL)
					break;

				worker->accepted++;
				kore_platform_event_schedule(c->fd,
				    EVFILT_READ, EV_ADD, c);
				kore_platform_event_schedule(c->fd,
				    EVFILT_WRITE, EV_ADD | EV_ONESHOT, c);
			}
			break;
		case KORE_TYPE_CONNECTION:
			c = (struct connection *)events[i].udata;
			if (events[i].filter == EVFILT_READ &&
			    !(c->flags & CONN_READ_BLOCK))
				c->flags |= CONN_READ_POSSIBLE;
			if (events[i].filter == EVFILT_WRITE &&
			    !(c->flags & CONN_WRITE_BLOCK))
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
			break;
#if defined(KORE_USE_PGSQL)
		case KORE_TYPE_PGSQL_CONN:
			kore_pgsql_handle(events[i].udata, 0);
			break;
#endif
		default:
			fatal("wrong type in event %d", type);
		}
	}
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *data)
{
	if (nchanges >= event_count) {
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
	struct listener		*l;

	LIST_FOREACH(l, &listeners, list)
		kore_platform_event_schedule(l->fd, EVFILT_READ, EV_ENABLE, l);
}

void
kore_platform_disable_accept(void)
{
	struct listener		*l;

	LIST_FOREACH(l, &listeners, list)
		kore_platform_event_schedule(l->fd, EVFILT_READ, EV_DISABLE, l);
}

void
kore_platform_schedule_read(int fd, void *data)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD, data);
}

void
kore_platform_disable_read(int fd)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_DELETE, NULL);
}

void
kore_platform_proctitle(char *title)
{
#ifndef __MACH__
	setproctitle("%s", title);
#endif
}
