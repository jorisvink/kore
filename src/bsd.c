/*
 * Copyright (c) 2013-2015 Joris Vink <joris@coders.se>
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
#include <sys/sysctl.h>

#if defined(__FreeBSD_version)
#include <sys/cpuset.h>
#endif

#include "kore.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

static int			kfd = -1;
static struct kevent		*events;
static u_int32_t		event_count = 0;

void
kore_platform_init(void)
{
#if defined(__MACH__) || defined(__FreeBSD_version)
	long	n;
	size_t	len = sizeof(n);
	int	mib[] = { CTL_HW, HW_NCPU };

	if (sysctl(mib, 2, &n, &len, NULL, 0) == -1) {
		kore_debug("kore_platform_init(): sysctl %s", errno_s);
		cpu_count = 1;
	} else {
		cpu_count = (u_int16_t)n;
	}
#else
	cpu_count = 0;
#endif /* __MACH__ || __FreeBSD_version */
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
#if defined(__FreeBSD_version)
	cpuset_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);
	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID,
	    -1, sizeof(cpuset), &cpuset) == -1) {
		fatal("failed: %s", errno_s);
	}

#endif /* __FreeBSD_version */
}

void
kore_platform_event_init(void)
{
	struct listener		*l;

	if ((kfd = kqueue()) == -1)
		fatal("kqueue(): %s", errno_s);

	event_count = (worker_max_connections * 2) + nlisteners;
	events = kore_calloc(event_count, sizeof(struct kevent));

	LIST_FOREACH(l, &listeners, list) {
		kore_platform_event_schedule(l->fd,
		    EVFILT_READ, EV_ADD | EV_DISABLE, l);
	}
}

int
kore_platform_event_wait(u_int64_t timer)
{
	u_int32_t		r;
	struct listener		*l;
	struct connection	*c;
	u_int8_t		type;
	struct timespec		timeo;
	int			n, i;

	timeo.tv_sec = timer / 1000;
	timeo.tv_nsec = (timer % 1000) * 1000000;
	n = kevent(kfd, NULL, 0, events, event_count, &timeo);
	if (n == -1) {
		if (errno == EINTR)
			return (0);
		fatal("kevent(): %s", errno_s);
	}

	if (n > 0)
		kore_debug("main(): %d sockets available", n);

	r = 0;
	for (i = 0; i < n; i++) {
		if (events[i].udata == NULL)
			fatal("events[%d].udata == NULL", i);

		type = *(u_int8_t *)events[i].udata;

		if (events[i].flags & EV_EOF ||
		    events[i].flags & EV_ERROR) {
			switch (type) {
			case KORE_TYPE_LISTENER:
				fatal("error on server socket");
				/* NOTREACHED */
#if defined(KORE_USE_PGSQL)
			case KORE_TYPE_PGSQL_CONN:
				kore_pgsql_handle(events[i].udata, 1);
				break;
#endif
#if defined(KORE_USE_TASKS)
			case KORE_TYPE_TASK:
				kore_task_handle(events[i].udata, 1);
				break;
#endif
			default:
				c = (struct connection *)events[i].udata;
				kore_connection_disconnect(c);
				break;
			}

			continue;
		}

		switch (type) {
		case KORE_TYPE_LISTENER:
			l = (struct listener *)events[i].udata;

			while (worker_active_connections <
			    worker_max_connections) {
				if (worker_accept_treshold != 0 &&
				    r >= worker_accept_treshold)
					break;

				if (!kore_connection_accept(l, &c)) {
					r = 1;
					break;
				}

				if (c == NULL)
					break;

				r++;
				kore_platform_event_all(c->fd, c);
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
#if defined(KORE_USE_TASKS)
		case KORE_TYPE_TASK:
			kore_task_handle(events[i].udata, 0);
			break;
#endif
		default:
			fatal("wrong type in event %d", type);
		}
	}

	return (r);
}

void
kore_platform_event_all(int fd, void *c)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD, c);
	kore_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, c);
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *data)
{
	struct kevent		event[1];

	EV_SET(&event[0], fd, type, flags, 0, 0, data);
	if (kevent(kfd, event, 1, NULL, 0, NULL) == -1)
		fatal("kevent: %s", errno_s);
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
