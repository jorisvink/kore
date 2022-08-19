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
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#if defined(__FreeBSD_version)
#include <sys/cpuset.h>
#endif

#include <errno.h>
#include <string.h>

#include "kore.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

static int			kfd = -1;
static int			scheduled = 0;
static struct kevent		*events = NULL;
static u_int32_t		event_count = 0;

#if defined(KORE_USE_PLATFORM_PLEDGE)
static char	pledges[256] = { "stdio rpath inet" };
#endif

void
kore_platform_init(void)
{
	long	n;
	size_t	len = sizeof(n);
	int	mib[] = { CTL_HW, HW_NCPU };

	if (sysctl(mib, 2, &n, &len, NULL, 0) == -1) {
		cpu_count = 1;
	} else {
		cpu_count = (u_int16_t)n;
	}
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
	if (kfd != -1)
		close(kfd);
	if (events != NULL)
		kore_free(events);

	if ((kfd = kqueue()) == -1)
		fatal("kqueue(): %s", errno_s);

	event_count = (worker_max_connections * 2) + nlisteners;
	events = kore_calloc(event_count, sizeof(struct kevent));
}

void
kore_platform_event_cleanup(void)
{
	if (kfd != -1) {
		close(kfd);
		kfd = -1;
	}

	if (events != NULL) {
		kore_free(events);
		events = NULL;
	}
}

void
kore_platform_event_wait(u_int64_t timer)
{
	u_int32_t		r;
	struct kore_event	*evt;
	int			n, i;
	struct timespec		timeo, *ts;

	if (timer == KORE_WAIT_INFINITE) {
		ts = NULL;
	} else {
		timeo.tv_sec = timer / 1000;
		timeo.tv_nsec = (timer % 1000) * 1000000;
		ts = &timeo;
	}

	n = kevent(kfd, NULL, 0, events, event_count, ts);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("kevent(): %s", errno_s);
	}

	for (i = 0; i < n; i++) {
		evt = (struct kore_event *)events[i].udata;

		if (evt == NULL)
			fatal("evt == NULL");

		r = 0;

		if (events[i].filter == EVFILT_READ)
			evt->flags |= KORE_EVENT_READ;

		if (events[i].filter == EVFILT_WRITE)
			evt->flags |= KORE_EVENT_WRITE;

		if (events[i].flags & EV_EOF || events[i].flags & EV_ERROR)
			r = 1;

		evt->handle(evt, r);
	}
}

void
kore_platform_event_all(int fd, void *c)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD | EV_CLEAR, c);
	kore_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, c);
}

void
kore_platform_event_level_all(int fd, void *c)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD, c);
	kore_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD, c);
}

void
kore_platform_event_level_read(int fd, void *c)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD, c);
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *data)
{
	struct kevent		event[1];

	EV_SET(&event[0], fd, type, flags, 0, 0, data);
	if (kevent(kfd, event, 1, NULL, 0, NULL) == -1 && errno != ENOENT)
		fatal("kevent: %s", errno_s);
}

void
kore_platform_enable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;
	int			flags;

	if (scheduled == 0) {
		scheduled = 1;
		flags = EV_ADD | EV_ENABLE;
	} else {
		flags = EV_ENABLE;
	}

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list) {
			kore_platform_event_schedule(l->fd,
			    EVFILT_READ, flags, l);
		}
	}
}

void
kore_platform_disable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list) {
			kore_platform_event_schedule(l->fd,
			    EVFILT_READ, EV_DISABLE, l);
		}
	}
}

void
kore_platform_schedule_read(int fd, void *data)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_ADD | EV_CLEAR, data);
}

void
kore_platform_schedule_write(int fd, void *data)
{
	kore_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, data);
}

void
kore_platform_disable_read(int fd)
{
	kore_platform_event_schedule(fd, EVFILT_READ, EV_DELETE, NULL);
}

void
kore_platform_disable_write(int fd)
{
	kore_platform_event_schedule(fd, EVFILT_WRITE, EV_DELETE, NULL);
}

void
kore_platform_proctitle(const char *title)
{
#ifdef __MACH__
	kore_proctitle(title);
#else
	setproctitle("%s", title);
#endif
}

#if defined(KORE_USE_PLATFORM_SENDFILE)
int
kore_platform_sendfile(struct connection *c, struct netbuf *nb)
{
	int		ret;
	off_t		len, smin;

	smin = nb->fd_len - nb->fd_off;
	len = MIN(SENDFILE_PAYLOAD_MAX, smin);

#if defined(__MACH__)
	ret = sendfile(nb->file_ref->fd, c->fd, nb->fd_off, &len, NULL, 0);
#else
	ret = sendfile(nb->file_ref->fd, c->fd, nb->fd_off, len, NULL, &len, 0);
#endif

	if (ret == -1) {
		if (errno == EAGAIN) {
			nb->fd_off += len;
			c->evt.flags &= ~KORE_EVENT_WRITE;
			return (KORE_RESULT_OK);
		}

		if (errno == EINTR) {
			nb->fd_off += len;
			return (KORE_RESULT_OK);
		}

		return (KORE_RESULT_ERROR);
	}

	nb->fd_off += len;

	if (len == 0 || nb->fd_off == nb->fd_len) {
		net_remove_netbuf(c, nb);
		c->snb = NULL;
	}

	return (KORE_RESULT_OK);
}
#endif

void
kore_platform_sandbox(void)
{
#if defined(KORE_USE_PLATFORM_PLEDGE)
	kore_platform_pledge();
#endif
}

#if defined(KORE_USE_PLATFORM_PLEDGE)
void
kore_platform_pledge(void)
{
	if (worker->id == KORE_WORKER_KEYMGR || worker->id == KORE_WORKER_ACME)
		return;

	if (pledge(pledges, NULL) == -1)
		fatal("failed to pledge process");
}

void
kore_platform_add_pledge(const char *pledge)
{
	size_t		len;

	len = strlcat(pledges, " ", sizeof(pledges));
	if (len >= sizeof(pledges))
		fatal("truncation on pledges");

	len = strlcat(pledges, pledge, sizeof(pledges));
	if (len >= sizeof(pledges))
		fatal("truncation on pledges (%s)", pledge);
}
#endif
