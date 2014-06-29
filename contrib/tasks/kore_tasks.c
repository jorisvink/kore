/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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
#include <sys/queue.h>
#include <sys/socket.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "kore.h"
#include "http.h"
#include "kore_tasks.h"

static u_int8_t				threads;
static pthread_mutex_t			task_thread_lock;

static TAILQ_HEAD(, kore_task_thread)	task_threads;

static void	*task_thread(void *);
static void	task_channel_read(int, void *, u_int32_t);
static void	task_channel_write(int, void *, u_int32_t);
static void	task_thread_spawn(struct kore_task_thread **);

#define THREAD_FD_ASSIGN(t, f, i, o)				\
	do {							\
		if (pthread_self() == t) {			\
			f = i;					\
		} else {					\
			f = o;					\
		}						\
	} while (0);

void
kore_task_init(void)
{
	threads = 0;

	TAILQ_INIT(&task_threads);
	pthread_mutex_init(&task_thread_lock, NULL);
}

void
kore_task_create(struct kore_task **out, void (*entry)(struct kore_task *))
{
	struct kore_task		*t;
	struct kore_task_thread		*tt;

	t = kore_malloc(sizeof(struct kore_task));
	t->entry = entry;
	t->type = KORE_TYPE_TASK;
	t->state = KORE_TASK_STATE_CREATED;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0,t->fds) == -1)
		fatal("kore_task_create: socketpair() %s", errno_s);

	kore_platform_schedule_read(t->fds[0], t);

	pthread_mutex_lock(&task_thread_lock);
	if (TAILQ_EMPTY(&task_threads))
		task_thread_spawn(&tt);
	else
		tt = TAILQ_FIRST(&task_threads);

	pthread_mutex_unlock(&task_thread_lock);
	pthread_mutex_lock(&(tt->lock));

	t->thread = tt;
	TAILQ_INSERT_TAIL(&(tt->tasks), t, list);

	pthread_mutex_unlock(&(tt->lock));
	pthread_cond_signal(&(tt->cond));

	if (out != NULL)
		*out = t;
}

void
kore_task_bind_request(struct kore_task *t, struct http_request *req)
{
	kore_debug("kore_task_bind_request: %p bound to %p", req, t);

	t->req = req;
	req->task = t;
	req->flags |= HTTP_REQUEST_SLEEPING;
}

void
kore_task_destroy(struct kore_task *t)
{
	kore_debug("kore_task_destroy: %p", t);

	if (t->req != NULL)
		t->req->task = NULL;

	close(t->fds[0]);
	close(t->fds[1]);		/* This might already be closed. */

	kore_mem_free(t);
}

int
kore_task_finished(struct kore_task *t)
{
	if (t->state == KORE_TASK_STATE_FINISHED)
		return (1);

	return (0);
}

void
kore_task_finish(struct kore_task *t)
{
	kore_debug("kore_task_finished: %p", t);

	close(t->fds[1]);
}

void
kore_task_channel_write(struct kore_task *t, void *data, u_int32_t len)
{
	int		fd;

	kore_debug("kore_task_channel_write: %p <- %p (%ld)", t, data, len);

	THREAD_FD_ASSIGN(t->thread->tid, fd, t->fds[1], t->fds[0]);
	task_channel_write(fd, &len, sizeof(len));
	task_channel_write(fd, data, len);
}

u_int32_t
kore_task_channel_read(struct kore_task *t, void *out, u_int32_t len)
{
	int		fd;
	u_int32_t	dlen;

	kore_debug("kore_task_channel_read: %p -> %p (%ld)", t, out, len);

	THREAD_FD_ASSIGN(t->thread->tid, fd, t->fds[1], t->fds[0]);
	task_channel_read(fd, &dlen, sizeof(dlen));
	if (dlen > len)
		fatal("task_channel_read: buffer too small, wanted %d", dlen);
	task_channel_read(fd, out, dlen);

	return (dlen);
}

void
kore_task_handle(struct kore_task *t, int finished)
{
	kore_debug("kore_task_handle: %p, %d", t, finished);

	if (finished) {
		t->state = KORE_TASK_STATE_FINISHED;
		if (t->req != NULL) {
			t->req->flags &= ~HTTP_REQUEST_SLEEPING;
			if (t->req->flags & HTTP_REQUEST_DELETE)
				kore_task_destroy(t);
		}
	}
}

static void
task_channel_write(int fd, void *data, u_int32_t len)
{
	ssize_t		r;
	u_int8_t	*d;
	u_int32_t	offset;

	d = data;
	offset = 0;
	while (offset != len) {
		r = write(fd, d + offset, len - offset);
		if (r == -1 && errno == EINTR)
			continue;
		if (r == -1)
			fatal("task_channel_write: %s", errno_s);
		offset += r;
	}
}

static void
task_channel_read(int fd, void *out, u_int32_t len)
{
	ssize_t		r;
	u_int8_t	*d;
	u_int32_t	offset;

	d = out;
	offset = 0;
	while (offset != len) {
		r = read(fd, d + offset, len - offset);
		if (r == -1 && errno == EINTR)
			continue;
		if (r == -1)
			fatal("task_channel_read: %s", errno_s);
		if (r == 0)
			fatal("task_channel_read: unexpected eof");

		offset += r;
	}
}

static void
task_thread_spawn(struct kore_task_thread **out)
{
	struct kore_task_thread		*tt;

	tt = kore_malloc(sizeof(*tt));
	tt->idx = threads++;

	TAILQ_INIT(&(tt->tasks));
	pthread_cond_init(&(tt->cond), NULL);
	pthread_mutex_init(&(tt->lock), NULL);

	if (pthread_create(&(tt->tid), NULL, task_thread, tt) != 0)
		fatal("pthread_create: %s", errno_s);

	*out = tt;
}

static void *
task_thread(void *arg)
{
	struct kore_task		*t;
	struct kore_task_thread		*tt = arg;

	kore_debug("task_thread: #%d starting", tt->idx);

	pthread_mutex_lock(&(tt->lock));

	pthread_mutex_lock(&task_thread_lock);
	TAILQ_INSERT_TAIL(&task_threads, tt, list);
	pthread_mutex_unlock(&task_thread_lock);

	for (;;) {
		if (TAILQ_EMPTY(&(tt->tasks)))
			pthread_cond_wait(&(tt->cond), &(tt->lock));

		kore_debug("task_thread#%d: woke up", tt->idx);

		t = TAILQ_FIRST(&(tt->tasks));
		TAILQ_REMOVE(&(tt->tasks), t, list);
		pthread_mutex_unlock(&(tt->lock));

		pthread_mutex_lock(&task_thread_lock);
		TAILQ_REMOVE(&task_threads, tt, list);
		pthread_mutex_unlock(&task_thread_lock);

		kore_debug("task_thread#%d: executing %p", tt->idx, t);

		t->state = KORE_TASK_STATE_RUNNING;
		t->entry(t);
		kore_task_finish(t);

		pthread_mutex_lock(&task_thread_lock);
		TAILQ_INSERT_HEAD(&task_threads, tt, list);
		pthread_mutex_unlock(&task_thread_lock);

		pthread_mutex_lock(&(tt->lock));
	}

	pthread_exit(NULL);

	/* NOTREACHED */
	return (NULL);
}
