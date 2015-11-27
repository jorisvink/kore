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
#include "tasks.h"

static u_int8_t				threads;
static TAILQ_HEAD(, kore_task_thread)	task_threads;

u_int16_t	kore_task_threads = KORE_TASK_THREADS;

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
}

void
kore_task_create(struct kore_task *t, int (*entry)(struct kore_task *))
{
	t->cb = NULL;
#if !defined(KORE_NO_HTTP)
	t->req = NULL;
#endif
	t->entry = entry;
	t->type = KORE_TYPE_TASK;
	t->state = KORE_TASK_STATE_CREATED;
	pthread_rwlock_init(&(t->lock), NULL);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, t->fds) == -1)
		fatal("kore_task_create: socketpair() %s", errno_s);
}

void
kore_task_run(struct kore_task *t)
{
	struct kore_task_thread		*tt;

	kore_platform_schedule_read(t->fds[0], t);
	if (threads < kore_task_threads) {
		/* task_thread_spawn() will lock tt->lock for us. */
		task_thread_spawn(&tt);
	} else {
		/* Cycle task around. */
		if ((tt = TAILQ_FIRST(&task_threads)) == NULL)
			fatal("no available tasks threads?");
		pthread_mutex_lock(&(tt->lock));
		TAILQ_REMOVE(&task_threads, tt, list);
		TAILQ_INSERT_TAIL(&task_threads, tt, list);
	}

	t->thread = tt;
	TAILQ_INSERT_TAIL(&(tt->tasks), t, list);

	pthread_mutex_unlock(&(tt->lock));
	pthread_cond_signal(&(tt->cond));
}

#if !defined(KORE_NO_HTTP)
void
kore_task_bind_request(struct kore_task *t, struct http_request *req)
{
	kore_debug("kore_task_bind_request: %p bound to %p", req, t);

	if (t->cb != NULL)
		fatal("cannot bind cbs and requests at the same time");

	t->req = req;
	LIST_INSERT_HEAD(&(req->tasks), t, rlist);

	http_request_sleep(req);
}
#endif

void
kore_task_bind_callback(struct kore_task *t, void (*cb)(struct kore_task *))
{
#if !defined(KORE_NO_HTTP)
	if (t->req != NULL)
		fatal("cannot bind requests and cbs at the same time");
#endif
	t->cb = cb;
}

void
kore_task_destroy(struct kore_task *t)
{
	kore_debug("kore_task_destroy: %p", t);

#if !defined(KORE_NO_HTTP)
	if (t->req != NULL) {
		t->req = NULL;
		LIST_REMOVE(t, rlist);
	}
#endif

	pthread_rwlock_wrlock(&(t->lock));

	if (t->fds[0] != -1) {
		(void)close(t->fds[0]);
		t->fds[0] = -1;
	}

	if (t->fds[1] != -1) {
		(void)close(t->fds[1]);
		t->fds[1] = -1;
	}

	pthread_rwlock_unlock(&(t->lock));
	pthread_rwlock_destroy(&(t->lock));
}

int
kore_task_finished(struct kore_task *t)
{
	return ((kore_task_state(t) == KORE_TASK_STATE_FINISHED));
}

void
kore_task_finish(struct kore_task *t)
{
	kore_debug("kore_task_finished: %p (%d)", t, t->result);

	pthread_rwlock_wrlock(&(t->lock));

	if (t->fds[1] != -1) {
		(void)close(t->fds[1]);
		t->fds[1] = -1;
	}

	pthread_rwlock_unlock(&(t->lock));
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
	u_int32_t	dlen, bytes;

	kore_debug("kore_task_channel_read: %p -> %p (%ld)", t, out, len);

	THREAD_FD_ASSIGN(t->thread->tid, fd, t->fds[1], t->fds[0]);
	task_channel_read(fd, &dlen, sizeof(dlen));

	if (dlen > len)
		bytes = len;
	else
		bytes = dlen;

	task_channel_read(fd, out, bytes);

	return (dlen);
}

void
kore_task_handle(struct kore_task *t, int finished)
{
	kore_debug("kore_task_handle: %p, %d", t, finished);

#if !defined(KORE_NO_HTTP)
	if (t->req != NULL)
		http_request_wakeup(t->req);
#endif

	if (finished) {
		kore_platform_disable_read(t->fds[0]);
		kore_task_set_state(t, KORE_TASK_STATE_FINISHED);
#if !defined(KORE_NO_HTTP)
		if (t->req != NULL) {
			if (t->req->flags & HTTP_REQUEST_DELETE)
				kore_task_destroy(t);
		}
#endif
	}

	if (t->cb != NULL)
		t->cb(t);
}

int
kore_task_state(struct kore_task *t)
{
	int	s;

	pthread_rwlock_rdlock(&(t->lock));
	s = t->state;
	pthread_rwlock_unlock(&(t->lock));

	return (s);
}

void
kore_task_set_state(struct kore_task *t, int state)
{
	pthread_rwlock_wrlock(&(t->lock));
	t->state = state;
	pthread_rwlock_unlock(&(t->lock));
}

int
kore_task_result(struct kore_task *t)
{
	int	r;

	pthread_rwlock_rdlock(&(t->lock));
	r = t->result;
	pthread_rwlock_unlock(&(t->lock));

	return (r);
}

void
kore_task_set_result(struct kore_task *t, int result)
{
	pthread_rwlock_wrlock(&(t->lock));
	t->result = result;
	pthread_rwlock_unlock(&(t->lock));
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
	pthread_mutex_lock(&(tt->lock));
	TAILQ_INSERT_TAIL(&task_threads, tt, list);

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

	for (;;) {
		if (TAILQ_EMPTY(&(tt->tasks)))
			pthread_cond_wait(&(tt->cond), &(tt->lock));

		kore_debug("task_thread#%d: woke up", tt->idx);

		t = TAILQ_FIRST(&(tt->tasks));
		TAILQ_REMOVE(&(tt->tasks), t, list);
		pthread_mutex_unlock(&(tt->lock));

		kore_debug("task_thread#%d: executing %p", tt->idx, t);

		kore_task_set_state(t, KORE_TASK_STATE_RUNNING);
		kore_task_set_result(t, t->entry(t));
		kore_task_finish(t);

		pthread_mutex_lock(&(tt->lock));
	}

	pthread_exit(NULL);

	/* NOTREACHED */
	return (NULL);
}
