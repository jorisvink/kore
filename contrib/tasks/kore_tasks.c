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
static pthread_mutex_t			task_lock;
static pthread_cond_t			task_broadcast;

static TAILQ_HEAD(, kore_task)		task_list;
static TAILQ_HEAD(, kore_task_thread)	task_threads;

static void	*task_thread(void *);
static void	task_thread_spawn(void);

void
kore_task_init(void)
{
	threads = 0;

	TAILQ_INIT(&task_list);
	TAILQ_INIT(&task_threads);

	pthread_mutex_init(&task_lock, NULL);
	pthread_cond_init(&task_broadcast, NULL);

	task_thread_spawn();
}

void
kore_task_setup(struct http_request *req)
{
	int	i;

	for (i = 0; i < HTTP_TASK_MAX; i++)
		req->tasks[i] = NULL;
}

void
kore_task_create(struct http_request *req, int idx,
    void (*entry)(struct kore_task *))
{
	if (idx >= HTTP_TASK_MAX)
		fatal("kore_task_create: idx > HTTP_TASK_MAX");
	if (req->tasks[idx] != NULL)
		return;

	req->flags |= HTTP_REQUEST_SLEEPING;

	req->tasks[idx] = kore_malloc(sizeof(struct kore_task));
	req->tasks[idx]->owner = req;
	req->tasks[idx]->entry = entry;
	req->tasks[idx]->type = KORE_TYPE_TASK;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, req->tasks[idx]->fds) == -1)
		fatal("kore_task_create: socketpair() %s", errno_s);

	kore_platform_schedule_read(req->tasks[idx]->fds[0], req->tasks[idx]);

	pthread_mutex_lock(&task_lock);
	TAILQ_INSERT_TAIL(&task_list, req->tasks[idx], list);
	pthread_mutex_unlock(&task_lock);

	pthread_cond_broadcast(&task_broadcast);
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
	kore_debug("kore_task_channel_write: %p <- %p (%ld)", t, data, len);
}

void
kore_task_handle(struct kore_task *t, int finished)
{
	struct http_request	*req = t->owner;

	kore_debug("kore_task_handle: %p, %d", t, finished);

	if (finished) {
		close(t->fds[0]);
		req->flags &= ~HTTP_REQUEST_SLEEPING;
		kore_mem_free(t);
	}
}

static void
task_thread_spawn(void)
{
	struct kore_task_thread		*tt;

	tt = kore_malloc(sizeof(*tt));
	tt->idx = threads++;
	TAILQ_INSERT_TAIL(&task_threads, tt, list);

	if (pthread_create(&(tt->tid), NULL, task_thread, tt) != 0)
		fatal("pthread_create: %s", errno_s);
}

static void *
task_thread(void *arg)
{
	struct kore_task		*t;
	struct kore_task_thread		*tt = arg;

	kore_debug("task_thread: #%d starting", tt->idx);

	for (;;) {
		pthread_mutex_lock(&task_lock);
		if (TAILQ_EMPTY(&task_list))
			pthread_cond_wait(&task_broadcast, &task_lock);

		kore_debug("task_thread#%d: woke up", tt->idx);

		t = TAILQ_FIRST(&task_list);
		TAILQ_REMOVE(&task_list, t, list);
		pthread_mutex_unlock(&task_lock);

		kore_debug("task_thread#%d: executing %p", tt->idx, t);
		t->thread = tt;
		t->entry(t);
	}

	pthread_exit(NULL);

	/* NOTREACHED */
	return (NULL);
}
