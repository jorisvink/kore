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

#ifndef __H_KORE_TASKS
#define __H_KORE_TASKS

#include <pthread.h>

#define KORE_TASK_STATE_CREATED		1
#define KORE_TASK_STATE_RUNNING		2
#define KORE_TASK_STATE_FINISHED	3
#define KORE_TASK_STATE_ABORT		4

#define KORE_TASK_THREADS		2

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(KORE_NO_HTTP)
struct http_request;
#endif

struct kore_task {
	struct kore_event	evt;
	int			state;
	int			result;
	pthread_rwlock_t	lock;

#if !defined(KORE_NO_HTTP)
	struct http_request	*req;
#endif

	int			fds[2];
	int			(*entry)(struct kore_task *);
	void			(*cb)(struct kore_task *);

	struct kore_task_thread		*thread;

	TAILQ_ENTRY(kore_task)		list;
	LIST_ENTRY(kore_task)		rlist;
};

struct kore_task_thread {
	u_int8_t		idx;
	pthread_t		tid;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	TAILQ_HEAD(, kore_task)	tasks;

	TAILQ_ENTRY(kore_task_thread)	list;
};

void		kore_task_init(void);
void		kore_task_handle(void *, int);
void		kore_task_run(struct kore_task *);
void		kore_task_finish(struct kore_task *);
void		kore_task_destroy(struct kore_task *);
int		kore_task_finished(struct kore_task *);

#if !defined(KORE_NO_HTTP)
void		kore_task_bind_request(struct kore_task *,
		    struct http_request *);
#endif
void		kore_task_bind_callback(struct kore_task *,
		    void (*cb)(struct kore_task *));
void		kore_task_create(struct kore_task *,
		    int (*entry)(struct kore_task *));

u_int32_t	kore_task_channel_read(struct kore_task *, void *, u_int32_t);
void		kore_task_channel_write(struct kore_task *, void *, u_int32_t);

void		kore_task_set_state(struct kore_task *, int);
void		kore_task_set_result(struct kore_task *, int);

int		kore_task_state(struct kore_task *);
int		kore_task_result(struct kore_task *);

extern u_int16_t	kore_task_threads;

#if defined(__cplusplus)
}
#endif

#endif
