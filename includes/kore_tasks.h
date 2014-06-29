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

struct kore_task {
	u_int8_t	type;
	int		fds[2];
	void		*owner;
	void		(*entry)(struct kore_task *);

	struct kore_task_thread		*thread;
	TAILQ_ENTRY(kore_task)		list;
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
void		kore_task_finish(struct kore_task *);
void		kore_task_destroy(struct kore_task *);
void		kore_task_handle(struct kore_task *, int);
void		kore_task_create(struct http_request *,
		    void (*entry)(struct kore_task *));

u_int32_t	kore_task_channel_read(struct kore_task *, void *, u_int32_t);
void		kore_task_channel_write(struct kore_task *, void *, u_int32_t);

#endif
