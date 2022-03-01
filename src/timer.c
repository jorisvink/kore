/*
 * Copyright (c) 2016-2022 Joris Vink <joris@coders.se>
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
#include <sys/queue.h>

#include "kore.h"

TAILQ_HEAD(timerlist, kore_timer)	kore_timers;

void
kore_timer_init(void)
{
	TAILQ_INIT(&kore_timers);
}

struct kore_timer *
kore_timer_add(void (*cb)(void *, u_int64_t), u_int64_t interval,
    void *arg, int flags)
{
	struct kore_timer	*timer, *t;

	timer = kore_malloc(sizeof(*timer));

	timer->cb = cb;
	timer->arg = arg;
	timer->flags = flags;
	timer->interval = interval;
	timer->nextrun = kore_time_ms() + timer->interval;

	TAILQ_FOREACH(t, &kore_timers, list) {
		if (t->nextrun > timer->nextrun) {
			TAILQ_INSERT_BEFORE(t, timer, list);
			return (timer);
		}
	}

	TAILQ_INSERT_TAIL(&kore_timers, timer, list);
	return (timer);
}

void
kore_timer_remove(struct kore_timer *timer)
{
	TAILQ_REMOVE(&kore_timers, timer, list);
	kore_free(timer);
}

u_int64_t
kore_timer_next_run(u_int64_t now)
{
	struct kore_timer	*timer;

	if ((timer = TAILQ_FIRST(&kore_timers)) != NULL) {
		if (timer->nextrun > now)
			return (timer->nextrun - now);
		return (0);
	}

	return (KORE_WAIT_INFINITE);
}

void
kore_timer_run(u_int64_t now)
{
	struct kore_timer	*timer, *t, *prev;

	prev = NULL;

	while ((timer = TAILQ_FIRST(&kore_timers)) != NULL) {
		if (timer == prev)
			break;

		if (timer->nextrun > now)
			break;

		TAILQ_REMOVE(&kore_timers, timer, list);
		timer->cb(timer->arg, now);

		if (timer->flags & KORE_TIMER_ONESHOT) {
			kore_free(timer);
		} else {
			prev = timer;
			timer->nextrun = now + timer->interval;
			TAILQ_FOREACH(t, &kore_timers, list) {
				if (t->nextrun > timer->nextrun) {
					TAILQ_INSERT_BEFORE(t, timer, list);
					break;
				}
			}

			if (t == NULL)
				TAILQ_INSERT_TAIL(&kore_timers, timer, list);
		}
	}
}
