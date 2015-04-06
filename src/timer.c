/*
 * Copyright (c) 2015 Joris Vink <joris@coders.se>
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

#include "kore.h"

struct timer {
	u_int64_t		nextrun;
	u_int64_t		interval;
	int			flags;
	void			(*cb)(u_int64_t, u_int64_t);
	TAILQ_ENTRY(timer)	list;
};

TAILQ_HEAD(timerlist, timer)	kore_timers;

void
kore_timer_init(void)
{
	TAILQ_INIT(&kore_timers);
}

void
kore_timer_add(void (*cb)(u_int64_t, u_int64_t), u_int64_t interval, int flags)
{
	struct timer	*timer, *t;

	timer = kore_malloc(sizeof(*timer));

	timer->cb = cb;
	timer->flags = flags;
	timer->interval = interval;
	timer->nextrun = kore_time_ms() + timer->interval;

	TAILQ_FOREACH(t, &kore_timers, list) {
		if (t->nextrun > timer->nextrun) {
			TAILQ_INSERT_BEFORE(t, timer, list);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&kore_timers, timer, list);
}

u_int64_t
kore_timer_run(u_int64_t now)
{
	struct timer	*timer, *t;
	u_int64_t	next_timer, delta;

	next_timer = 100;

	while ((timer = TAILQ_FIRST(&kore_timers)) != NULL) {
		if (timer->nextrun > now) {
			next_timer = timer->nextrun - now;
			break;
		}

		TAILQ_REMOVE(&kore_timers, timer, list);
		delta = now - timer->nextrun;
		timer->cb(now, delta);

		if (timer->flags & KORE_TIMER_ONESHOT) {
			kore_mem_free(timer);
		} else {
			timer->nextrun += timer->interval - delta;
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

	if (next_timer > 1)
		next_timer -= 1;

	return (next_timer);
}
