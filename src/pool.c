/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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

#include <sys/queue.h>

#include "kore.h"

#define POOL_ELEMENT_BUSY		0
#define POOL_ELEMENT_FREE		1

static void		pool_region_create(struct kore_pool *, u_int32_t);

void
kore_pool_init(struct kore_pool *pool, const char *name,
    u_int32_t len, u_int32_t elm)
{
	kore_debug("kore_pool_init(%p, %s, %d, %d)", pool, name, len, elm);

	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = len;
	pool->name = kore_strdup(name);
	pool->slen = pool->elen + sizeof(struct kore_pool_entry);

	LIST_INIT(&(pool->regions));
	LIST_INIT(&(pool->freelist));

	pool_region_create(pool, elm);
}

void *
kore_pool_get(struct kore_pool *pool)
{
	u_int8_t			*ptr;
	struct kore_pool_entry		*entry;

	if (LIST_EMPTY(&(pool->freelist))) {
		kore_log(LOG_NOTICE, "pool %s is exhausted (%d/%d)",
		    pool->name, pool->inuse, pool->elms);

		pool_region_create(pool, pool->elms);
	}

	entry = LIST_FIRST(&(pool->freelist));
	if (entry->state != POOL_ELEMENT_FREE)
		fatal("%s: element %p was not free", pool->name, entry);
	LIST_REMOVE(entry, list);

	entry->state = POOL_ELEMENT_BUSY;
	ptr = (u_int8_t *)entry + sizeof(struct kore_pool_entry);

	pool->inuse++;

	return (ptr);
}

void
kore_pool_put(struct kore_pool *pool, void *ptr)
{
	struct kore_pool_entry		*entry;

	entry = (struct kore_pool_entry *)
	    ((u_int8_t *)ptr - sizeof(struct kore_pool_entry));

	if (entry->state != POOL_ELEMENT_BUSY)
		fatal("%s: element %p was not busy", pool->name, ptr);

	entry->state = POOL_ELEMENT_FREE;
	LIST_INSERT_HEAD(&(pool->freelist), entry, list);

	pool->inuse--;
}

static void
pool_region_create(struct kore_pool *pool, u_int32_t elms)
{
	u_int32_t			i;
	u_int8_t			*p;
	struct kore_pool_region		*reg;
	struct kore_pool_entry		*entry;

	kore_debug("pool_region_create(%p, %d)", pool, elms);

	reg = kore_malloc(sizeof(struct kore_pool_region));
	LIST_INSERT_HEAD(&(pool->regions), reg, list);

	reg->start = kore_malloc(elms * pool->slen);
	p = (u_int8_t *)reg->start;

	for (i = 0; i < elms; i++) {
		entry = (struct kore_pool_entry *)p;
		entry->region = reg;
		entry->state = POOL_ELEMENT_FREE;
		LIST_INSERT_HEAD(&(pool->freelist), entry, list);

		p = p + pool->slen;
	}

	pool->elms += elms;
}
