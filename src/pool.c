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

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include <stdint.h>

#include "kore.h"

#define POOL_MIN_ELEMENTS		16

#define POOL_ELEMENT_BUSY		0
#define POOL_ELEMENT_FREE		1

#if defined(KORE_USE_TASKS)
static void		pool_lock(struct kore_pool *);
static void		pool_unlock(struct kore_pool *);
#endif

static void		pool_region_create(struct kore_pool *, size_t);
static void		pool_region_destroy(struct kore_pool *);

void
kore_pool_init(struct kore_pool *pool, const char *name,
    size_t len, size_t elm)
{
	if (elm < POOL_MIN_ELEMENTS)
		elm = POOL_MIN_ELEMENTS;

	if ((pool->name = strdup(name)) == NULL)
		fatal("kore_pool_init: strdup %s", errno_s);

	len = (len + (8 - 1)) & ~(8 - 1);

	pool->lock = 0;
	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = len;
	pool->growth = elm * 0.25f;
	pool->slen = pool->elen + sizeof(struct kore_pool_entry);

	LIST_INIT(&(pool->regions));
	LIST_INIT(&(pool->freelist));

	pool_region_create(pool, elm);
}

void
kore_pool_cleanup(struct kore_pool *pool)
{
	pool->lock = 0;
	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = 0;
	pool->slen = 0;

	free(pool->name);
	pool->name = NULL;

	pool_region_destroy(pool);
}

void *
kore_pool_get(struct kore_pool *pool)
{
	u_int8_t			*ptr;
	struct kore_pool_entry		*entry;

#if defined(KORE_USE_TASKS)
	pool_lock(pool);
#endif

	if (LIST_EMPTY(&(pool->freelist)))
		pool_region_create(pool, pool->growth);

	entry = LIST_FIRST(&(pool->freelist));
	if (entry->state != POOL_ELEMENT_FREE)
		fatal("%s: element %p was not free", pool->name, (void *)entry);
	LIST_REMOVE(entry, list);

	entry->state = POOL_ELEMENT_BUSY;
	ptr = (u_int8_t *)entry + sizeof(struct kore_pool_entry);

	pool->inuse++;

#if defined(KORE_USE_TASKS)
	pool_unlock(pool);
#endif

	return (ptr);
}

void
kore_pool_put(struct kore_pool *pool, void *ptr)
{
	struct kore_pool_entry		*entry;

#if defined(KORE_USE_TASKS)
	pool_lock(pool);
#endif

	entry = (struct kore_pool_entry *)
	    ((u_int8_t *)ptr - sizeof(struct kore_pool_entry));

	if (entry->state != POOL_ELEMENT_BUSY)
		fatal("%s: element %p was not busy", pool->name, ptr);

	entry->state = POOL_ELEMENT_FREE;
	LIST_INSERT_HEAD(&(pool->freelist), entry, list);

	pool->inuse--;

#if defined(KORE_USE_TASKS)
	pool_unlock(pool);
#endif
}

static void
pool_region_create(struct kore_pool *pool, size_t elms)
{
	size_t				i;
	u_int8_t			*p;
	struct kore_pool_region		*reg;
	struct kore_pool_entry		*entry;

	if ((reg = calloc(1, sizeof(struct kore_pool_region))) == NULL)
		fatal("pool_region_create: calloc: %s", errno_s);

	LIST_INSERT_HEAD(&(pool->regions), reg, list);

	if (SIZE_MAX / elms < pool->slen)
		fatal("pool_region_create: overflow");

	reg->length = elms * pool->slen;
	reg->start = mmap(NULL, reg->length, PROT_READ | PROT_WRITE,
	    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (reg->start == MAP_FAILED)
		fatal("mmap: %s", errno_s);

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

static void
pool_region_destroy(struct kore_pool *pool)
{
	struct kore_pool_region		*reg;

	/* Take care iterating when modifying list contents */
	while (!LIST_EMPTY(&pool->regions)) {
		reg = LIST_FIRST(&pool->regions);
		LIST_REMOVE(reg, list);
		(void)munmap(reg->start, reg->length);
		free(reg);
	}

	/* Freelist references into the regions memory allocations */
	LIST_INIT(&pool->freelist);
	pool->elms = 0;
}

#if defined(KORE_USE_TASKS)
static void
pool_lock(struct kore_pool *pool)
{
	for (;;) {
		if (__sync_bool_compare_and_swap(&pool->lock, 0, 1))
			break;
	}
}

static void
pool_unlock(struct kore_pool *pool)
{
	if (!__sync_bool_compare_and_swap(&pool->lock, 1, 0))
		fatal("pool_unlock: failed to release %s", pool->name);
}
#endif
