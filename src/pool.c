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

/*
 * A kore_pool is a memory pool containing fixed-sized objects that
 * can quickly be obtained by a caller via kore_pool_get() and returned
 * via kore_pool_put().
 *
 * Each entry in a pool will have a canary at the end that is used to
 * catch any potential overruns when the entry is returned to the pool.
 *
 * If memory pool guards are enabled three additional things happen:
 *
 *   1) The metadata is placed at the start of a page instead
 *      of right before the returned user pointer.
 *
 *   2) Each pool entry gets a guard page at the end of its allocation
 *      that is marked as PROT_NONE. Touching a guard page will cause
 *      the application to receive a SIGSEGV.
 *
 *   3) Entries are only marked PROT_READ | PROT_WRITE when they are
 *      obtained with kore_pool_get(). Their memory protection is
 *      changed to PROT_NONE when returned to the pool via kore_pool_get().
 *
 * Caveats:
 *    Pools are designed to live for the entire lifetime of a Kore process
 *    until it will exit and are therefor not properly cleaned up when exit
 *    time arrives.
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

static void		pool_grow(struct kore_pool *, size_t);

static void		pool_mark_entry_rw(struct kore_pool *, void *);
static void		pool_mark_entry_none(struct kore_pool *, void *);

void
kore_pool_init(struct kore_pool *pool, const char *name,
    size_t len, size_t elm)
{
	long		pagesz;

	if (elm < POOL_MIN_ELEMENTS)
		elm = POOL_MIN_ELEMENTS;

	if ((pagesz = sysconf(_SC_PAGESIZE)) == -1)
		fatal("%s: sysconf: %s", __func__, errno_s);

	if ((pool->name = strdup(name)) == NULL)
		fatal("kore_pool_init: strdup %s", errno_s);

	pool->uselen = len;

	len = len + sizeof(u_int64_t);
	len = (len + (16 - 1)) & ~(16 - 1);

	pool->elmlen = len;

	pool->lock = 0;
	pool->freelist = NULL;
	pool->pagesz = pagesz;
	pool->growth = elm * 0.25f;
	pool->canary = (u_int64_t)kore_platform_random_uint32() << 32 |
	    kore_platform_random_uint32();

	if (kore_mem_guard) {
		pool->memsz = pool->pagesz * 2;

		while (pool->elmlen >
		    pool->pagesz - sizeof(struct kore_pool_entry)) {
			pool->memsz += pool->pagesz;
			pool->elmlen -= MIN(pool->elmlen, pool->pagesz);
		}

		pool->elmlen = len;
	} else {
		pool->memsz = pool->elmlen;
	}

	pool_grow(pool, elm);
}

void
kore_pool_cleanup(struct kore_pool *pool)
{
	struct kore_pool_entry		*entry, *next;

	if (kore_mem_guard) {
		for (entry = pool->freelist; entry != NULL; entry = next) {
			pool_mark_entry_rw(pool, entry);
			next = entry->nextfree;
			(void)munmap(entry, pool->memsz);
		}
	}

	free(pool->name);
}

void *
kore_pool_get(struct kore_pool *pool)
{
	u_int64_t			canary;
	struct kore_pool_entry		*entry;

#if defined(KORE_USE_TASKS)
	pool_lock(pool);
#endif

	if (pool->freelist == NULL)
		pool_grow(pool, pool->growth);

	entry = pool->freelist;

	if (kore_mem_guard)
		pool_mark_entry_rw(pool, entry);

	pool->freelist = entry->nextfree;

	if (entry->state != POOL_ELEMENT_FREE)
		fatal("%s: element %p was not free", pool->name, (void *)entry);

	entry->nextfree = NULL;
	entry->state = POOL_ELEMENT_BUSY;

	canary = pool->canary;
	canary ^= (uintptr_t)entry;
	canary ^= (uintptr_t)entry->uptr;

	memcpy(entry->canary, &canary, sizeof(canary));

#if defined(KORE_USE_TASKS)
	pool_unlock(pool);
#endif

	return (entry->uptr);
}

void
kore_pool_put(struct kore_pool *pool, void *ptr)
{
	void				*base;
	u_int64_t			canary;
	struct kore_pool_entry		*entry;

#if defined(KORE_USE_TASKS)
	pool_lock(pool);
#endif

	if (kore_mem_guard) {
		base = (u_int8_t *)ptr - ((uintptr_t)ptr % pool->pagesz);
	} else {
		base = (u_int8_t *)ptr - sizeof(*entry);
	}

	entry = (struct kore_pool_entry *)base;

	if (entry->uptr != ptr) {
		fatal("%s: uptr mismatch %p != %p",
		    pool->name, entry->uptr, ptr);
	}

	memcpy(&canary, entry->canary, sizeof(canary));
	canary ^= (uintptr_t)entry;
	canary ^= (uintptr_t)ptr;

	if (canary != pool->canary)
		fatal("%s: memory corruption detected", pool->name);

	if (entry->state != POOL_ELEMENT_BUSY)
		fatal("%s: element %p was not busy", pool->name, ptr);

	entry->state = POOL_ELEMENT_FREE;
	entry->nextfree = pool->freelist;

	if (kore_mem_guard)
		pool_mark_entry_none(pool, entry);

	pool->freelist = entry;
#if defined(KORE_USE_TASKS)
	pool_unlock(pool);
#endif
}

static void
pool_grow(struct kore_pool *pool, size_t elms)
{
	size_t				i;
	u_int8_t			*base, *p;
	struct kore_pool_entry		*entry, *prev;

	prev = pool->freelist;

	if (kore_mem_guard == 0)
		base = kore_mmap_region(elms * (sizeof(*entry) + pool->elmlen));
	else
		base = NULL;

	for (i = 0; i < elms; i++) {
		if (kore_mem_guard) {
			base = kore_mmap_region(pool->memsz);
			p = base + (pool->memsz - pool->pagesz - pool->elmlen);
			entry = (struct kore_pool_entry *)base;
		} else {
			p = base + ((sizeof(*entry) + pool->elmlen) * i);
			entry = (struct kore_pool_entry *)p;
			p += sizeof(*entry);
		}

		entry->uptr = p;
		entry->nextfree = NULL;
		entry->state = POOL_ELEMENT_FREE;
		entry->canary = p + pool->uselen;

		if (prev != NULL) {
			prev->nextfree = entry;
			if (kore_mem_guard)
				pool_mark_entry_none(pool, prev);
		}

		prev = entry;

		if (pool->freelist == NULL)
			pool->freelist = entry;

		if (kore_mem_guard) {
			p += pool->elmlen;

			if (((uintptr_t)p % pool->pagesz) != 0)
				fatal("%s: misaligned page", __func__);

			if (mprotect(p, pool->pagesz, PROT_NONE) == -1)
				fatal("%s: mprotect: %s", __func__, errno_s);

			if (madvise(p, pool->pagesz, MADV_FREE) == -1)
				fatal("%s: madvise: %s", __func__, errno_s);
		}
	}

	if (prev != NULL && kore_mem_guard)
		pool_mark_entry_none(pool, prev);
}

static void
pool_mark_entry_none(struct kore_pool *pool, void *ptr)
{
	if (mprotect(ptr, pool->memsz - pool->pagesz, PROT_NONE) == -1)
		fatal("%s: mprotect: %s", __func__, errno_s);
}

static void
pool_mark_entry_rw(struct kore_pool *pool, void *ptr)
{
	if (mprotect(ptr, pool->memsz - pool->pagesz,
	    PROT_READ | PROT_WRITE) == -1)
		fatal("%s: mprotect: %s", __func__, errno_s);
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
