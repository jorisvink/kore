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
 * The memory facitilies such as kore_malloc / kore_calloc are all
 * based on the kore pool system as long as the allocations are
 * below 8192 bytes.
 *
 * Anything over 8192 bytes will get an mmap() allocation instead
 * that does not benefit from the protections offered by the kore_pool API.
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <stdint.h>

#include "kore.h"

#define KORE_MEM_POOLS			11
#define KORE_MEM_POOLS_PREALLOC		32
#define KORE_MEM_POOLS_SIZE_MAX		8192

#define KORE_MEM_TAGGED			0x0001

struct meminfo {
	size_t			len;
	u_int16_t		flags;
};

struct tag {
	void			*ptr;
	u_int32_t		id;
	TAILQ_ENTRY(tag)	list;
};

static inline struct meminfo	*meminfo(void *);
static void			*mem_alloc(size_t);
static size_t			mem_index(size_t);

static TAILQ_HEAD(, tag)	tags;
static struct kore_pool		tag_pool;
static struct kore_pool		mempools[KORE_MEM_POOLS];

void
kore_mem_init(void)
{
	const char	*opt;
	int		i, len;
	char		name[32];
	size_t		size, elm, mlen;

	if ((opt = getenv("KORE_MEM_GUARD")) != NULL && !strcmp(opt, "1"))
		kore_mem_guard = 1;

	size = 8;
	TAILQ_INIT(&tags);
	kore_pool_init(&tag_pool, "tag_pool", sizeof(struct tag), 4);

	for (i = 0; i < KORE_MEM_POOLS; i++) {
		len = snprintf(name, sizeof(name), "block-%zu", size);
		if (len == -1 || (size_t)len >= sizeof(name))
			fatal("kore_mem_init: snprintf");

		elm = (KORE_MEM_POOLS_PREALLOC * 1024) / size;
		mlen = sizeof(struct meminfo) + size;

		kore_pool_init(&mempools[i], name, mlen, elm);

		size = size << 1;
	}
}

void
kore_mem_cleanup(void)
{
	int		i;

	for (i = 0; i < KORE_MEM_POOLS; i++) {
		kore_pool_cleanup(&mempools[i]);
	}
}

void *
kore_mmap_region(size_t len)
{
	void		*ptr;

	if ((ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
	    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		fatal("%s: mmap: %s", __func__, errno_s);

	return (ptr);
}

void *
kore_malloc(size_t len)
{
	return (mem_alloc(len));
}

void *
kore_realloc(void *ptr, size_t len)
{
	struct meminfo		*mem;
	void			*nptr;

	if (ptr == NULL) {
		nptr = mem_alloc(len);
	} else {
		mem = meminfo(ptr);
		if (len <= mem->len)
			return (ptr);
		nptr = mem_alloc(len);
		memcpy(nptr, ptr, mem->len);
		kore_free_zero(ptr);
	}

	return (nptr);
}

void *
kore_calloc(size_t memb, size_t len)
{
	void		*ptr;
	size_t		total;

	if (SIZE_MAX / memb < len)
		fatal("kore_calloc(): memb * len > SIZE_MAX");

	total = memb * len;
	ptr = mem_alloc(total);
	memset(ptr, 0, total);

	return (ptr);
}

void
kore_free_zero(void *ptr)
{
	struct meminfo		*mem;

	if (ptr == NULL)
		return;

	mem = meminfo(ptr);
	kore_mem_zero(ptr, mem->len);

	kore_free(ptr);
}

void
kore_free(void *ptr)
{
	size_t			idx;
	struct meminfo		*mem;
	u_int8_t		*addr;

	if (ptr == NULL)
		return;

	mem = meminfo(ptr);
	if (mem->flags & KORE_MEM_TAGGED) {
		kore_mem_untag(ptr);
		mem->flags &= ~KORE_MEM_TAGGED;
	}

	addr = (u_int8_t *)ptr - sizeof(struct meminfo);

	if (mem->len <= KORE_MEM_POOLS_SIZE_MAX) {
		idx = mem_index(mem->len);
		kore_pool_put(&mempools[idx], addr);
	} else {
		if (munmap(addr, sizeof(*mem) + mem->len) == -1)
			fatal("%s: munmap: %s", __func__, errno_s);
	}
}

char *
kore_strdup(const char *str)
{
	size_t		len;
	char		*nstr;

	len = strlen(str) + 1;
	nstr = mem_alloc(len);
	(void)kore_strlcpy(nstr, str, len);

	return (nstr);
}

void *
kore_malloc_tagged(size_t len, u_int32_t tag)
{
	void		*ptr;

	ptr = mem_alloc(len);
	kore_mem_tag(ptr, tag);

	return (ptr);
}

void
kore_mem_tag(void *ptr, u_int32_t id)
{
	struct tag		*tag;
	struct meminfo		*mem;

	if (kore_mem_lookup(id) != NULL)
		fatal("kore_mem_tag: tag %u taken", id);

	mem = meminfo(ptr);
	mem->flags |= KORE_MEM_TAGGED;

	tag = kore_pool_get(&tag_pool);
	tag->id = id;
	tag->ptr = ptr;

	TAILQ_INSERT_TAIL(&tags, tag, list);
}

void
kore_mem_untag(void *ptr)
{
	struct tag		*tag;

	TAILQ_FOREACH(tag, &tags, list) {
		if (tag->ptr == ptr) {
			TAILQ_REMOVE(&tags, tag, list);
			kore_pool_put(&tag_pool, tag);
			break;
		}
	}
}

void *
kore_mem_lookup(u_int32_t id)
{
	struct tag		*tag;

	TAILQ_FOREACH(tag, &tags, list) {
		if (tag->id == id)
			return (tag->ptr);
	}

	return (NULL);
}

/* Best effort to try and let the compiler not optimize this call away. */
void
kore_mem_zero(void *ptr, size_t len)
{
	volatile char	*p;

	p = (volatile char *)ptr;

	if (p != NULL) {
		while (len-- > 0)
			*(p)++ = 0x00;
	}
}

static void *
mem_alloc(size_t len)
{
	void			*ptr;
	struct meminfo		*mem;
	size_t			mlen, idx;

	if (len == 0)
		len = 8;

	if (len <= KORE_MEM_POOLS_SIZE_MAX) {
		idx = mem_index(len);
		ptr = kore_pool_get(&mempools[idx]);
	} else {
		mlen = sizeof(struct meminfo) + len;
		ptr = kore_mmap_region(mlen);
	}

	mem = (struct meminfo *)ptr;
	mem->len = len;
	mem->flags = 0;

	return ((u_int8_t *)ptr + sizeof(struct meminfo));
}

static size_t
mem_index(size_t len)
{
	size_t		mlen, idx;

	idx = 0;
	mlen = 8;
	while (mlen < len) {
		idx++;
		mlen = mlen << 1;
	}

	if (idx > (KORE_MEM_POOLS - 1))
		fatal("mem_index: idx too high");

	return (idx);
}

static inline struct meminfo *
meminfo(void *ptr)
{
	return ((struct meminfo *)((u_int8_t *)ptr - sizeof(struct meminfo)));
}
