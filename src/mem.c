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

#include <sys/param.h>

#include <stdlib.h>
#include <stdint.h>

#include "kore.h"

#define KORE_MEM_BLOCKS			11
#define KORE_MEM_BLOCK_SIZE_MAX		8192
#define KORE_MEM_BLOCK_PREALLOC		128

#define KORE_MEM_ALIGN		(sizeof(size_t))
#define KORE_MEM_MAGIC		0xd0d0
#define KORE_MEMSIZE(x)		\
	(*(size_t *)((u_int8_t *)x - sizeof(size_t)))
#define KORE_MEMINFO(x)		\
	(struct meminfo *)((u_int8_t *)x + KORE_MEMSIZE(x))

struct meminfo {
	u_int16_t		magic;
};

struct memblock {
	struct kore_pool	pool;
};

static size_t			memblock_index(size_t);

static struct memblock		blocks[KORE_MEM_BLOCKS];

void
kore_mem_init(void)
{
	int		i, len;
	char		name[32];
	u_int32_t	size, elm, mlen;

	size = 8;

	for (i = 0; i < KORE_MEM_BLOCKS; i++) {
		len = snprintf(name, sizeof(name), "block-%u", size);
		if (len == -1 || (size_t)len >= sizeof(name))
			fatal("kore_mem_init: snprintf");

		elm = (KORE_MEM_BLOCK_PREALLOC * 1024) / size;
		mlen = sizeof(size_t) + size +
		    sizeof(struct meminfo) + KORE_MEM_ALIGN;
		mlen = mlen & ~(KORE_MEM_ALIGN - 1);

		kore_pool_init(&blocks[i].pool, name, mlen, elm);

		size = size << 1;
	}
}

void
kore_mem_cleanup(void)
{
	int		i;

	for (i = 0; i < KORE_MEM_BLOCKS; i++) {
		kore_pool_cleanup(&blocks[i].pool);
	}
}

void *
kore_malloc(size_t len)
{
	void			*ptr;
	struct meminfo		*mem;
	u_int8_t		*addr;
	size_t			mlen, idx, *plen;

	if (len == 0)
		len = 8;

	if (len <= KORE_MEM_BLOCK_SIZE_MAX) {
		idx = memblock_index(len);
		ptr = kore_pool_get(&blocks[idx].pool);
	} else {
		mlen = sizeof(size_t) + len + sizeof(struct meminfo);
		if ((ptr = calloc(1, mlen)) == NULL)
			fatal("kore_malloc(%zd): %d", len, errno);
	}

	plen = (size_t *)ptr;
	*plen = len;
	addr = (u_int8_t *)ptr + sizeof(size_t);

	mem = KORE_MEMINFO(addr);
	mem->magic = KORE_MEM_MAGIC;

	return (addr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	struct meminfo		*mem;
	void			*nptr;

	if (ptr == NULL) {
		nptr = kore_malloc(len);
	} else {
		if (len == KORE_MEMSIZE(ptr))
			return (ptr);
		mem = KORE_MEMINFO(ptr);
		if (mem->magic != KORE_MEM_MAGIC)
			fatal("kore_realloc(): magic boundary not found");

		nptr = kore_malloc(len);
		memcpy(nptr, ptr, MIN(len, KORE_MEMSIZE(ptr)));
		kore_free(ptr);
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
	ptr = kore_malloc(total);
	memset(ptr, 0, total);

	return (ptr);
}

void
kore_free(void *ptr)
{
	u_int8_t		*addr;
	struct meminfo		*mem;
	size_t			len, idx;

	if (ptr == NULL)
		return;

	mem = KORE_MEMINFO(ptr);
	if (mem->magic != KORE_MEM_MAGIC)
		fatal("kore_free(): magic boundary not found");

	len = KORE_MEMSIZE(ptr);
	addr = (u_int8_t *)ptr - sizeof(size_t);

	if (len <= KORE_MEM_BLOCK_SIZE_MAX) {
		idx = memblock_index(len);
		kore_pool_put(&blocks[idx].pool, addr);
	} else {
		free(addr);
	}
}

char *
kore_strdup(const char *str)
{
	size_t		len;
	char		*nstr;

	len = strlen(str) + 1;
	nstr = kore_malloc(len);
	(void)kore_strlcpy(nstr, str, len);

	return (nstr);
}

static size_t
memblock_index(size_t len)
{
	size_t		mlen, idx;

	idx = 0;
	mlen = 8;
	while (mlen < len) {
		idx++;
		mlen = mlen << 1;
	}

	if (idx > (KORE_MEM_BLOCKS - 1))
		fatal("kore_malloc: idx too high");

	return (idx);
}
