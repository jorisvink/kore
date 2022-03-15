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

#include <sys/param.h>
#include <sys/types.h>

#include <stdlib.h>
#include <stdint.h>

#include "kore.h"

#define KORE_MEM_BLOCKS			11
#define KORE_MEM_BLOCK_SIZE_MAX		8192
#define KORE_MEM_BLOCK_PREALLOC		128

#define KORE_MEM_ALIGN		16
#define KORE_MEM_MAGIC		0xd0d0

#define KORE_MEM_TAGGED		0x0001

struct memsize {
	size_t			len;
	size_t			magic;
} __attribute__((packed));

struct meminfo {
	u_int16_t		flags;
	u_int16_t		magic;
} __attribute__((packed));

struct memblock {
	struct kore_pool	pool;
};

struct tag {
	void			*ptr;
	u_int32_t		id;
	TAILQ_ENTRY(tag)	list;
};

static inline struct memsize	*memsize(void *);
static inline struct meminfo	*meminfo(void *);
static size_t			memblock_index(size_t);

static TAILQ_HEAD(, tag)	tags;
static struct kore_pool		tag_pool;
static struct memblock		blocks[KORE_MEM_BLOCKS];

void
kore_mem_init(void)
{
	int		i, len;
	char		name[32];
	u_int32_t	size, elm, mlen;

	size = 8;
	TAILQ_INIT(&tags);
	kore_pool_init(&tag_pool, "tag_pool", sizeof(struct tag), 100);

	for (i = 0; i < KORE_MEM_BLOCKS; i++) {
		len = snprintf(name, sizeof(name), "block-%u", size);
		if (len == -1 || (size_t)len >= sizeof(name))
			fatal("kore_mem_init: snprintf");

		elm = (KORE_MEM_BLOCK_PREALLOC * 1024) / size;
		mlen = sizeof(struct memsize) + size +
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
	struct memsize		*size;
	u_int8_t		*addr;
	size_t			mlen, idx;

	if (len == 0)
		len = 8;

	if (len <= KORE_MEM_BLOCK_SIZE_MAX) {
		idx = memblock_index(len);
		ptr = kore_pool_get(&blocks[idx].pool);
	} else {
		mlen = sizeof(struct memsize) + len + sizeof(struct meminfo);
		if ((ptr = calloc(1, mlen)) == NULL)
			fatal("kore_malloc(%zu): %d", len, errno);
	}

	size = (struct memsize *)ptr;
	size->len = len;
	size->magic = KORE_MEM_MAGIC;

	addr = (u_int8_t *)ptr + sizeof(struct memsize);

	mem = (struct meminfo *)(addr + size->len);
	mem->flags = 0;
	mem->magic = KORE_MEM_MAGIC;

	return (addr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	struct memsize		*size;
	void			*nptr;

	if (ptr == NULL) {
		nptr = kore_malloc(len);
	} else {
		size = memsize(ptr);
		if (len == size->len)
			return (ptr);
		nptr = kore_malloc(len);
		memcpy(nptr, ptr, MIN(len, size->len));
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
	size_t			idx;
	struct meminfo		*mem;
	struct memsize		*size;
	u_int8_t		*addr;

	if (ptr == NULL)
		return;

	mem = meminfo(ptr);
	if (mem->flags & KORE_MEM_TAGGED) {
		kore_mem_untag(ptr);
		mem->flags &= ~KORE_MEM_TAGGED;
	}

	size = memsize(ptr);
	addr = (u_int8_t *)ptr - sizeof(struct memsize);

	if (size->len <= KORE_MEM_BLOCK_SIZE_MAX) {
		idx = memblock_index(size->len);
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

void *
kore_malloc_tagged(size_t len, u_int32_t tag)
{
	void		*ptr;

	ptr = kore_malloc(len);
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

static inline struct memsize *
memsize(void *ptr)
{
	struct memsize	*ms;

	ms = (struct memsize *)((u_int8_t *)ptr - sizeof(*ms));

	if (ms->magic != KORE_MEM_MAGIC)
		fatal("%s: bad memsize magic (0x%zx)", __func__, ms->magic);

	return (ms);
}

static inline struct meminfo *
meminfo(void *ptr)
{
	struct memsize	*ms;
	struct meminfo	*info;

	ms = memsize(ptr);
	info = (struct meminfo *)((u_int8_t *)ptr + ms->len);

	if (info->magic != KORE_MEM_MAGIC)
		fatal("%s: bad meminfo magic (0x%x)", __func__, info->magic);

	return (info);
}
