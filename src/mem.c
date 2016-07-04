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

#define KORE_MEM_MAGIC		0xd0d0
#define KORE_MEMSIZE(x)		\
	(*(u_int32_t *)((u_int8_t *)x - sizeof(u_int32_t)))
#define KORE_MEMINFO(x)		\
	(struct meminfo *)((u_int8_t *)x + KORE_MEMSIZE(x))

struct meminfo {
	u_int16_t		magic;
};

void
kore_mem_init(void)
{
}

void *
kore_malloc(size_t len)
{
	size_t			mlen;
	void			*ptr;
	struct meminfo		*mem;
	u_int8_t		*addr;
	u_int32_t		*plen;

	if (len == 0)
		fatal("kore_malloc(): zero size");

	mlen = sizeof(u_int32_t) + len + sizeof(struct meminfo);
	if ((ptr = calloc(1, mlen)) == NULL)
		fatal("kore_malloc(%zd): %d", len, errno);

	plen = (u_int32_t *)ptr;
	*plen = len;
	addr = (u_int8_t *)ptr + sizeof(u_int32_t);

	mem = KORE_MEMINFO(addr);
	mem->magic = KORE_MEM_MAGIC;

	return (addr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	struct meminfo		*mem;
	void			*nptr;

	if (len == 0)
		fatal("kore_realloc(): zero size");

	if (ptr == NULL) {
		nptr = kore_malloc(len);
	} else {
		mem = KORE_MEMINFO(ptr);
		if (mem->magic != KORE_MEM_MAGIC)
			fatal("kore_realloc(): magic boundary not found");

		nptr = kore_malloc(len);
		memcpy(nptr, ptr, MIN(len, KORE_MEMSIZE(ptr)));
		kore_mem_free(ptr);
	}

	return (nptr);
}

void *
kore_calloc(size_t memb, size_t len)
{
	if (memb == 0 || len == 0)
		fatal("kore_calloc(): zero size");
	if (SIZE_MAX / memb < len)
		fatal("kore_calloc(): memb * len > SIZE_MAX");

	return (kore_malloc(memb * len));
}

void
kore_mem_free(void *ptr)
{
	u_int8_t	*addr;
	struct meminfo	*mem;

	if (ptr == NULL)
		return;

	mem = KORE_MEMINFO(ptr);
	if (mem->magic != KORE_MEM_MAGIC)
		fatal("kore_mem_free(): magic boundary not found");

	addr = (u_int8_t *)ptr - sizeof(u_int32_t);
	free(addr);
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
