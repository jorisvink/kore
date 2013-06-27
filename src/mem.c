/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <regex.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

#define KORE_MEM_MAGIC		0xd0d0
#define KORE_MEMINFO(x)		\
	((struct meminfo *)((u_int8_t *)x - sizeof(struct meminfo)))

struct meminfo {
	u_int32_t		id;
	u_int32_t		len;
	u_int32_t		clen;
	u_int64_t		t;
	TAILQ_ENTRY(meminfo)	list;
	u_int16_t		magic;
	u_int8_t		*addr;
};

static u_int64_t		memid;
u_int32_t			meminuse;
TAILQ_HEAD(, meminfo)		memused;

void
kore_mem_init(void)
{
	memid = 0;
	meminuse = 0;
	TAILQ_INIT(&memused);
}

void *
kore_malloc(size_t len)
{
	size_t			mlen;
	struct meminfo		*mem;

	mlen = sizeof(struct meminfo) + len;
	if ((mem = (struct meminfo *)malloc(mlen)) == NULL)
		fatal("kore_malloc(%d): %d", len, errno);

	mem->clen = len;
	mem->len = mlen;
	mem->id = memid++;
	mem->t = kore_time_ms();
	mem->addr = (u_int8_t *)mem + sizeof(struct meminfo);
	mem->magic = KORE_MEM_MAGIC;
	TAILQ_INSERT_TAIL(&memused, mem, list);
	if ((u_int8_t *)mem != mem->addr - sizeof(struct meminfo))
		fatal("kore_malloc(): addr offset is wrong");

	meminuse += len;
	memset(mem->addr, '\0', mem->clen);

	return (mem->addr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	struct meminfo		*mem;
	void			*nptr;

	mem = KORE_MEMINFO(ptr);
	if (mem->magic != KORE_MEM_MAGIC)
		fatal("kore_realloc(): magic boundary not found");

	nptr = kore_malloc(len);
	memcpy(nptr, mem->addr, mem->clen);
	kore_mem_free(mem);

	mem = (struct meminfo *)nptr - sizeof(*mem);
	return (mem->addr);
}

void *
kore_calloc(size_t memb, size_t len)
{
	return (kore_malloc(memb * len));
}

void
kore_mem_free(void *ptr)
{
	struct meminfo	*mem;

	mem = KORE_MEMINFO(ptr);
	if (mem->magic != KORE_MEM_MAGIC)
		fatal("kore_mem_free(): magic boundary not found");

	meminuse -= mem->clen;
	TAILQ_REMOVE(&memused, mem, list);
	free(mem);
}

char *
kore_strdup(const char *str)
{
	size_t		len;
	char		*nstr;

	len = strlen(str) + 1;
	nstr = (char *)kore_malloc(len);
	kore_strlcpy(nstr, str, len);

	return (nstr);
}
