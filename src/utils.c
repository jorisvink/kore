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
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

void *
kore_malloc(size_t len)
{
	void		*ptr;

	if ((ptr = malloc(len)) == NULL)
		fatal("kore_malloc(%d): %d", len, errno);

	return (ptr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	void		*nptr;

	if ((nptr = realloc(ptr, len)) == NULL)
		fatal("kore_realloc(%p, %d): %d", ptr, len, errno);

	return (nptr);
}

void *
kore_calloc(size_t memb, size_t len)
{
	void		*ptr;

	if ((ptr = calloc(memb, len)) == NULL)
		fatal("kore_calloc(%d, %d): %d", memb, len, errno);

	return (ptr);
}

char *
kore_strdup(const char *str)
{
	char		*nstr;

	if ((nstr = strdup(str)) == NULL)
		fatal("kore_strdup(): %d", errno);

	return (nstr);
}

void
kore_log_internal(char *file, int line, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("%s:%d - %s\n", file, line, buf);
}

void
kore_strlcpy(char *dst, const char *src, size_t len)
{
	char		*d = dst;
	const char	*s = src;

	while ((*d++ = *s++) != '\0') {
		if (d == (dst + len - 1)) {
			*d = '\0';
			break;
		}
	}
}

void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("error: %s\n", buf);
	exit(1);
}
