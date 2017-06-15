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

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "kore.h"

struct kore_buf *
kore_buf_alloc(size_t initial)
{
	struct kore_buf		*buf;

	buf = kore_malloc(sizeof(*buf));
	kore_buf_init(buf, initial);
	buf->flags = KORE_BUF_OWNER_API;

	return (buf);
}

void
kore_buf_init(struct kore_buf *buf, size_t initial)
{
	if (initial > 0)
		buf->data = kore_malloc(initial);
	else
		buf->data = NULL;

	buf->length = initial;
	buf->offset = 0;
	buf->flags = 0;
}

void
kore_buf_cleanup(struct kore_buf *buf)
{
	kore_free(buf->data);
	buf->data = NULL;
	buf->offset = 0;
	buf->length = 0;
}

void
kore_buf_free(struct kore_buf *buf)
{
	kore_buf_cleanup(buf);
	if (buf->flags & KORE_BUF_OWNER_API)
		kore_free(buf);
}

void
kore_buf_append(struct kore_buf *buf, const void *d, size_t len)
{
	if ((buf->offset + len) < len)
		fatal("overflow in kore_buf_append");

	if ((buf->offset + len) > buf->length) {
		buf->length += len;
		buf->data = kore_realloc(buf->data, buf->length);
	}

	memcpy((buf->data + buf->offset), d, len);
	buf->offset += len;
}

void
kore_buf_appendv(struct kore_buf *buf, const char *fmt, va_list args)
{
	int		l;
	va_list		copy;
	char		*b, sb[BUFSIZ];

	va_copy(copy, args);

	l = vsnprintf(sb, sizeof(sb), fmt, args);
	if (l == -1)
		fatal("kore_buf_appendv(): vsnprintf error");

	if ((size_t)l >= sizeof(sb)) {
		l = vasprintf(&b, fmt, copy);
		if (l == -1)
			fatal("kore_buf_appendv(): error or truncation");
	} else {
		b = sb;
	}

	kore_buf_append(buf, b, l);
	if (b != sb)
		free(b);

	va_end(copy);
}

void
kore_buf_appendf(struct kore_buf *buf, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	kore_buf_appendv(buf, fmt, args);
	va_end(args);
}

char *
kore_buf_stringify(struct kore_buf *buf, size_t *len)
{
	char		c;

	if (len != NULL)
		*len = buf->offset;

	c = '\0';
	kore_buf_append(buf, &c, sizeof(c));

	return ((char *)buf->data);
}

u_int8_t *
kore_buf_release(struct kore_buf *buf, size_t *len)
{
	u_int8_t	*p;

	p = buf->data;
	*len = buf->offset;

	buf->data = NULL;
	kore_buf_free(buf);

	return (p);
}

void
kore_buf_replace_string(struct kore_buf *b, char *src, void *dst, size_t len)
{
	char		*key, *end, *tmp, *p;
	size_t		blen, off, off2, nlen, klen;

	off = 0;
	klen = strlen(src);
	for (;;) {
		blen = b->offset;
		nlen = blen + len;
		p = (char *)b->data;

		key = kore_mem_find(p + off, b->offset - off, src, klen);
		if (key == NULL)
			break;

		end = key + klen;
		off = key - p;
		off2 = ((char *)(b->data + b->offset) - end);

		tmp = kore_malloc(nlen);
		memcpy(tmp, p, off);
		if (dst != NULL)
			memcpy((tmp + off), dst, len);
		memcpy((tmp + off + len), end, off2);

		kore_free(b->data);
		b->data = (u_int8_t *)tmp;
		b->offset = off + len + off2;
		b->length = nlen;

		off = off + len;
	}
}

void
kore_buf_reset(struct kore_buf *buf)
{
	buf->offset = 0;
}
