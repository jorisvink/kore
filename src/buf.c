/*
 * Copyright (c) 2013-2015 Joris Vink <joris@coders.se>
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

#include "kore.h"

struct kore_buf *
kore_buf_create(u_int32_t initial)
{
	struct kore_buf		*buf;

	buf = kore_malloc(sizeof(*buf));
	buf->data = kore_malloc(initial);
	buf->length = initial;
	buf->offset = 0;

	return (buf);
}

void
kore_buf_append(struct kore_buf *buf, const void *d, u_int32_t len)
{
	if ((buf->offset + len) >= buf->length) {
		buf->length += len + KORE_BUF_INCREMENT;
		buf->data = kore_realloc(buf->data, buf->length);
	}

	memcpy((buf->data + buf->offset), d, len);
	buf->offset += len;
}

void
kore_buf_appendb(struct kore_buf *buf, struct kore_buf *src)
{
	u_int8_t	*d;
	u_int32_t	len;

	d = kore_buf_release(src, &len);
	kore_buf_append(buf, d, len);
	kore_mem_free(d);
}

void
kore_buf_appendv(struct kore_buf *buf, const char *fmt, va_list args)
{
	int		l;
	char		*b, sb[BUFSIZ];

	l = vsnprintf(sb, sizeof(sb), fmt, args);
	if (l == -1)
		fatal("kore_buf_appendv(): vsnprintf error");

	if ((size_t)l >= sizeof(sb)) {
		l = vasprintf(&b, fmt, args);
		if (l == -1)
			fatal("kore_buf_appendv(): error or truncation");
	} else {
		b = sb;
	}

	kore_buf_append(buf, (u_int8_t *)b, l);
	if (b != sb)
		free(b);
}

void
kore_buf_appendf(struct kore_buf *buf, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	kore_buf_appendv(buf, fmt, args);
	va_end(args);
}

u_int8_t *
kore_buf_release(struct kore_buf *buf, u_int32_t *len)
{
	u_int8_t	*p;

	p = buf->data;
	*len = buf->offset;
	kore_mem_free(buf);

	return (p);
}

void
kore_buf_free(struct kore_buf *buf)
{
	kore_mem_free(buf->data);
	kore_mem_free(buf);
}

void
kore_buf_replace_string(struct kore_buf *b, char *src, void *dst, size_t len)
{
	u_int32_t	blen, off, off2;
	size_t		nlen, klen;
	char		*key, *end, *tmp, *p;

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

		kore_mem_free(b->data);
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
	memset(buf->data, 0, buf->length);
}
