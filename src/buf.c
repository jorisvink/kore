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

#include "kore.h"

struct kore_buf *
kore_buf_create(u_int32_t initial)
{
	struct kore_buf		*buf;

	buf = (struct kore_buf *)kore_malloc(sizeof(*buf));
	buf->data = (u_int8_t *)kore_malloc(initial);
	buf->length = initial;
	buf->offset = 0;

	return (buf);
}

void
kore_buf_append(struct kore_buf *buf, u_int8_t *d, u_int32_t len)
{
	if ((buf->offset + len) >= buf->length) {
		buf->length += len + KORE_BUF_INCREMENT;
		buf->data = (u_int8_t *)kore_realloc(buf->data, buf->length);
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
}

void
kore_buf_appendv(struct kore_buf *buf, struct buf_vec *v, u_int16_t count)
{
	u_int16_t		i;
	struct buf_vec		*p;

	p = v;
	for (i = 0; i < count; i++) {
		kore_buf_append(buf, p->data, p->length);
		p++;
	}
}

void
kore_buf_appendf(struct kore_buf *buf, const char *fmt, ...)
{
	va_list		args;
	char		b[2048];

	va_start(args, fmt);
	vsnprintf(b, sizeof(b), fmt, args);
	va_end(args);

	kore_buf_append(buf, (u_int8_t *)b, strlen(b));
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
