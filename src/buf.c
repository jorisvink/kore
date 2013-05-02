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

#include "buf.h"
#include "spdy.h"
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

u_int8_t *
kore_buf_release(struct kore_buf *buf, u_int32_t *len)
{
	u_int8_t	*p;

	p = buf->data;
	*len = buf->offset;
	free(buf);

	return (p);
}
