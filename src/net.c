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
#include <sys/epoll.h>

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

#include "spdy.h"
#include "kore.h"

int
net_send_queue(struct connection *c, u_int8_t *data, size_t len,
    int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	kore_log("net_send_queue(%p, %p, %d, %p)", c, data, len, cb);

	nb = (struct netbuf *)kore_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->retain = 0;
	nb->type = NETBUF_SEND;
	nb->buf = (u_int8_t *)kore_malloc(nb->len);
	memcpy(nb->buf, data, nb->len);

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
	return (net_send(c));
}

int
net_recv_queue(struct connection *c, size_t len, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	kore_log("net_recv_queue(%p, %d, %p)", c, len, cb);

	nb = (struct netbuf *)kore_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->retain = 0;
	nb->type = NETBUF_RECV;
	nb->buf = (u_int8_t *)kore_malloc(nb->len);

	TAILQ_INSERT_TAIL(&(c->recv_queue), nb, list);
	return (net_recv(c));
}

int
net_recv_expand(struct connection *c, struct netbuf *nb, size_t len,
    int (*cb)(struct netbuf *))
{
	kore_log("net_recv_expand(%p, %p, %d, %p)", c, nb, len, cb);

	if (nb->type != NETBUF_RECV) {
		kore_log("net_recv_expand(): wrong netbuf type");
		return (KORE_RESULT_ERROR);
	}

	nb->cb = cb;
	nb->len += len;
	nb->buf = (u_int8_t *)kore_realloc(nb->buf, nb->len);
	TAILQ_INSERT_HEAD(&(c->recv_queue), nb, list);

	return (net_recv(c));
}

int
net_send(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	kore_log("net_send(%p)", c);

	if (TAILQ_EMPTY(&(c->send_queue)))
		return (KORE_RESULT_OK);

	nb = TAILQ_FIRST(&(c->send_queue));
	kore_log("nb is %p (%d/%d bytes)", nb, nb->offset, nb->len);
	r = SSL_write(c->ssl, (nb->buf + nb->offset), (nb->len - nb->offset));
	kore_log("SSL_write(): %d bytes", r);
	if (r <= 0) {
		r = SSL_get_error(c->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
			kore_log("ssl_want_read on net_send()");
			return (KORE_RESULT_OK);
		case SSL_ERROR_WANT_WRITE:
			kore_log("ssl_want_write on net_send()");
			return (KORE_RESULT_OK);
		default:
			kore_log("SSL_write(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	nb->offset += (size_t)r;
	if (nb->offset == nb->len) {
		TAILQ_REMOVE(&(c->send_queue), nb, list);

		if (nb->cb != NULL)
			r = nb->cb(nb);
		else
			r = KORE_RESULT_OK;

		free(nb->buf);
		free(nb);
	} else {
		r = KORE_RESULT_OK;
	}

	return (r);
}

int
net_recv(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	kore_log("net_recv(%p)", c);

	if (TAILQ_EMPTY(&(c->recv_queue)))
		return (KORE_RESULT_ERROR);

	nb = TAILQ_FIRST(&(c->recv_queue));
	kore_log("nb is %p (%d/%d bytes)", nb, nb->offset, nb->len);
	r = SSL_read(c->ssl, (nb->buf + nb->offset), (nb->len - nb->offset));
	kore_log("SSL_read(): %d bytes", r);
	if (r <= 0) {
		r = SSL_get_error(c->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
			kore_log("ssl_want_read on net_recv()");
			return (KORE_RESULT_OK);
		case SSL_ERROR_WANT_WRITE:
			kore_log("ssl_want_write on net_recv()");
			return (KORE_RESULT_OK);
		default:
			kore_log("SSL_read(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	nb->offset += (size_t)r;
	kore_log("read %d out of %d bytes", nb->offset, nb->len);
	if (nb->offset == nb->len) {
		if (nb->cb == NULL) {
			kore_log("kore_read_client(): nb->cb == NULL");
			return (KORE_RESULT_ERROR);
		}

		nb->retain++;
		TAILQ_REMOVE(&(c->recv_queue), nb, list);
		r = nb->cb(nb);
		nb->retain--;

		if (nb->retain == 0 && nb->offset == nb->len) {
			free(nb->buf);
			free(nb);
		}
	} else {
		r = KORE_RESULT_OK;
	}

	return (r);
}

u_int16_t
net_read16(u_int8_t *b)
{
	u_int16_t	r;

	r = *(u_int16_t *)b;
	return (ntohs(r));
}

u_int32_t
net_read32(u_int8_t *b)
{
	u_int32_t	r;

	r = *(u_int32_t *)b;
	return (ntohl(r));
}

void
net_write16(u_int8_t *p, u_int16_t n)
{
	*p = htons(n);
}

void
net_write32(u_int8_t *p, u_int32_t n)
{
	*p = htonl(n);
}
