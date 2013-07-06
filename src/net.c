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

#include <openssl/err.h>

void
net_send_queue(struct connection *c, u_int8_t *data, size_t len, int flags,
    struct netbuf **out, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	//kore_debug("net_send_queue(%p, %p, %d, %p)", c, data, len, cb);

	nb = (struct netbuf *)kore_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->flags = flags;
	nb->type = NETBUF_SEND;

	if (len > 0) {
		nb->buf = (u_int8_t *)kore_malloc(nb->len);
		memcpy(nb->buf, data, nb->len);
	} else {
		nb->buf = NULL;
	}

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
	if (out != NULL)
		*out = nb;
}

void
net_recv_queue(struct connection *c, size_t len, int flags,
    struct netbuf **out, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	//kore_debug("net_recv_queue(%p, %d, %p)", c, len, cb);

	nb = (struct netbuf *)kore_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->flags = flags;
	nb->type = NETBUF_RECV;
	nb->buf = (u_int8_t *)kore_malloc(nb->len);

	TAILQ_INSERT_TAIL(&(c->recv_queue), nb, list);
	if (out != NULL)
		*out = nb;
}

int
net_recv_expand(struct connection *c, struct netbuf *nb, size_t len,
    int (*cb)(struct netbuf *))
{
	//kore_debug("net_recv_expand(%p, %p, %d, %p)", c, nb, len, cb);

	if (nb->type != NETBUF_RECV) {
		kore_debug("net_recv_expand(): wrong netbuf type");
		return (KORE_RESULT_ERROR);
	}

	nb->cb = cb;
	nb->len += len;
	nb->buf = (u_int8_t *)kore_realloc(nb->buf, nb->len);
	TAILQ_INSERT_HEAD(&(c->recv_queue), nb, list);

	return (KORE_RESULT_OK);
}

int
net_send(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&(c->send_queue))) {
		nb = TAILQ_FIRST(&(c->send_queue));
		if (nb->len == 0) {
			kore_debug("net_send(): len is 0");
			return (KORE_RESULT_ERROR);
		}

		r = SSL_write(c->ssl,
		    (nb->buf + nb->offset), (nb->len - nb->offset));

		kore_debug("net_send(%ld/%ld bytes), progress with %d",
		    nb->offset, nb->len, r);

		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				c->flags &= ~CONN_WRITE_POSSIBLE;
				return (KORE_RESULT_OK);
			default:
				kore_debug("SSL_write(): %s", ssl_errno_s);
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

			if (nb->offset == nb->len) {
				if (nb->buf != NULL)
					kore_mem_free(nb->buf);
				kore_mem_free(nb);
			}

			if (r != KORE_RESULT_OK)
				return (r);
		}
	}

	return (KORE_RESULT_OK);
}

int
net_send_flush(struct connection *c)
{
	kore_debug("net_send_flush(%p)", c);

	while (!TAILQ_EMPTY(&(c->send_queue)) &&
	    (c->flags & CONN_WRITE_POSSIBLE)) {
		if (!net_send(c))
			return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

int
net_recv(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&(c->recv_queue))) {
		nb = TAILQ_FIRST(&(c->recv_queue));
		if (nb->cb == NULL) {
			kore_debug("kore_read_client(): nb->cb == NULL");
			return (KORE_RESULT_ERROR);
		}

		r = SSL_read(c->ssl,
		    (nb->buf + nb->offset), (nb->len - nb->offset));

		kore_debug("net_recv(%ld/%ld bytes), progress with %d",
		    nb->offset, nb->len, r);

		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
				c->flags &= ~CONN_READ_POSSIBLE;
				if (nb->flags & NETBUF_CALL_CB_ALWAYS &&
				    nb-> offset > 0)
					goto handle;
				return (KORE_RESULT_OK);
			case SSL_ERROR_WANT_WRITE:
				c->flags &= ~CONN_READ_POSSIBLE;
				return (KORE_RESULT_OK);
			default:
				kore_debug("SSL_read(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}
		}

		nb->offset += (size_t)r;
		if (nb->offset == nb->len) {
handle:
			r = nb->cb(nb);
			if (nb->offset == nb->len ||
			    (nb->flags & NETBUF_FORCE_REMOVE)) {
				TAILQ_REMOVE(&(c->recv_queue), nb, list);

				if (!(nb->flags & NETBUF_RETAIN)) {
					kore_mem_free(nb->buf);
					kore_mem_free(nb);
				}
			}

			if (r != KORE_RESULT_OK)
				return (r);
		}
	}

	return (KORE_RESULT_OK);
}

int
net_recv_flush(struct connection *c)
{
	kore_debug("net_recv_flush(%p)", c);

	while (!TAILQ_EMPTY(&(c->recv_queue)) &&
	    (c->flags & CONN_READ_POSSIBLE)) {
		if (!net_recv(c))
			return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
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
	u_int16_t	r;

	r = htons(n);
	memcpy(p, &r, sizeof(r));
}

void
net_write32(u_int8_t *p, u_int32_t n)
{
	u_int32_t	r;

	r = htonl(n);
	memcpy(p, &r, sizeof(r));
}
