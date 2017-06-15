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

#if defined(__linux__)
#include <endian.h>
#elif defined(__MACH__)
#include <libkern/OSByteOrder.h>
#define htobe64(x)	OSSwapHostToBigInt64(x)
#define be64toh(x)	OSSwapBigToHostInt64(x)
#else
#include <sys/endian.h>
#endif

#include "kore.h"

struct kore_pool		nb_pool;

void
net_init(void)
{
	kore_pool_init(&nb_pool, "nb_pool", sizeof(struct netbuf), 1000);
}

void
net_cleanup(void)
{
	kore_debug("net_cleanup()");
	kore_pool_cleanup(&nb_pool);
}

void
net_send_queue(struct connection *c, const void *data, size_t len)
{
	const u_int8_t		*d;
	struct netbuf		*nb;
	size_t			avail;

	kore_debug("net_send_queue(%p, %p, %zu)", c, data, len);

	d = data;
	nb = TAILQ_LAST(&(c->send_queue), netbuf_head);
	if (nb != NULL && !(nb->flags & NETBUF_IS_STREAM) &&
	    nb->b_len < nb->m_len) {
		avail = nb->m_len - nb->b_len;
		if (len < avail) {
			memcpy(nb->buf + nb->b_len, d, len);
			nb->b_len += len;
			return;
		} else {
			memcpy(nb->buf + nb->b_len, d, avail);
			nb->b_len += avail;

			len -= avail;
			d += avail;
			if (len == 0)
				return;
		}
	}

	nb = kore_pool_get(&nb_pool);
	nb->flags = 0;
	nb->cb = NULL;
	nb->owner = c;
	nb->s_off = 0;
	nb->b_len = len;
	nb->type = NETBUF_SEND;

	if (nb->b_len < NETBUF_SEND_PAYLOAD_MAX)
		nb->m_len = NETBUF_SEND_PAYLOAD_MAX;
	else
		nb->m_len = nb->b_len;

	nb->buf = kore_malloc(nb->m_len);
	if (len > 0)
		memcpy(nb->buf, d, nb->b_len);

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
}

void
net_send_stream(struct connection *c, void *data, size_t len,
    int (*cb)(struct netbuf *), struct netbuf **out)
{
	struct netbuf		*nb;

	kore_debug("net_send_stream(%p, %p, %zu)", c, data, len);

	nb = kore_pool_get(&nb_pool);
	nb->cb = cb;
	nb->owner = c;
	nb->s_off = 0;
	nb->buf = data;
	nb->b_len = len;
	nb->m_len = nb->b_len;
	nb->type = NETBUF_SEND;
	nb->flags  = NETBUF_IS_STREAM;

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
	if (out != NULL)
		*out = nb;
}

void
net_recv_reset(struct connection *c, size_t len, int (*cb)(struct netbuf *))
{
	kore_debug("net_recv_reset(): %p %zu", c, len);

	if (c->rnb->type != NETBUF_RECV)
		fatal("net_recv_reset(): wrong netbuf type");

	c->rnb->cb = cb;
	c->rnb->s_off = 0;
	c->rnb->b_len = len;

	if (c->rnb->b_len <= c->rnb->m_len &&
	    c->rnb->m_len < (NETBUF_SEND_PAYLOAD_MAX / 2))
		return;

	kore_free(c->rnb->buf);
	c->rnb->m_len = len;
	c->rnb->buf = kore_malloc(c->rnb->m_len);
}

void
net_recv_queue(struct connection *c, size_t len, int flags,
    int (*cb)(struct netbuf *))
{
	kore_debug("net_recv_queue(): %p %zu %d", c, len, flags);

	if (c->rnb != NULL)
		fatal("net_recv_queue(): called incorrectly for %p", c);

	c->rnb = kore_pool_get(&nb_pool);
	c->rnb->cb = cb;
	c->rnb->owner = c;
	c->rnb->s_off = 0;
	c->rnb->b_len = len;
	c->rnb->m_len = len;
	c->rnb->extra = NULL;
	c->rnb->flags = flags;
	c->rnb->type = NETBUF_RECV;
	c->rnb->buf = kore_malloc(c->rnb->b_len);
}

void
net_recv_expand(struct connection *c, size_t len, int (*cb)(struct netbuf *))
{
	kore_debug("net_recv_expand(): %p %d", c, len);

	if (c->rnb->type != NETBUF_RECV)
		fatal("net_recv_expand(): wrong netbuf type");

	c->rnb->cb = cb;
	c->rnb->b_len += len;
	c->rnb->m_len = c->rnb->b_len;
	c->rnb->buf = kore_realloc(c->rnb->buf, c->rnb->b_len);
}

int
net_send(struct connection *c)
{
	size_t		r, len, smin;

	c->snb = TAILQ_FIRST(&(c->send_queue));
	if (c->snb->b_len != 0) {
		smin = c->snb->b_len - c->snb->s_off;
		len = MIN(NETBUF_SEND_PAYLOAD_MAX, smin);

		if (!c->write(c, len, &r))
			return (KORE_RESULT_ERROR);
		if (!(c->flags & CONN_WRITE_POSSIBLE))
			return (KORE_RESULT_OK);

		c->snb->s_off += r;
		c->snb->flags &= ~NETBUF_MUST_RESEND;
	}

	if (c->snb->s_off == c->snb->b_len ||
	    (c->snb->flags & NETBUF_FORCE_REMOVE)) {
		net_remove_netbuf(&(c->send_queue), c->snb);
		c->snb = NULL;
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

	if ((c->flags & CONN_CLOSE_EMPTY) && TAILQ_EMPTY(&(c->send_queue)))
		kore_connection_disconnect(c);

	return (KORE_RESULT_OK);
}

int
net_recv_flush(struct connection *c)
{
	size_t		r;

	kore_debug("net_recv_flush(%p)", c);

	if (c->rnb == NULL)
		return (KORE_RESULT_OK);

	while (c->flags & CONN_READ_POSSIBLE) {
		if (!c->read(c, &r))
			return (KORE_RESULT_ERROR);
		if (!(c->flags & CONN_READ_POSSIBLE))
			break;

		c->rnb->s_off += r;
		if (c->rnb->s_off == c->rnb->b_len ||
		    (c->rnb->flags & NETBUF_CALL_CB_ALWAYS)) {
			r = c->rnb->cb(c->rnb);
			if (r != KORE_RESULT_OK)
				return (r);
		}
	}

	return (KORE_RESULT_OK);
}

void
net_remove_netbuf(struct netbuf_head *list, struct netbuf *nb)
{
	kore_debug("net_remove_netbuf(%p, %p)", list, nb);

	if (nb->type == NETBUF_RECV)
		fatal("net_remove_netbuf(): cannot remove recv netbuf");

	if (nb->flags & NETBUF_MUST_RESEND) {
		kore_debug("retaining %p (MUST_RESEND)", nb);
		nb->flags |= NETBUF_FORCE_REMOVE;
		return;
	}

	if (!(nb->flags & NETBUF_IS_STREAM)) {
		kore_free(nb->buf);
	} else if (nb->cb != NULL) {
		(void)nb->cb(nb);
	}

	TAILQ_REMOVE(list, nb, list);
	kore_pool_put(&nb_pool, nb);
}

#if !defined(KORE_NO_TLS)
int
net_write_tls(struct connection *c, size_t len, size_t *written)
{
	int		r;

	if (len > INT_MAX)
		return (KORE_RESULT_ERROR);

	ERR_clear_error();
	r = SSL_write(c->ssl, (c->snb->buf + c->snb->s_off), len);
	if (c->tls_reneg > 1)
		return (KORE_RESULT_ERROR);

	if (r <= 0) {
		r = SSL_get_error(c->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			c->snb->flags |= NETBUF_MUST_RESEND;
			c->flags &= ~CONN_WRITE_POSSIBLE;
			return (KORE_RESULT_OK);
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case EINTR:
				*written = 0;
				return (KORE_RESULT_OK);
			case EAGAIN:
				c->snb->flags |= NETBUF_MUST_RESEND;
				c->flags &= ~CONN_WRITE_POSSIBLE;
				return (KORE_RESULT_OK);
			default:
				break;
			}
			/* FALLTHROUGH */
		default:
			kore_debug("SSL_write(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	*written = (size_t)r;

	return (KORE_RESULT_OK);
}

int
net_read_tls(struct connection *c, size_t *bytes)
{
	int		r;

	ERR_clear_error();
	r = SSL_read(c->ssl, (c->rnb->buf + c->rnb->s_off),
	    (c->rnb->b_len - c->rnb->s_off));

	if (c->tls_reneg > 1)
		return (KORE_RESULT_ERROR);

	if (r <= 0) {
		r = SSL_get_error(c->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			c->flags &= ~CONN_READ_POSSIBLE;
			return (KORE_RESULT_OK);
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case EINTR:
				*bytes = 0;
				return (KORE_RESULT_OK);
			case EAGAIN:
				c->snb->flags |= NETBUF_MUST_RESEND;
				c->flags &= ~CONN_WRITE_POSSIBLE;
				return (KORE_RESULT_OK);
			default:
				break;
			}
			/* FALLTHROUGH */
		default:
			kore_debug("SSL_read(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	*bytes = (size_t)r;

	return (KORE_RESULT_OK);
}
#endif

int
net_write(struct connection *c, size_t len, size_t *written)
{
	ssize_t		r;

	r = write(c->fd, (c->snb->buf + c->snb->s_off), len);
	if (r <= -1) {
		switch (errno) {
		case EINTR:
			*written = 0;
			return (KORE_RESULT_OK);
		case EAGAIN:
			c->flags &= ~CONN_WRITE_POSSIBLE;
			return (KORE_RESULT_OK);
		default:
			kore_debug("write: %s", errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	*written = (size_t)r;

	return (KORE_RESULT_OK);
}

int
net_read(struct connection *c, size_t *bytes)
{
	ssize_t		r;

	r = read(c->fd, (c->rnb->buf + c->rnb->s_off),
	    (c->rnb->b_len - c->rnb->s_off));
	if (r <= 0) {
		switch (errno) {
		case EINTR:
			*bytes = 0;
			return (KORE_RESULT_OK);
		case EAGAIN:
			c->flags &= ~CONN_READ_POSSIBLE;
			return (KORE_RESULT_OK);
		default:
			kore_debug("read(): %s", errno_s);
			return (KORE_RESULT_ERROR);
		}
	}

	*bytes = (size_t)r;

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

u_int64_t
net_read64(u_int8_t *b)
{
	u_int64_t	r;

	r = *(u_int64_t *)b;
	return (be64toh(r));
}

void
net_write64(u_int8_t *p, u_int64_t n)
{
	u_int64_t	r;

	r = htobe64(n);
	memcpy(p, &r, sizeof(r));
}
