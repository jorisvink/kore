/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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
#include <sys/socket.h>
#include <sys/types.h>

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
	u_int32_t	elm;

	/* Add some overhead so we don't roll over for internal items. */
	elm = worker_max_connections + 10;
	kore_pool_init(&nb_pool, "nb_pool", sizeof(struct netbuf), elm);
}

void
net_cleanup(void)
{
	kore_pool_cleanup(&nb_pool);
}

struct netbuf *
net_netbuf_get(void)
{
	struct netbuf	*nb;

	nb = kore_pool_get(&nb_pool);

	nb->cb = NULL;
	nb->buf = NULL;
	nb->owner = NULL;
	nb->extra = NULL;
	nb->file_ref = NULL;

	nb->type = 0;
	nb->s_off = 0;
	nb->b_len = 0;
	nb->m_len = 0;
	nb->flags = 0;

#if defined(KORE_USE_PLATFORM_SENDFILE)
	nb->fd_off = -1;
	nb->fd_len = -1;
#endif

	return (nb);
}

void
net_send_queue(struct connection *c, const void *data, size_t len)
{
	const u_int8_t		*d;
	struct netbuf		*nb;
	size_t			avail;

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

	nb = net_netbuf_get();

	nb->owner = c;
	nb->b_len = len;
	nb->type = NETBUF_SEND;

	if (nb->b_len < NETBUF_SEND_PAYLOAD_MAX)
		nb->m_len = NETBUF_SEND_PAYLOAD_MAX;
	else
		nb->m_len = nb->b_len;

	nb->buf = kore_malloc(nb->m_len);
	memcpy(nb->buf, d, nb->b_len);

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
}

void
net_send_stream(struct connection *c, void *data, size_t len,
    int (*cb)(struct netbuf *), struct netbuf **out)
{
	struct netbuf		*nb;

	nb = net_netbuf_get();
	nb->cb = cb;
	nb->owner = c;
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
net_send_fileref(struct connection *c, struct kore_fileref *ref)
{
	struct netbuf		*nb;

	nb = net_netbuf_get();
	nb->owner = c;
	nb->file_ref = ref;
	nb->type = NETBUF_SEND;
	nb->flags = NETBUF_IS_FILEREF;

#if defined(KORE_USE_PLATFORM_SENDFILE)
	if (c->owner->server->tls == 0) {
		nb->fd_off = 0;
		nb->fd_len = ref->size;
	} else {
		nb->buf = ref->base;
		nb->b_len = ref->size;
		nb->m_len = nb->b_len;
		nb->flags |= NETBUF_IS_STREAM;
	}
#else
	nb->buf = ref->base;
	nb->b_len = ref->size;
	nb->m_len = nb->b_len;
	nb->flags |= NETBUF_IS_STREAM;
#endif

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
}

void
net_recv_reset(struct connection *c, size_t len, int (*cb)(struct netbuf *))
{
	c->rnb->cb = cb;
	c->rnb->s_off = 0;
	c->rnb->b_len = len;

	if (c->rnb->buf != NULL && c->rnb->b_len <= c->rnb->m_len &&
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
	if (c->rnb != NULL)
		fatal("net_recv_queue(): called incorrectly");

	c->rnb = net_netbuf_get();
	c->rnb->cb = cb;
	c->rnb->owner = c;
	c->rnb->b_len = len;
	c->rnb->m_len = len;
	c->rnb->flags = flags;
	c->rnb->type = NETBUF_RECV;
	c->rnb->buf = kore_malloc(c->rnb->b_len);
}

void
net_recv_expand(struct connection *c, size_t len, int (*cb)(struct netbuf *))
{
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

#if defined(KORE_USE_PLATFORM_SENDFILE)
	if ((c->snb->flags & NETBUF_IS_FILEREF) &&
	    !(c->snb->flags & NETBUF_IS_STREAM)) {
		return (kore_platform_sendfile(c, c->snb));
	}
#endif

	if (c->snb->b_len != 0) {
		smin = c->snb->b_len - c->snb->s_off;
		len = MIN(NETBUF_SEND_PAYLOAD_MAX, smin);

		if (!c->write(c, len, &r))
			return (KORE_RESULT_ERROR);
		if (!(c->evt.flags & KORE_EVENT_WRITE))
			return (KORE_RESULT_OK);

		c->snb->s_off += r;
		c->snb->flags &= ~NETBUF_MUST_RESEND;
	}

	if (c->snb->s_off == c->snb->b_len ||
	    (c->snb->flags & NETBUF_FORCE_REMOVE)) {
		net_remove_netbuf(c, c->snb);
		c->snb = NULL;
	}

	return (KORE_RESULT_OK);
}

int
net_send_flush(struct connection *c)
{
	while (!TAILQ_EMPTY(&(c->send_queue)) &&
	    (c->evt.flags & KORE_EVENT_WRITE)) {
		if (!net_send(c))
			return (KORE_RESULT_ERROR);
	}

	if ((c->flags & CONN_CLOSE_EMPTY) && TAILQ_EMPTY(&(c->send_queue))) {
		kore_connection_disconnect(c);
	}

	return (KORE_RESULT_OK);
}

int
net_recv_flush(struct connection *c)
{
	size_t		r;

	if (c->rnb == NULL)
		return (KORE_RESULT_OK);

	while (c->evt.flags & KORE_EVENT_READ) {
		if (c->rnb->buf == NULL)
			return (KORE_RESULT_OK);

		if ((c->rnb->b_len - c->rnb->s_off) == 0)
			return (KORE_RESULT_OK);

		if (!c->read(c, &r))
			return (KORE_RESULT_ERROR);
		if (!(c->evt.flags & KORE_EVENT_READ))
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
net_remove_netbuf(struct connection *c, struct netbuf *nb)
{
	if (nb->type == NETBUF_RECV)
		fatal("net_remove_netbuf(): cannot remove recv netbuf");

	if (nb->flags & NETBUF_MUST_RESEND) {
		nb->flags |= NETBUF_FORCE_REMOVE;
		return;
	}

	if (!(nb->flags & NETBUF_IS_STREAM)) {
		kore_free(nb->buf);
	} else if (nb->cb != NULL) {
		(void)nb->cb(nb);
	}

	if (nb->flags & NETBUF_IS_FILEREF)
		kore_fileref_release(nb->file_ref);

	TAILQ_REMOVE(&(c->send_queue), nb, list);

	kore_pool_put(&nb_pool, nb);
}

int
net_write(struct connection *c, size_t len, size_t *written)
{
	ssize_t		r;

	r = send(c->fd, (c->snb->buf + c->snb->s_off), len, 0);
	if (r == -1) {
		switch (errno) {
		case EINTR:
			*written = 0;
			return (KORE_RESULT_OK);
		case EAGAIN:
			c->evt.flags &= ~KORE_EVENT_WRITE;
			return (KORE_RESULT_OK);
		default:
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

	r = recv(c->fd, (c->rnb->buf + c->rnb->s_off),
	    (c->rnb->b_len - c->rnb->s_off), 0);
	if (r == -1) {
		switch (errno) {
		case EINTR:
			*bytes = 0;
			return (KORE_RESULT_OK);
		case EAGAIN:
			c->evt.flags &= ~KORE_EVENT_READ;
			return (KORE_RESULT_OK);
		default:
			return (KORE_RESULT_ERROR);
		}
	}

	if (r == 0) {
		kore_connection_disconnect(c);
		c->evt.flags &= ~KORE_EVENT_READ;
		return (KORE_RESULT_OK);
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
