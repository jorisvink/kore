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
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pwd.h>
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <syslog.h>
#include <time.h>
#include <regex.h>
#include <zlib.h>
#include <unistd.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

int
kore_connection_accept(struct listener *l, struct connection **out)
{
	socklen_t		len;
	struct connection	*c;

	kore_debug("kore_connection_accept(%p)", l);

	*out = NULL;
	len = sizeof(struct sockaddr_in);
	c = (struct connection *)kore_malloc(sizeof(*c));
	if ((c->fd = accept(l->fd, (struct sockaddr *)&(c->sin), &len)) == -1) {
		kore_mem_free(c);
		kore_debug("accept(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_connection_nonblock(c->fd)) {
		close(c->fd);
		kore_mem_free(c);
		return (KORE_RESULT_ERROR);
	}

	c->owner = l;
	c->ssl = NULL;
	c->flags = 0;
	c->inflate_started = 0;
	c->deflate_started = 0;
	c->client_stream_id = 0;
	c->proto = CONN_PROTO_UNKNOWN;
	c->state = CONN_STATE_SSL_SHAKE;

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	TAILQ_INIT(&(c->spdy_streams));
	kore_worker_connection_add(c);

	*out = c;
	return (KORE_RESULT_OK);
}

void
kore_connection_disconnect(struct connection *c)
{
	if (c->state != CONN_STATE_DISCONNECTING) {
		kore_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;
		kore_worker_connection_move(c);
	}
}

int
kore_connection_handle(struct connection *c)
{
	int			r;
	u_int32_t		len;
	const u_char		*data;

	kore_debug("kore_connection_handle(%p)", c);

	switch (c->state) {
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(primary_dom->ssl_ctx);
			if (c->ssl == NULL) {
				kore_debug("SSL_new(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}

			SSL_set_fd(c->ssl, c->fd);
			SSL_set_accept_state(c->ssl);
		}

		r = SSL_accept(c->ssl);
		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return (KORE_RESULT_OK);
			default:
				kore_debug("SSL_accept(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}
		}

		r = SSL_get_verify_result(c->ssl);
		if (r != X509_V_OK) {
			kore_debug("SSL_get_verify_result(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}

		SSL_get0_next_proto_negotiated(c->ssl, &data, &len);
		if (data) {
			if (!memcmp(data, "spdy/3", 6))
				kore_debug("using SPDY/3");
			c->proto = CONN_PROTO_SPDY;
			net_recv_queue(c, SPDY_FRAME_SIZE, 0,
			    NULL, spdy_frame_recv);
		} else {
			kore_debug("using HTTP/1.1");
			c->proto = CONN_PROTO_HTTP;
			net_recv_queue(c, HTTP_HEADER_MAX_LEN,
			    NETBUF_CALL_CB_ALWAYS, NULL,
			    http_header_recv);
		}

		c->state = CONN_STATE_ESTABLISHED;
		/* FALLTHROUGH */
	case CONN_STATE_ESTABLISHED:
		if (c->flags & CONN_READ_POSSIBLE) {
			if (!net_recv_flush(c))
				return (KORE_RESULT_ERROR);
		}

		if (c->flags & CONN_WRITE_POSSIBLE) {
			if (!net_send_flush(c))
				return (KORE_RESULT_ERROR);
		}
		break;
	case CONN_STATE_DISCONNECTING:
		break;
	default:
		kore_debug("unknown state on %d (%d)", c->fd, c->state);
		break;
	}

	return (KORE_RESULT_OK);
}

void
kore_connection_remove(struct connection *c)
{
	struct netbuf		*nb, *next;
	struct spdy_stream	*s, *snext;

	kore_debug("kore_connection_remove(%p)", c);

	if (c->ssl != NULL)
		SSL_free(c->ssl);
	close(c->fd);

	if (c->inflate_started)
		inflateEnd(&(c->z_inflate));
	if (c->deflate_started)
		deflateEnd(&(c->z_deflate));

	for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);
		if (nb->buf != NULL)
			kore_mem_free(nb->buf);
		kore_mem_free(nb);
	}

	for (nb = TAILQ_FIRST(&(c->recv_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->recv_queue), nb, list);
		kore_mem_free(nb->buf);
		kore_mem_free(nb);
	}

	for (s = TAILQ_FIRST(&(c->spdy_streams)); s != NULL; s = snext) {
		snext = TAILQ_NEXT(s, list);
		TAILQ_REMOVE(&(c->spdy_streams), s, list);

		if (s->hblock != NULL) {
			if (s->hblock->header_block != NULL)
				kore_mem_free(s->hblock->header_block);
			kore_mem_free(s->hblock);
		}

		kore_mem_free(s);
	}

	kore_worker_connection_remove(c);
	kore_mem_free(c);
}

int
kore_connection_nonblock(int fd)
{
	int		flags;

	kore_debug("kore_connection_nonblock(%d)", fd);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		kore_debug("fcntl(): F_GETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		kore_debug("fcntl(): F_SETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
