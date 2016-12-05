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
#include <sys/socket.h>

#include <netinet/tcp.h>

#include <fcntl.h>

#include "kore.h"
#include "http.h"

struct kore_pool		connection_pool;
struct connection_list		connections;
struct connection_list		disconnected;

void
kore_connection_init(void)
{
	TAILQ_INIT(&connections);
	TAILQ_INIT(&disconnected);

	kore_pool_init(&connection_pool, "connection_pool",
	    sizeof(struct connection), worker_max_connections);
}

void
kore_connection_cleanup(void)
{
	kore_debug("connection_cleanup()");

	/* Drop all connections */
	kore_connection_prune(KORE_CONNECTION_PRUNE_ALL);
	kore_pool_cleanup(&connection_pool);
}

struct connection *
kore_connection_new(void *owner)
{
	struct connection	*c;

	c = kore_pool_get(&connection_pool);

#if !defined(KORE_NO_TLS)
	c->ssl = NULL;
	c->cert = NULL;
	c->tls_reneg = 0;
#endif
	c->flags = 0;
	c->rnb = NULL;
	c->snb = NULL;
	c->owner = owner;
	c->handle = NULL;
	c->disconnect = NULL;
	c->hdlr_extra = NULL;
	c->proto = CONN_PROTO_UNKNOWN;
	c->type = KORE_TYPE_CONNECTION;
	c->idle_timer.start = 0;
	c->idle_timer.length = KORE_IDLE_TIMER_MAX;

#if !defined(KORE_NO_HTTP)
	c->wscbs = NULL;
	TAILQ_INIT(&(c->http_requests));
#endif

	TAILQ_INIT(&(c->send_queue));

	return (c);
}

int
kore_connection_accept(struct listener *listener, struct connection **out)
{
	struct connection	*c;
	struct sockaddr		*sin;
	socklen_t		len;

	kore_debug("kore_connection_accept(%p)", listener);

	*out = NULL;
	c = kore_connection_new(listener);

	c->addrtype = listener->addrtype;
	if (c->addrtype == AF_INET) {
		len = sizeof(struct sockaddr_in);
		sin = (struct sockaddr *)&(c->addr.ipv4);
	} else {
		len = sizeof(struct sockaddr_in6);
		sin = (struct sockaddr *)&(c->addr.ipv6);
	}

	if ((c->fd = accept(listener->fd, sin, &len)) == -1) {
		kore_pool_put(&connection_pool, c);
		kore_debug("accept(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_connection_nonblock(c->fd, 1)) {
		close(c->fd);
		kore_pool_put(&connection_pool, c);
		return (KORE_RESULT_ERROR);
	}

	c->handle = kore_connection_handle;
	TAILQ_INSERT_TAIL(&connections, c, list);

#if !defined(KORE_NO_TLS)
	c->state = CONN_STATE_SSL_SHAKE;
	c->write = net_write_ssl;
	c->read = net_read_ssl;
#else
	c->state = CONN_STATE_ESTABLISHED;
	c->write = net_write;
	c->read = net_read;

	if (listener->connect != NULL) {
		listener->connect(c);
	} else {
#if !defined(KORE_NO_HTTP)
		c->proto = CONN_PROTO_HTTP;
		if (http_keepalive_time != 0)
			c->idle_timer.length = http_keepalive_time * 1000;
		net_recv_queue(c, http_header_max,
		    NETBUF_CALL_CB_ALWAYS, http_header_recv);
#endif
	}
#endif

	kore_connection_start_idletimer(c);
	worker_active_connections++;

	*out = c;
	return (KORE_RESULT_OK);
}

void
kore_connection_check_timeout(void)
{
	struct connection	*c;
	u_int64_t		now;

	now = kore_time_ms();
	TAILQ_FOREACH(c, &connections, list) {
		if (c->proto == CONN_PROTO_MSG)
			continue;
		if (!(c->flags & CONN_IDLE_TIMER_ACT))
			continue;
		kore_connection_check_idletimer(now, c);
	}
}

void
kore_connection_prune(int all)
{
	struct connection	*c, *cnext;

	if (all) {
		for (c = TAILQ_FIRST(&connections); c != NULL; c = cnext) {
			cnext = TAILQ_NEXT(c, list);
			net_send_flush(c);
			kore_connection_disconnect(c);
		}
	}

	for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
		cnext = TAILQ_NEXT(c, list);
		TAILQ_REMOVE(&disconnected, c, list);
		kore_connection_remove(c);
	}
}

void
kore_connection_disconnect(struct connection *c)
{
	if (c->state != CONN_STATE_DISCONNECTING) {
		kore_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;
		if (c->disconnect)
			c->disconnect(c);

		TAILQ_REMOVE(&connections, c, list);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
	}
}

int
kore_connection_handle(struct connection *c)
{
#if !defined(KORE_NO_TLS)
	int			r;
	struct listener		*listener;
	char			cn[X509_CN_LENGTH];
#endif

	kore_debug("kore_connection_handle(%p) -> %d", c, c->state);
	kore_connection_stop_idletimer(c);

	switch (c->state) {
#if !defined(KORE_NO_TLS)
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(primary_dom->ssl_ctx);
			if (c->ssl == NULL) {
				kore_debug("SSL_new(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}

			SSL_set_fd(c->ssl, c->fd);
			SSL_set_accept_state(c->ssl);
			SSL_set_app_data(c->ssl, c);
		}

		ERR_clear_error();
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

		if (SSL_get_verify_mode(c->ssl) & SSL_VERIFY_PEER) {
			c->cert = SSL_get_peer_certificate(c->ssl);
			if (c->cert == NULL) {
				kore_log(LOG_NOTICE,
				    "no client certificate presented?");
				return (KORE_RESULT_ERROR);
			}

			if (X509_GET_CN(c->cert, cn, sizeof(cn)) == -1) {
				kore_log(LOG_NOTICE,
				    "no CN found in client certificate");
				return (KORE_RESULT_ERROR);
			}
		} else {
			c->cert = NULL;
		}

		r = SSL_get_verify_result(c->ssl);
		if (r != X509_V_OK) {
			kore_debug("SSL_get_verify_result(): %d, %s",
			    r, ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}

		if (c->owner != NULL) {
			listener = (struct listener *)c->owner;
			if (listener->connect != NULL) {
				listener->connect(c);
				return (KORE_RESULT_OK);
			}
		}

#if !defined(KORE_NO_HTTP)
		c->proto = CONN_PROTO_HTTP;
		if (http_keepalive_time != 0) {
			c->idle_timer.length =
			    http_keepalive_time * 1000;
		}

		net_recv_queue(c, http_header_max,
		    NETBUF_CALL_CB_ALWAYS, http_header_recv);
#endif

		c->state = CONN_STATE_ESTABLISHED;
		/* FALLTHROUGH */
#endif /* !KORE_NO_TLS */
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

	kore_connection_start_idletimer(c);

	return (KORE_RESULT_OK);
}

void
kore_connection_remove(struct connection *c)
{
	struct netbuf		*nb, *next;
#if !defined(KORE_NO_HTTP)
	struct http_request	*req, *rnext;
#endif

	kore_debug("kore_connection_remove(%p)", c);

#if !defined(KORE_NO_TLS)
	if (c->ssl != NULL) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}

	if (c->cert != NULL)
		X509_free(c->cert);
#endif

	close(c->fd);

	if (c->hdlr_extra != NULL)
		kore_free(c->hdlr_extra);

#if !defined(KORE_NO_HTTP)
	for (req = TAILQ_FIRST(&(c->http_requests)); req != NULL; req = rnext) {
		rnext = TAILQ_NEXT(req, olist);
		TAILQ_REMOVE(&(c->http_requests), req, olist);
		req->flags |= HTTP_REQUEST_DELETE;
		http_request_wakeup(req);
	}
#endif

	for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);
		if (!(nb->flags & NETBUF_IS_STREAM)) {
			kore_free(nb->buf);
		} else if (nb->cb != NULL) {
			(void)nb->cb(nb);
		}
		kore_pool_put(&nb_pool, nb);
	}

	if (c->rnb != NULL) {
		kore_free(c->rnb->buf);
		kore_pool_put(&nb_pool, c->rnb);
	}

	kore_pool_put(&connection_pool, c);
	worker_active_connections--;
}

void
kore_connection_check_idletimer(u_int64_t now, struct connection *c)
{
	u_int64_t	d;

	d = now - c->idle_timer.start;
	if (d >= c->idle_timer.length) {
		kore_debug("%p idle for %d ms, expiring", c, d);
		kore_connection_disconnect(c);
	}
}

void
kore_connection_start_idletimer(struct connection *c)
{
	kore_debug("kore_connection_start_idletimer(%p)", c);

	c->flags |= CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = kore_time_ms();
}

void
kore_connection_stop_idletimer(struct connection *c)
{
	kore_debug("kore_connection_stop_idletimer(%p)", c);

	c->flags &= ~CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = 0;
}

int
kore_connection_nonblock(int fd, int nodelay)
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

	if (nodelay) {
		flags = 1;
		if (setsockopt(fd, IPPROTO_TCP,
		    TCP_NODELAY, (char *)&flags, sizeof(flags)) == -1) {
			kore_log(LOG_NOTICE,
			    "failed to set TCP_NODELAY on %d", fd);
		}
	}

	return (KORE_RESULT_OK);
}
