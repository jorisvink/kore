/*
 * Copyright (c) 2015 Joris Vink <joris@coders.se>
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

#include <kore/kore.h>

/*
 * In this example Kore acts as a simple TLS proxy.
 * Be sure to update PROXY_HOST and PROXY_PORT to reflect
 * your endpoint.
 *
 * Note - right now the connect() call in proxy_setup() is still
 * done synchronously, might change in the future in this example.
 *
 * Hint: enabling client certificates in Kore still works with this :-)
 */

#define PROXY_HOST		"127.0.0.1"
#define PROXY_PORT		80

void	proxy_setup(struct connection *);
void	proxy_disconnect(struct connection *);
int	proxy_data(struct netbuf *);
int	proxy_handle(struct connection *);

void
proxy_setup(struct connection *c)
{
	int			fd;
	struct sockaddr_in	sin;
	struct connection	*proxy;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		kore_log(LOG_ERR, "socket(): %s", errno_s);
		kore_connection_disconnect(c);
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PROXY_PORT);
	sin.sin_addr.s_addr = inet_addr(PROXY_HOST);

	/* Blocking connect(), perhaps we can improve on that later. */
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		kore_log(LOG_ERR, "connect(): %s", errno_s);
		close(fd);
		kore_connection_disconnect(c);
		return;
	}

	if (!kore_connection_nonblock(fd, 1)) {
		close(fd);
		kore_connection_disconnect(c);
		return;
	}

	proxy = kore_connection_new(NULL);

	proxy->fd = fd;
	proxy->addr.ipv4 = sin;
	proxy->read = net_read;
	proxy->write = net_write;
	proxy->addrtype = AF_INET;
	proxy->proto = CONN_PROTO_UNKNOWN;
	proxy->state = CONN_STATE_ESTABLISHED;

	proxy->idle_timer.length = 60000;
	c->idle_timer.length = 60000;

	c->hdlr_extra = proxy;
	proxy->hdlr_extra = c;

	c->handle = proxy_handle;
	c->disconnect = proxy_disconnect;
	proxy->handle = proxy_handle;
	proxy->disconnect = proxy_disconnect;

	kore_connection_start_idletimer(proxy);
	kore_platform_event_all(proxy->fd, proxy);

	net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX,
	    NETBUF_CALL_CB_ALWAYS, proxy_data);
	net_recv_queue(proxy, NETBUF_SEND_PAYLOAD_MAX,
	    NETBUF_CALL_CB_ALWAYS, proxy_data);

	kore_log(LOG_NOTICE, "new connection alright, us:%p proxy:%p", c, proxy);

	/* We must set the state for this connection ourselves. */
	c->state = CONN_STATE_ESTABLISHED;
	TAILQ_INSERT_TAIL(&connections, proxy, list);
}

int
proxy_handle(struct connection *c)
{
	kore_log(LOG_NOTICE, "connection activity on %p", c);
	return (kore_connection_handle(c));
}

void
proxy_disconnect(struct connection *c)
{
	struct connection	*proxy = (struct connection *)c->hdlr_extra;

	kore_log(LOG_NOTICE, "disconnecting %p (proxy: %p)", c, proxy);

	c->hdlr_extra = NULL;

	if (proxy != NULL) {
		proxy->hdlr_extra = NULL;
		kore_connection_disconnect(proxy);
	}
}

int
proxy_data(struct netbuf *nb)
{
	struct connection	*src = nb->owner;
	struct connection	*proxy = src->hdlr_extra;

	kore_log(LOG_NOTICE, "proxying %u bytes", nb->s_off);

	net_send_queue(proxy, nb->buf, nb->s_off);
	net_send_flush(proxy);
	net_recv_reset(src, NETBUF_SEND_PAYLOAD_MAX, proxy_data);

	return (KORE_RESULT_OK);
}
