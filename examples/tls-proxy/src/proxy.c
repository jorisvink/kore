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
 * In this example Kore acts as a TLS proxy shuffling data between
 * an encrypted connection and a plain text backend.
 *
 * It will look at the TLS SNI extension to figure out what backend
 * to use for the connection when it comes in.
 *
 * Add your backends to the data structure below.
 */

/* Default timeouts, 5 seconds for connecting, 15 seconds otherwise. */
#define PROXY_TIMEOUT		(15 * 1000)
#define PROXY_CONNECT_TIMEOUT	(5 * 1000)

/* All domains and their backends. */
struct {
	const char		*name;
	const char		*ip;
	const u_int16_t		port;
} backends[] = {
	{ "localhost",	"127.0.0.1",	8080 },
	{ NULL,		NULL,		0 }
};

int	client_handle(struct connection *);
void	client_setup(struct connection *);

void	disconnect(struct connection *);
int	pipe_data(struct netbuf *);

int	backend_handle_connect(struct connection *);
int	backend_handle_default(struct connection *);

/*
 * Called for every new connection on a certain ip/port. Which one is
 * configured in the TLS proxy its configuration file.
 */
void
client_setup(struct connection *c)
{
	int			i, fd;
	const char		*name;
	struct connection	*backend;

	/* Paranoia. */
	name = SSL_get_servername(c->ssl, TLSEXT_NAMETYPE_host_name);
	if (name == NULL) {
		kore_connection_disconnect(c);
		return;
	}

	/* Figure out what backend to use. */
	for (i = 0; backends[i].name != NULL; i++) {
		if (!strcasecmp(backends[i].name, name))
			break;
	}

	/* If we don't have any backends, we just disconnect the client. */
	if (backends[i].name == NULL) {
		kore_connection_disconnect(c);
		return;
	}

	/* Create new socket for the backend connection. */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		kore_log(LOG_ERR, "socket(): %s", errno_s);
		kore_connection_disconnect(c);
		return;
	}

	/* Set it to non blocking as well. */
	if (!kore_connection_nonblock(fd, 1)) {
		close(fd);
		kore_connection_disconnect(c);
		return;
	}

	/* Grab a new connection from Kore to hook backend into. */
	backend = kore_connection_new(NULL);

	/* Prepare our connection. */
	backend->family = AF_INET;
	backend->addr.ipv4.sin_family = AF_INET;
	backend->addr.ipv4.sin_port = htons(backends[i].port);
	backend->addr.ipv4.sin_addr.s_addr = inet_addr(backends[i].ip);

	/* Set the file descriptor for the backend. */
	backend->fd = fd;

	/* Default write/read callbacks for backend. */
	backend->read = net_read;
	backend->write = net_write;

	/* Connection type (unknown to Kore). */
	backend->proto = CONN_PROTO_UNKNOWN;
	backend->state = CONN_STATE_ESTABLISHED;

	/* The backend idle timer is set first to connection timeout. */
	backend->idle_timer.length = PROXY_CONNECT_TIMEOUT;

	/* The client idle timer is set to default idle time. */
	c->idle_timer.length = PROXY_TIMEOUT;

	/* Now link both the client and the backend connection together. */
	c->hdlr_extra = backend;
	backend->hdlr_extra = c;

	/*
	 * The handle function pointer for the backend is set to the
	 * backend_handle_connect() while connecting.
	 */
	c->handle = client_handle;
	backend->handle = backend_handle_connect;

	/* Set the disconnect method for both connections. */
	c->disconnect = disconnect;
	backend->disconnect = disconnect;

	/* Queue write events for the backend connection for now. */
	kore_platform_schedule_write(backend->fd, backend);

	/* Start idle timer for the backend. */
	kore_connection_start_idletimer(backend);

	/* Set our client connection to established. */
	c->state = CONN_STATE_ESTABLISHED;

	/* Insert the backend into the list of Kore connections. */
	TAILQ_INSERT_TAIL(&connections, backend, list);

	/* Kick off connecting. */
	backend->evt.flags |= KORE_EVENT_WRITE;
	backend->handle(backend);
}

/*
 * This function is called for backends while they are connecting.
 * In here we check for write events and attempt to connect() to the
 * backend.
 *
 * Once a connection is established we set the backend handle function
 * pointer to the backend_handle_default() callback and setup the reads
 * for both the backend and the client connection we received.
 */
int
backend_handle_connect(struct connection *c)
{
	int			ret;
	struct connection	*src;

	/* We will get a write notification when we can progress. */
	if (!(c->evt.flags & KORE_EVENT_WRITE))
		return (KORE_RESULT_OK);

	kore_connection_stop_idletimer(c);

	/* Attempt connecting. */
	ret = connect(c->fd, (struct sockaddr *)&c->addr.ipv4,
	    sizeof(c->addr.ipv4));

	/* If we failed check why, we are non blocking. */
	if (ret == -1) {
		/* If we got a real error, disconnect. */
		if (errno != EALREADY && errno != EINPROGRESS &&
		    errno != EISCONN) {
			kore_log(LOG_ERR, "connect(): %s", errno_s);
			return (KORE_RESULT_ERROR);
		}

		/* Clean the write flag, we'll be called later. */
		if (errno != EISCONN) {
			c->evt.flags &= ~KORE_EVENT_WRITE;
			kore_connection_start_idletimer(c);
			return (KORE_RESULT_OK);
		}
	}

	/* The connection to the backend succeeded. */
	c->handle = backend_handle_default;

	/* Setup read calls for both backend and its client. */
	net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX,
	    NETBUF_CALL_CB_ALWAYS, pipe_data);
	net_recv_queue(c->hdlr_extra, NETBUF_SEND_PAYLOAD_MAX,
	    NETBUF_CALL_CB_ALWAYS, pipe_data);

	/* Allow for all events now. */
	kore_connection_start_idletimer(c);
	kore_platform_event_all(c->fd, c);

	/* Allow events from source now. */
	src = c->hdlr_extra;
	kore_platform_event_all(src->fd, src);

	/* Now lets start. */
	return (c->handle(c));
}

/*
 * Called for connection activity on a backend, just forwards
 * to the default Kore connection handling for now.
 */
int
backend_handle_default(struct connection *c)
{
	return (kore_connection_handle(c));
}

/*
 * Called for connection activity on a client, just forwards
 * to the default Kore connection handling for now.
 */
int
client_handle(struct connection *c)
{
	return (kore_connection_handle(c));
}

/*
 * Called whenever a client or its backend have disconnected.
 * This will disconnect the matching paired connection as well.
 */
void
disconnect(struct connection *c)
{
	struct connection	*pair = c->hdlr_extra;

	c->hdlr_extra = NULL;

	if (pair != NULL) {
		pair->hdlr_extra = NULL;
		kore_connection_disconnect(pair);
	}
}

/*
 * Called whenever data is available that must be piped through
 * to the paired connection. (client<>backend or backend<>client).
 */
int
pipe_data(struct netbuf *nb)
{
	struct connection	*src = nb->owner;
	struct connection	*dst = src->hdlr_extra;

	/* Flush data out towards destination. */
	net_send_queue(dst, nb->buf, nb->s_off);
	net_send_flush(dst);

	/* Reset read for source. */
	net_recv_reset(src, NETBUF_SEND_PAYLOAD_MAX, pipe_data);

	return (KORE_RESULT_OK);
}
