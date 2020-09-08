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

/*
 * Example of using Kore as a network application server.
 *
 * We will get called for every new connection that has been established.
 * For TLS connections we will get called after the TLS handshake completed.
 *
 * From the setup we can queue up our own read commands and do whatever we
 * like with the newly connected client.
 */

#include <kore/kore.h>

void		connection_setup(struct connection *);
int		connection_handle(struct connection *);
int		connection_recv_data(struct netbuf *);

void
connection_setup(struct connection *c)
{
	kore_log(LOG_NOTICE, "%p: new connection", c);

	/*
	 * Setup a read command that will read up to 128 bytes and will
	 * always call the callback connection_recv_data even if not all
	 * 128 bytes were read.
	 */
	net_recv_queue(c, 128, NETBUF_CALL_CB_ALWAYS, connection_recv_data);

	/* We are responsible for setting the connection state. */
	c->state = CONN_STATE_ESTABLISHED;

	/* Override the handle function, called when new events occur. */
	c->handle = connection_handle;
}

/*
 * This function is called every time a new event is triggered on the
 * connection. In this demo we just use it as a stub for the normal
 * callback kore_connection_handle().
 *
 * In this callback you would generally look at the state of the connection
 * in c->state and perform the required actions like writing / reading using
 * net_send_flush() or net_recv_flush() if KORE_EVENT_WRITE or
 * KORE_EVENT_READ are set respectively in c->evt.flags.
 * Returning KORE_RESULT_ERROR from this callback will disconnect the
 * connection altogether.
 */
int
connection_handle(struct connection *c)
{
	kore_log(LOG_NOTICE, "connection_handle: %p", c);
	return (kore_connection_handle(c));
}

/*
 * This function is called every time we get up to 128 bytes of data.
 * The connection can be found under nb->owner.
 * The data received can be found under nb->buf.
 * The length of the received data can be found under s_off.
 */
int
connection_recv_data(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;

	kore_log(LOG_NOTICE, "%p: received %zu bytes", (void *)c, nb->s_off);

	/* We will just dump these back to the client. */
	net_send_queue(c, nb->buf, nb->s_off);
	net_send_flush(c);

	/* Now reset the receive command for the next one. */
	net_recv_reset(c, 128, connection_recv_data);

	return (KORE_RESULT_OK);
}
