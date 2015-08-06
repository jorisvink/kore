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
 * Simple example of how SSE (Server Side Events) could be used in Kore.
 * We deal with SSE both over normal HTTP/1.1 and over SPDY connections.
 *
 * Upon new arrivals, a join event is broadcast to all clients.
 * If a client goes away a leave event is broadcasted.
 * Each connection gets its own 10 second ping timer which will emit
 * a ping event to the connection endpoint.
 */

#include <kore/kore.h>
#include <kore/http.h>

#include "assets.h"

void	sse_ping(void *, u_int64_t);
int	page(struct http_request *);
int	subscribe(struct http_request *);
void	sse_disconnect(struct connection *);
void	sse_send(struct connection *, void *, size_t);
void	sse_broadcast(struct connection *, void *, size_t);
void	sse_spdy_stream_closed(struct connection *, struct spdy_stream *);
int	check_header(struct http_request *, const char *, const char *);

/*
 * Each client subscribed to our SSE gets a state attached
 * to their hdlr_extra pointer member.
 */
struct sse_state {
	struct spdy_stream		*stream;
	struct kore_timer		*timer;
};

int
page(struct http_request *req)
{
	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "get");
		http_response(req, 405, NULL, 0);
		return (KORE_RESULT_OK);
	}

	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_index_html, asset_len_index_html);
	return (KORE_RESULT_OK);
}

int
subscribe(struct http_request *req)
{
	struct sse_state	*state;
	char			*hello = "event:join\ndata: client\n\n";

	/* Preventive paranoia. */
	if (req->hdlr_extra != NULL) {
		kore_log(LOG_ERR, "%p: already subscribed", req->owner);
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Only allow GET methods. */
	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "get");
		http_response(req, 405, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Only do SSE if the client told us it wanted too. */
	if (!check_header(req, "accept", "text/event-stream"))
		return (KORE_RESULT_OK);

	/* Do not include content-length in our response. */
	req->flags |= HTTP_REQUEST_NO_CONTENT_LENGTH;

	/* Notify existing clients of our new client now. */
	sse_broadcast(req->owner, hello, strlen(hello));

	/* Set a disconnection method so we know when this client goes away. */
	req->owner->disconnect = sse_disconnect;

	/* For non SPDY clients we do not expect any more data to arrive. */
	if (req->owner->proto != CONN_PROTO_SPDY)
		req->owner->flags |= CONN_READ_BLOCK;

	/* Allocate a state to be carried by our connection. */
	state = kore_malloc(sizeof(*state));
	state->stream = req->stream;
	req->owner->hdlr_extra = state;

	/* SSE over SPDY will need this extra love. */
	if (req->owner->proto == CONN_PROTO_SPDY) {
		/* Unset the http request attached to our SPDY stream. */
		req->stream->httpreq = NULL;

		/*
		 * Do not let the stream close unless a RST occurs or
		 * until we close it ourselves.
		 */
		req->stream->flags |= SPDY_NO_CLOSE;

		/* Set a callback in case this stream gets a RST. */
		req->stream->onclose = sse_spdy_stream_closed;
	}

	/* Now start a timer to send a ping back every 10 second. */
	state->timer = kore_timer_add(sse_ping, 10000, req->owner, 0);

	/* Respond that the SSE channel is now open. */
	kore_log(LOG_NOTICE, "%p: connected for SSE", req->owner);
	http_response_header(req, "content-type", "text/event-stream");
	http_response(req, 200, NULL, 0);

	return (KORE_RESULT_OK);
}

void
sse_broadcast(struct connection *src, void *data, size_t len)
{
	struct connection	*c;

	/* Broadcast the message to all other clients. */
	TAILQ_FOREACH(c, &connections, list) {
		if (c == src)
			continue;
		sse_send(c, data, len);
	}
}

void
sse_send(struct connection *c, void *data, size_t len)
{
	struct sse_state	*state = c->hdlr_extra;

	/* Do not send to clients that do not have a state. */
	if (state == NULL)
		return;

	/* SPDY connections need this extra bit of magic. */
	if (c->proto == CONN_PROTO_SPDY) {
		if (state->stream == NULL) {
			kore_log(LOG_ERR, "no SPDY stream for sse_send()");
			kore_connection_disconnect(c);
			return;
		}

		/*
		 * Tell Kore to send a dataframe prelude + increase the
		 * length of our stream to be sent.
		 */
		if (state->stream->send_size == 0)
			state->stream->flags |= SPDY_DATAFRAME_PRELUDE;
		state->stream->send_size += len;
	}

	/* Queue outgoing data now. */
	net_send_queue(c, data, len, state->stream, NETBUF_LAST_CHAIN);
	net_send_flush(c);
}

void
sse_ping(void *arg, u_int64_t now)
{
	struct connection		*c = arg;
	char				*ping = "event:ping\ndata:\n\n";

	/* Send our ping to the client. */
	sse_send(c, ping, strlen(ping));
}

void
sse_disconnect(struct connection *c)
{
	struct sse_state	*state = c->hdlr_extra;
	char			*leaving = "event: leave\ndata: client\n\n";

	kore_log(LOG_NOTICE, "%p: disconnecting for SSE", c);

	/* Tell others we are leaving. */
	sse_broadcast(c, leaving, strlen(leaving));

	/* Make sure we cleanup our hooked stream if any. */
	if (c->proto == CONN_PROTO_SPDY && state->stream != NULL) {
		state->stream->onclose = NULL;
		spdy_stream_close(c, state->stream, SPDY_REMOVE_NETBUFS);
	}

	/* Kill our timer and free/remove the state. */
	kore_timer_remove(state->timer);
	kore_mem_free(state);

	/* Prevent us to be called again. */
	c->hdlr_extra = NULL;
	c->disconnect = NULL;
}

void
sse_spdy_stream_closed(struct connection *c, struct spdy_stream *s)
{
	struct sse_state	*state = c->hdlr_extra;

	/* Paranoia. */
	if (state->stream != s) {
		state->stream = NULL;
		kore_connection_disconnect(c);
		return;
	}

	/* Set our stream to NULL and call sse_disconnect. */
	state->stream = NULL;
	sse_disconnect(c);
}

int
check_header(struct http_request *req, const char *name, const char *value)
{
	char		*hdr;

	if (!http_request_header(req, name, &hdr)) {
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(hdr, value)) {
		kore_mem_free(hdr);
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	kore_mem_free(hdr);
	return (KORE_RESULT_OK);
}
