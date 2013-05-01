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
#include <zlib.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

TAILQ_HEAD(, http_request)	http_requests;

static int		http_generic_cb(struct http_request *);
static int		http_generic_404(struct http_request *);

void
http_init(void)
{
	TAILQ_INIT(&http_requests);
}

int
http_new_request(struct connection *c, struct spdy_stream *s, char *host,
    char *method, char *path)
{
	struct http_request		*req;

	kore_log("http_new_request(%p, %p, %s, %s, %s)", c, s,
	    host, method, path);

	req = (struct http_request *)kore_malloc(sizeof(*req));
	req->owner = c;
	req->stream = s;
	req->host = kore_strdup(host);
	req->path = kore_strdup(path);
	req->method = kore_strdup(method);
	TAILQ_INSERT_TAIL(&http_requests, req, list);

	return (KORE_RESULT_OK);
}

void
http_request_free(struct http_request *req)
{
	free(req->method);
	free(req->path);
	free(req->host);
	free(req);
}

int
http_response(struct http_request *req, int status, u_int8_t *d, u_int32_t len)
{
	u_int32_t			hlen;
	u_int8_t			*htext;
	char				sbuf[4];
	struct spdy_header_block	*hblock;

	kore_log("http_response(%p, %d, %p, %d)", req, status, d, len);

	if (req->stream != NULL) {
		snprintf(sbuf, sizeof(sbuf), "%d", status);
		hblock = spdy_header_block_create(SPDY_HBLOCK_NORMAL);
		spdy_header_block_add(hblock, ":status", sbuf);
		spdy_header_block_add(hblock, ":version", "HTTP/1.1");
		spdy_header_block_add(hblock, "content-type", "text/plain");
		htext = spdy_header_block_release(req->owner, hblock, &hlen);
		if (htext == NULL)
			return (KORE_RESULT_ERROR);

		if (!spdy_frame_send(req->owner, SPDY_CTRL_FRAME_SYN_REPLY,
		    0, hlen, req->stream->stream_id))
			return (KORE_RESULT_ERROR);

		if (!net_send_queue(req->owner, htext, hlen, NULL))
			return (KORE_RESULT_ERROR);

		if (len > 0) {
			if (!spdy_frame_send(req->owner, SPDY_DATA_FRAME,
			    0, len, req->stream->stream_id))
				return (KORE_RESULT_ERROR);
			if (!net_send_queue(req->owner, d, len, NULL))
				return (KORE_RESULT_ERROR);
		}

		if (!spdy_frame_send(req->owner, SPDY_DATA_FRAME,
		    FLAG_FIN, 0, req->stream->stream_id))
			return (KORE_RESULT_ERROR);
	} else {
		kore_log("normal http not functional yet");
	}

	return (KORE_RESULT_OK);
}

void
http_process(void)
{
	struct http_request		*req, *next;

	if (TAILQ_EMPTY(&http_requests))
		return;

	kore_log("http_process()");
	for (req = TAILQ_FIRST(&http_requests); req != NULL; req = next) {
		next = TAILQ_NEXT(req, list);

		/* XXX - add module hooks here */
		if (!strcmp(req->path, "/favicon.ico")) {
			if (!http_generic_404(req))
				kore_server_disconnect(req->owner);
		} else {
			if (!http_generic_cb(req))
				kore_server_disconnect(req->owner);
		}

		TAILQ_REMOVE(&http_requests, req, list);
		http_request_free(req);
	}
}

static int
http_generic_cb(struct http_request *req)
{
	u_int32_t		len;

	kore_log("http_generic_cb(%s, %s, %s)",
	    req->host, req->method, req->path);

	len = strlen("<p>Hello world</p>");
	return (http_response(req, 200, (u_int8_t *)"<p>Hello world</p>", len));
}

static int
http_generic_404(struct http_request *req)
{
	kore_log("http_generic_404(%s, %s, %s)",
	    req->host, req->method, req->path);

	return (http_response(req, 404, NULL, 0));
}
