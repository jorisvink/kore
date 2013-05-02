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
#include <time.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

TAILQ_HEAD(, http_request)	http_requests;

static int		http_generic_404(struct http_request *);

void
http_init(void)
{
	TAILQ_INIT(&http_requests);
}

int
http_request_new(struct connection *c, struct spdy_stream *s, char *host,
    char *method, char *path, struct http_request **out)
{
	struct http_request		*req;

	kore_log("http_request_new(%p, %p, %s, %s, %s)", c, s,
	    host, method, path);

	req = (struct http_request *)kore_malloc(sizeof(*req));
	req->flags = 0;
	req->owner = c;
	req->stream = s;
	req->post_data = NULL;
	req->host = kore_strdup(host);
	req->path = kore_strdup(path);
	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));

	if (!strcasecmp(method, "get")) {
		req->method = HTTP_METHOD_GET;
		req->flags |= HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "post")) {
		req->method = HTTP_METHOD_POST;
	} else {
		kore_log("invalid method specified in request: %s", method);
		http_request_free(req);
		return (KORE_RESULT_ERROR);
	}

	TAILQ_INSERT_TAIL(&http_requests, req, list);

	if (out != NULL)
		*out = req;

	return (KORE_RESULT_OK);
}

void
http_response_header_add(struct http_request *req, char *header, char *value)
{
	struct http_header	*hdr;

	kore_log("http_response_header_add(%p, %s, %s)", req, header, value);

	hdr = (struct http_header *)kore_malloc(sizeof(*hdr));
	hdr->header = kore_strdup(header);
	hdr->value = kore_strdup(value);
	TAILQ_INSERT_TAIL(&(req->resp_headers), hdr, list);
}

void
http_request_free(struct http_request *req)
{
	struct http_header	*hdr, *next;

	for (hdr = TAILQ_FIRST(&(req->resp_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->resp_headers), hdr, list);
		free(hdr->header);
		free(hdr->value);
		free(hdr);
	}

	for (hdr = TAILQ_FIRST(&(req->req_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->req_headers), hdr, list);
		free(hdr->header);
		free(hdr->value);
		free(hdr);
	}

	free(req->path);
	free(req->host);
	free(req);
}

int
http_response(struct http_request *req, int status, u_int8_t *d, u_int32_t len)
{
	u_int32_t			hlen;
	struct http_header		*hdr;
	struct kore_buf			*buf;
	u_int8_t			*htext;
	struct spdy_header_block	*hblock;
	char				sbuf[64];

	kore_log("http_response(%p, %d, %p, %d)", req, status, d, len);

	if (req->owner->proto == CONN_PROTO_SPDY) {
		snprintf(sbuf, sizeof(sbuf), "%d", status);

		hblock = spdy_header_block_create(SPDY_HBLOCK_NORMAL);
		spdy_header_block_add(hblock, ":status", sbuf);
		spdy_header_block_add(hblock, ":version", "HTTP/1.1");
		TAILQ_FOREACH(hdr, &(req->resp_headers), list)
			spdy_header_block_add(hblock, hdr->header, hdr->value);

		htext = spdy_header_block_release(req->owner, hblock, &hlen);
		if (htext == NULL)
			return (KORE_RESULT_ERROR);

		spdy_frame_send(req->owner, SPDY_CTRL_FRAME_SYN_REPLY,
		    0, hlen, req->stream, 0);
		net_send_queue(req->owner, htext, hlen, 0, NULL, NULL);
		free(htext);

		if (len > 0) {
			spdy_frame_send(req->owner, SPDY_DATA_FRAME,
			    0, len, req->stream, 0);
			net_send_queue(req->owner, d, len, 0, NULL, NULL);
		}

		spdy_frame_send(req->owner, SPDY_DATA_FRAME,
		    FLAG_FIN, 0, req->stream, 0);
	} else {
		buf = kore_buf_create(KORE_BUF_INITIAL);

		snprintf(sbuf, sizeof(sbuf), "HTTP/1.1 %d\r\n", status);
		kore_buf_append(buf, (u_int8_t *)sbuf, strlen(sbuf));

		snprintf(sbuf, sizeof(sbuf), "Content-length: %d\r\n", len);
		kore_buf_append(buf, (u_int8_t *)sbuf, strlen(sbuf));

		snprintf(sbuf, sizeof(sbuf), "Connection: close\r\n");
		kore_buf_append(buf, (u_int8_t *)sbuf, strlen(sbuf));

		TAILQ_FOREACH(hdr, &(req->resp_headers), list) {
			snprintf(sbuf, sizeof(sbuf), "%s: %s\r\n",
			    hdr->header, hdr->value);
			kore_buf_append(buf, (u_int8_t *)sbuf, strlen(sbuf));
		}

		kore_buf_append(buf, (u_int8_t *)"\r\n", 2);
		htext = kore_buf_release(buf, &hlen);
		net_send_queue(req->owner, htext, hlen, 0, NULL, NULL);
		free(htext);

		net_send_queue(req->owner, d, len, 0, NULL, NULL);
	}

	return (KORE_RESULT_OK);
}

int
http_request_header_get(struct http_request *req, char *header, char **out)
{
	int			r;
	struct http_header	*hdr;

	if (req->owner->proto == CONN_PROTO_SPDY) {
		r = spdy_stream_get_header(req->stream->hblock, header, out);
	} else {
		TAILQ_FOREACH(hdr, &(req->req_headers), list) {
			if (!strcasecmp(hdr->header, header)) {
				r = strlen(hdr->value) + 1;
				*out = (char *)kore_malloc(r);
				kore_strlcpy(*out, hdr->value, r);
				return (KORE_RESULT_OK);
			}
		}

		r = KORE_RESULT_ERROR;
	}

	return (r);
}

void
http_process(void)
{
	struct http_request	*req, *next;
	int			r, (*hdlr)(struct http_request *);

	if (TAILQ_EMPTY(&http_requests))
		return;

	kore_log("http_process()");
	for (req = TAILQ_FIRST(&http_requests); req != NULL; req = next) {
		next = TAILQ_NEXT(req, list);
		if (!(req->flags & HTTP_REQUEST_COMPLETE))
			continue;

		hdlr = kore_module_handler_find(req->host, req->path);
		if (hdlr == NULL)
			r = http_generic_404(req);
		else
			r = hdlr(req);

		if (r != KORE_RESULT_ERROR)
			net_send_flush(req->owner);
		else
			kore_server_disconnect(req->owner);

		TAILQ_REMOVE(&http_requests, req, list);
		http_request_free(req);
	}
}

int
http_header_recv(struct netbuf *nb)
{
	char			*p;
	struct http_header	*hdr;
	struct http_request	*req;
	int			h, i, v;
	char			*request[4], *host[3], *hbuf;
	char			*headers[HTTP_REQ_HEADER_MAX];
	struct connection	*c = (struct connection *)nb->owner;

	kore_log("http_header_recv(%p)", nb);

	nb->buf[nb->len] = '\0';
	if ((p = strrchr((char *)nb->buf, '\r')) == NULL)
		return (KORE_RESULT_OK);
	if (nb->len > 2 && strncmp((p - 2), "\r\n\r\n", 4))
		return (KORE_RESULT_OK);

	nb->flags |= NETBUF_FORCE_REMOVE;
	hbuf = kore_strdup((const char *)nb->buf);

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	if (strlen(headers[0]) > 3 && strncasecmp(headers[0], "get", 3)) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	v = kore_split_string(headers[1], ":", host, 3);
	if (v != 2) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	if (strlen(host[0]) != 4 || strncasecmp(host[0], "host", 4) ||
	    strlen(host[1]) < 3) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	host[1]++;
	if (!http_request_new(c, NULL, host[1], request[0], request[1], &req)) {
		free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	for (i = 2; i < h; i++) {
		p = strchr(headers[i], ':');
		if (p == NULL) {
			kore_log("malformed header: '%s'", headers[i]);
			continue;
		}

		*(p++) = '\0';
		hdr = (struct http_header *)kore_malloc(sizeof(*hdr));
		hdr->header = kore_strdup(headers[i]);
		hdr->value = kore_strdup(p);
		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);
	}

	free(hbuf);
	return (KORE_RESULT_OK);
}

static int
http_generic_404(struct http_request *req)
{
	kore_log("http_generic_404(%s, %s, %s)",
	    req->host, req->method, req->path);

	return (http_response(req, 404, NULL, 0));
}
