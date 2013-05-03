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
static int		http_post_data_recv(struct netbuf *);
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
	TAILQ_INIT(&(req->arguments));

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
	struct http_arg		*q, *qnext;
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

	for (q = TAILQ_FIRST(&(req->arguments)); q != NULL; q = qnext) {
		qnext = TAILQ_NEXT(q, list);

		TAILQ_REMOVE(&(req->arguments), q, list);
		free(q->name);
		free(q->value);
		free(q);
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
	struct http_header	*hdr;
	struct http_request	*req;
	struct netbuf		*nnb;
	int			h, i, v, skip;
	u_int8_t		*end_headers, ch;
	size_t			clen, len, bytes_left;
	char			*request[4], *host[3], *hbuf;
	char			*p, *headers[HTTP_REQ_HEADER_MAX];
	struct connection	*c = (struct connection *)nb->owner;

	kore_log("http_header_recv(%p)", nb);

	ch = nb->buf[nb->len];
	nb->buf[nb->len] = '\0';

	if ((end_headers = (u_int8_t *)strrchr((char *)nb->buf, '\r')) == NULL)
		return (KORE_RESULT_OK);
	if (nb->len > 2 && strncmp(((char *)end_headers - 2), "\r\n\r\n", 4))
		return (KORE_RESULT_OK);

	nb->buf[nb->len] = ch;
	nb->flags |= NETBUF_FORCE_REMOVE;
	end_headers += 2;

	len = end_headers - nb->buf;
	hbuf = (char *)kore_malloc(len + 1);
	kore_strlcpy(hbuf, (char *)nb->buf, len + 1);

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2) {
		free(hbuf);
		kore_log("err 1");
		return (KORE_RESULT_ERROR);
	}

	if ((strlen(headers[0]) > 3 && strncasecmp(headers[0], "get", 3)) &&
	    (strlen(headers[0]) > 4 && strncasecmp(headers[0], "post", 4))) {
		free(hbuf);
		kore_log("err 2");
		return (KORE_RESULT_ERROR);
	}

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3) {
		free(hbuf);
		kore_log("err 3");
		return (KORE_RESULT_ERROR);
	}

	host[0] = NULL;
	for (i = 0; i < h; i++) {
		if (strncasecmp(headers[i], "host",
		    MIN(strlen(headers[i]), strlen("host"))))
			continue;

		v = kore_split_string(headers[i], ":", host, 3);
		if (v != 2) {
			free(hbuf);
			kore_log("err 4");
			return (KORE_RESULT_ERROR);
		}

		if (strlen(host[0]) != 4 || strncasecmp(host[0], "host", 4) ||
		    strlen(host[1]) < 4) {
			free(hbuf);
			kore_log("err 5");
			return (KORE_RESULT_ERROR);
		}

		host[1]++;
		skip = i;
		break;
	}

	if (host[0] == NULL) {
		free(hbuf);
		kore_log("err 6");
		return (KORE_RESULT_ERROR);
	}

	if (!http_request_new(c, NULL, host[1], request[0], request[1], &req)) {
		free(hbuf);
		kore_log("err 7");
		return (KORE_RESULT_ERROR);
	}

	for (i = 1; i < h; i++) {
		if (i == skip)
			continue;

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

	if (req->method == HTTP_METHOD_POST) {
		if (!http_request_header_get(req, "content-length", &p)) {
			kore_log("POST but no content-length");
			TAILQ_REMOVE(&http_requests, req, list);
			http_request_free(req);
			return (KORE_RESULT_ERROR);
		}

		clen = kore_strtonum(p, 0, UINT_MAX, &v);
		if (v == KORE_RESULT_ERROR) {
			free(p);
			kore_log("content-length invalid: %s", p);
			TAILQ_REMOVE(&http_requests, req, list);
			http_request_free(req);
			return (KORE_RESULT_ERROR);
		}

		req->post_data = kore_buf_create(clen);
		kore_buf_append(req->post_data, end_headers,
		    (nb->offset - len));

		bytes_left = clen - (nb->offset - len);
		kore_log("need %ld more bytes for POST", bytes_left);
		net_recv_queue(c, bytes_left, 0, &nnb, http_post_data_recv);
		nnb->extra = req;
	}

	return (KORE_RESULT_OK);
}

int
http_populate_arguments(struct http_request *req)
{
	struct http_arg		*q;
	int			i, v, c, count;
	char			*query, *args[HTTP_MAX_QUERY_ARGS], *val[3];

	if (req->method == HTTP_METHOD_POST) {
		query = http_post_data_text(req);
	} else {
		kore_log("HTTP_METHOD_GET not supported for arguments");
		return (0);
	}

	count = 0;
	v = kore_split_string(query, "&", args, HTTP_MAX_QUERY_ARGS);
	for (i = 0; i < v; i++) {
		c = kore_split_string(args[i], "=", val, 3);
		if (c != 2) {
			kore_log("malformed query argument");
			continue;
		}

		q = (struct http_arg *)kore_malloc(sizeof(*q));
		q->name = kore_strdup(val[0]);
		q->value = kore_strdup(val[1]);
		TAILQ_INSERT_TAIL(&(req->arguments), q, list);
		count++;
	}

	free(query);
	return (count);
}

int
http_argument_lookup(struct http_request *req, const char *name, char **out)
{
	struct http_arg		*q;

	TAILQ_FOREACH(q, &(req->arguments), list) {
		if (!strcmp(q->name, name)) {
			*out = kore_strdup(q->value);
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

char *
http_post_data_text(struct http_request *req)
{
	u_int32_t	len;
	u_int8_t	*data;
	char		*text;

	data = kore_buf_release(req->post_data, &len);
	len++;

	text = (char *)kore_malloc(len);
	kore_strlcpy(text, (char *)data, len);
	free(data);

	return (text);
}

static int
http_generic_404(struct http_request *req)
{
	kore_log("http_generic_404(%s, %d, %s)",
	    req->host, req->method, req->path);

	return (http_response(req, 404, NULL, 0));
}

static int
http_post_data_recv(struct netbuf *nb)
{
	struct http_request	*req = (struct http_request *)nb->extra;

	kore_buf_append(req->post_data, nb->buf, nb->offset);
	req->flags |= HTTP_REQUEST_COMPLETE;

	return (KORE_RESULT_OK);
}
