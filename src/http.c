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

#include "kore.h"
#include "http.h"

#include <sys/param.h>

static int		http_post_data_recv(struct netbuf *);
static int		http_send_done(struct netbuf *);

static TAILQ_HEAD(, http_request)	http_requests;

int		http_request_count;

void
http_init(void)
{
	http_request_count = 0;
	TAILQ_INIT(&http_requests);
}

int
http_request_new(struct connection *c, struct spdy_stream *s, char *host,
    char *method, char *path, struct http_request **out)
{
	struct http_request		*req;

	kore_debug("http_request_new(%p, %p, %s, %s, %s)", c, s,
	    host, method, path);

	if (strlen(host) >= KORE_DOMAINNAME_LEN - 1)
		return (KORE_RESULT_ERROR);
	if (strlen(path) >= HTTP_URI_LEN - 1)
		return (KORE_RESULT_ERROR);

	req = (struct http_request *)kore_malloc(sizeof(*req));
	req->end = 0;
	req->start = 0;
	req->flags = 0;
	req->owner = c;
	req->status = 0;
	req->stream = s;
	req->post_data = NULL;
	kore_strlcpy(req->host, host, sizeof(req->host));
	kore_strlcpy(req->path, path, sizeof(req->path));

	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));
	TAILQ_INIT(&(req->arguments));

	if (!strcasecmp(method, "get")) {
		req->method = HTTP_METHOD_GET;
		req->flags |= HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "post")) {
		req->method = HTTP_METHOD_POST;
	} else {
		kore_debug("invalid method specified in request: %s", method);
		http_request_free(req);
		return (KORE_RESULT_ERROR);
	}

	if (s != NULL) {
		if (!http_request_header_get(req, "user-agent", &(req->agent)))
			req->agent = kore_strdup("unknown");
	} else {
		req->agent = NULL;
	}

	if (out != NULL)
		*out = req;

	http_request_count++;
	TAILQ_INSERT_TAIL(&http_requests, req, list);
	return (KORE_RESULT_OK);
}

void
http_process(void)
{
	struct http_request	*req, *next;
	int			r, (*hdlr)(struct http_request *);

	for (req = TAILQ_FIRST(&http_requests); req != NULL; req = next) {
		next = TAILQ_NEXT(req, list);

		if (req->flags & HTTP_REQUEST_DELETE) {
			TAILQ_REMOVE(&http_requests, req, list);
			http_request_free(req);
			http_request_count--;
			continue;
		}

		if (!(req->flags & HTTP_REQUEST_COMPLETE))
			continue;

		hdlr = kore_module_handler_find(req->host, req->path);
		req->start = kore_time_ms();
		if (hdlr == NULL)
			r = http_generic_404(req);
		else
			r = hdlr(req);
		req->end = kore_time_ms();

		switch (r) {
		case KORE_RESULT_OK:
			r = net_send_flush(req->owner);
			if (r == KORE_RESULT_ERROR)
				kore_connection_disconnect(req->owner);
			break;
		case KORE_RESULT_ERROR:
			kore_connection_disconnect(req->owner);
			break;
		case KORE_RESULT_RETRY:
			break;
		}

		if (r != KORE_RESULT_RETRY) {
			kore_accesslog(req);

			TAILQ_REMOVE(&http_requests, req, list);
			http_request_free(req);
			http_request_count--;
		}
	}
}

void
http_response_header_add(struct http_request *req, char *header, char *value)
{
	struct http_header	*hdr;

	kore_debug("http_response_header_add(%p, %s, %s)", req, header, value);

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
		kore_mem_free(hdr->header);
		kore_mem_free(hdr->value);
		kore_mem_free(hdr);
	}

	for (hdr = TAILQ_FIRST(&(req->req_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->req_headers), hdr, list);
		kore_mem_free(hdr->header);
		kore_mem_free(hdr->value);
		kore_mem_free(hdr);
	}

	for (q = TAILQ_FIRST(&(req->arguments)); q != NULL; q = qnext) {
		qnext = TAILQ_NEXT(q, list);

		TAILQ_REMOVE(&(req->arguments), q, list);
		kore_mem_free(q->name);
		if (q->value != NULL)
			kore_mem_free(q->value);
		kore_mem_free(q);
	}

	if (req->agent != NULL)
		kore_mem_free(req->agent);
	kore_mem_free(req);
}

int
http_response(struct http_request *req, int status, u_int8_t *d, u_int32_t len)
{
	struct netbuf			*nb;
	u_int32_t			hlen;
	struct http_header		*hdr;
	struct kore_buf			*buf;
	u_int8_t			*htext;
	struct spdy_header_block	*hblock;
	char				sbuf[512];

	kore_debug("http_response(%p, %d, %p, %d)", req, status, d, len);

	req->status = status;
	if (req->owner->proto == CONN_PROTO_SPDY) {
		snprintf(sbuf, sizeof(sbuf), "%d", status);

		hblock = spdy_header_block_create(SPDY_HBLOCK_NORMAL);
		spdy_header_block_add(hblock, ":status", sbuf);
		spdy_header_block_add(hblock, ":version", "HTTP/1.1");
		spdy_header_block_add(hblock, ":server", kore_version_string);
		TAILQ_FOREACH(hdr, &(req->resp_headers), list)
			spdy_header_block_add(hblock, hdr->header, hdr->value);

		htext = spdy_header_block_release(req->owner, hblock, &hlen);
		if (htext == NULL)
			return (KORE_RESULT_ERROR);

		spdy_frame_send(req->owner, SPDY_CTRL_FRAME_SYN_REPLY,
		    0, hlen, req->stream, 0);
		net_send_queue(req->owner, htext, hlen, 0, NULL, NULL);
		kore_mem_free(htext);

		if (len > 0) {
			spdy_frame_send(req->owner, SPDY_DATA_FRAME,
			    0, len, req->stream, 0);
			net_send_queue(req->owner, d, len, 0, &nb,
			    spdy_frame_data_done);
			nb->extra = req->stream;
		}

		spdy_frame_send(req->owner, SPDY_DATA_FRAME,
		    FLAG_FIN, 0, req->stream, 0);
	} else {
		buf = kore_buf_create(KORE_BUF_INITIAL);

		kore_buf_appendf(buf, "HTTP/1.1 %d\r\n", status);
		kore_buf_appendf(buf, "Content-length: %d\r\n", len);
		kore_buf_appendf(buf, "Connection: keep-alive\r\n");
		kore_buf_appendf(buf, "Keep-Alive: timeout=20\r\n");
		kore_buf_appendf(buf, "Server: %s\r\n", kore_version_string);

		TAILQ_FOREACH(hdr, &(req->resp_headers), list) {
			kore_buf_appendf(buf, "%s: %s\r\n",
			    hdr->header, hdr->value);
		}

		kore_buf_append(buf, (u_int8_t *)"\r\n", 2);
		htext = kore_buf_release(buf, &hlen);
		net_send_queue(req->owner, htext, hlen, 0, NULL, NULL);
		kore_mem_free(htext);

		net_send_queue(req->owner, d, len, 0, NULL, http_send_done);
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

	kore_debug("http_header_recv(%p)", nb);

	ch = nb->buf[nb->len - 1];
	nb->buf[nb->len - 1] = '\0';

	if ((end_headers = (u_int8_t *)strrchr((char *)nb->buf, '\r')) == NULL)
		return (KORE_RESULT_OK);
	if (nb->len > 2 && strncmp(((char *)end_headers - 2), "\r\n\r\n", 4))
		return (KORE_RESULT_OK);

	nb->buf[nb->len - 1] = ch;
	nb->flags |= NETBUF_FORCE_REMOVE;
	end_headers += 2;

	len = end_headers - nb->buf;
	hbuf = (char *)kore_malloc(len + 1);
	kore_strlcpy(hbuf, (char *)nb->buf, len + 1);

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2) {
		kore_mem_free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	if ((strlen(headers[0]) > 3 && strncasecmp(headers[0], "get", 3)) &&
	    (strlen(headers[0]) > 4 && strncasecmp(headers[0], "post", 4))) {
		kore_mem_free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3) {
		kore_mem_free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	host[0] = NULL;
	for (i = 0; i < h; i++) {
		if (strncasecmp(headers[i], "host",
		    MIN(strlen(headers[i]), strlen("host"))))
			continue;

		v = kore_split_string(headers[i], ":", host, 3);
		if (v != 2) {
			kore_mem_free(hbuf);
			return (KORE_RESULT_ERROR);
		}

		if (strlen(host[0]) != 4 || strncasecmp(host[0], "host", 4) ||
		    strlen(host[1]) < 4) {
			kore_mem_free(hbuf);
			return (KORE_RESULT_ERROR);
		}

		host[1]++;
		skip = i;
		break;
	}

	if (host[0] == NULL) {
		kore_mem_free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	if (!http_request_new(c, NULL, host[1], request[0], request[1], &req)) {
		kore_mem_free(hbuf);
		return (KORE_RESULT_ERROR);
	}

	for (i = 1; i < h; i++) {
		if (i == skip)
			continue;

		p = strchr(headers[i], ':');
		if (p == NULL) {
			kore_debug("malformed header: '%s'", headers[i]);
			continue;
		}

		*(p++) = '\0';
		if (*p == ' ')
			p++;
		hdr = (struct http_header *)kore_malloc(sizeof(*hdr));
		hdr->header = kore_strdup(headers[i]);
		hdr->value = kore_strdup(p);
		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);

		if (req->agent == NULL &&
		    !strcasecmp(hdr->header, "user-agent"))
			req->agent = kore_strdup(hdr->value);
	}

	kore_mem_free(hbuf);

	if (req->method == HTTP_METHOD_POST) {
		if (!http_request_header_get(req, "content-length", &p)) {
			kore_debug("POST but no content-length");
			req->flags |= HTTP_REQUEST_DELETE;
			return (KORE_RESULT_ERROR);
		}

		clen = kore_strtonum(p, 0, UINT_MAX, &v);
		if (v == KORE_RESULT_ERROR) {
			kore_mem_free(p);
			kore_debug("content-length invalid: %s", p);
			req->flags |= HTTP_REQUEST_DELETE;
			return (KORE_RESULT_ERROR);
		}

		kore_mem_free(p);
		req->post_data = kore_buf_create(clen);
		kore_buf_append(req->post_data, end_headers,
		    (nb->offset - len));

		bytes_left = clen - (nb->offset - len);
		kore_debug("need %ld more bytes for POST", bytes_left);
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
		kore_debug("HTTP_METHOD_GET not supported for arguments");
		return (0);
	}

	count = 0;
	v = kore_split_string(query, "&", args, HTTP_MAX_QUERY_ARGS);
	for (i = 0; i < v; i++) {
		c = kore_split_string(args[i], "=", val, 3);
		if (c != 1 && c != 2) {
			kore_debug("malformed query argument");
			continue;
		}

		q = (struct http_arg *)kore_malloc(sizeof(*q));
		q->name = kore_strdup(val[0]);
		if (c == 2)
			q->value = kore_strdup(val[1]);
		else
			q->value = NULL;
		TAILQ_INSERT_TAIL(&(req->arguments), q, list);
		count++;
	}

	kore_mem_free(query);
	return (count);
}

int
http_argument_lookup(struct http_request *req, const char *name, char **out)
{
	struct http_arg		*q;

	TAILQ_FOREACH(q, &(req->arguments), list) {
		if (!strcmp(q->name, name)) {
			if (q->value == NULL)
				return (KORE_RESULT_ERROR);
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
	kore_mem_free(data);

	return (text);
}

int
http_generic_404(struct http_request *req)
{
	kore_debug("http_generic_404(%s, %d, %s)",
	    req->host, req->method, req->path);

	return (http_response(req, 404, NULL, 0));
}

static int
http_post_data_recv(struct netbuf *nb)
{
	struct http_request	*req = (struct http_request *)nb->extra;

	kore_buf_append(req->post_data, nb->buf, nb->offset);
	req->flags |= HTTP_REQUEST_COMPLETE;

	kore_debug("post complete for request %p", req);

	return (KORE_RESULT_OK);
}

static int
http_send_done(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;

	net_recv_queue(c, HTTP_HEADER_MAX_LEN,
	    NETBUF_CALL_CB_ALWAYS, NULL, http_header_recv);

	return (KORE_RESULT_OK);
}
