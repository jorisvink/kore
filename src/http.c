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

#include <ctype.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

static char		*http_status_text(int);
static int		http_post_data_recv(struct netbuf *);
static int		http_send_done(struct netbuf *);

static TAILQ_HEAD(, http_request)	http_requests;
static struct kore_pool			http_request_pool;
static struct kore_pool			http_header_pool;

int		http_request_count;

void
http_init(void)
{
	http_request_count = 0;
	TAILQ_INIT(&http_requests);

	kore_pool_init(&http_request_pool, "http_request_pool",
	    sizeof(struct http_request), worker_max_connections);
	kore_pool_init(&http_header_pool, "http_header_pool",
	    sizeof(struct http_header),
	    worker_max_connections * HTTP_REQ_HEADER_MAX);
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

	req = kore_pool_get(&http_request_pool);
	req->end = 0;
	req->start = 0;
	req->flags = 0;
	req->owner = c;
	req->status = 0;
	req->stream = s;
	req->post_data = NULL;
	req->hdlr_extra = NULL;
	req->multipart_body = NULL;
	kore_strlcpy(req->host, host, sizeof(req->host));
	kore_strlcpy(req->path, path, sizeof(req->path));

	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));
	TAILQ_INIT(&(req->arguments));
	TAILQ_INIT(&(req->files));

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
	TAILQ_INSERT_TAIL(&(c->http_requests), req, olist);

	return (KORE_RESULT_OK);
}

void
http_process(void)
{
	struct http_request		*req, *next;
	struct kore_module_handle	*hdlr;
	int				r, (*cb)(struct http_request *);

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
		if (hdlr == NULL) {
			r = http_generic_404(req);
		} else {
			cb = hdlr->addr;

			worker->active_hdlr = hdlr;
			r = cb(req);
			worker->active_hdlr = NULL;
		}
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

	hdr = kore_pool_get(&http_header_pool);
	hdr->header = kore_strdup(header);
	hdr->value = kore_strdup(value);
	TAILQ_INSERT_TAIL(&(req->resp_headers), hdr, list);
}

void
http_request_free(struct http_request *req)
{
	struct http_file	*f, *fnext;
	struct http_arg		*q, *qnext;
	struct http_header	*hdr, *next;

	TAILQ_REMOVE(&(req->owner->http_requests), req, olist);

	for (hdr = TAILQ_FIRST(&(req->resp_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->resp_headers), hdr, list);
		kore_mem_free(hdr->header);
		kore_mem_free(hdr->value);
		kore_pool_put(&http_header_pool, hdr);
	}

	for (hdr = TAILQ_FIRST(&(req->req_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->req_headers), hdr, list);
		kore_mem_free(hdr->header);
		kore_mem_free(hdr->value);
		kore_pool_put(&http_header_pool, hdr);
	}

	for (q = TAILQ_FIRST(&(req->arguments)); q != NULL; q = qnext) {
		qnext = TAILQ_NEXT(q, list);

		TAILQ_REMOVE(&(req->arguments), q, list);
		kore_mem_free(q->name);

		if (q->value != NULL)
			kore_mem_free(q->value);
		kore_mem_free(q);
	}

	for (f = TAILQ_FIRST(&(req->files)); f != NULL; f = fnext) {
		fnext = TAILQ_NEXT(f, list);
		TAILQ_REMOVE(&(req->files), f, list);

		kore_mem_free(f->filename);
		kore_mem_free(f->name);
		kore_mem_free(f);
	}

	if (req->method == HTTP_METHOD_POST && req->post_data != NULL)
		kore_buf_free(req->post_data);
	if (req->method == HTTP_METHOD_POST && req->multipart_body != NULL)
		kore_mem_free(req->multipart_body);

	if (req->agent != NULL)
		kore_mem_free(req->agent);
	if (req->hdlr_extra != NULL)
		kore_mem_free(req->hdlr_extra);

	kore_pool_put(&http_request_pool, req);
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
		snprintf(sbuf, sizeof(sbuf),
		    "%d %s", status, http_status_text(status));

		hblock = spdy_header_block_create(SPDY_HBLOCK_NORMAL);
		spdy_header_block_add(hblock, ":status", sbuf);
		spdy_header_block_add(hblock, ":version", "HTTP/1.1");
		spdy_header_block_add(hblock, ":server", KORE_NAME_STRING);
		TAILQ_FOREACH(hdr, &(req->resp_headers), list)
			spdy_header_block_add(hblock, hdr->header, hdr->value);

		htext = spdy_header_block_release(req->owner, hblock, &hlen);
		if (htext == NULL) {
			spdy_session_teardown(req->owner,
			    SPDY_SESSION_ERROR_INTERNAL);
			return (KORE_RESULT_OK);
		}

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

		kore_buf_appendf(buf, "HTTP/1.1 %d %s\r\n",
		    status, http_status_text(status));
		kore_buf_appendf(buf, "Content-length: %d\r\n", len);
		kore_buf_appendf(buf, "Connection: keep-alive\r\n");
		kore_buf_appendf(buf, "Keep-Alive: timeout=20\r\n");
		kore_buf_appendf(buf, "Server: %s\r\n", KORE_NAME_STRING);

		TAILQ_FOREACH(hdr, &(req->resp_headers), list) {
			kore_buf_appendf(buf, "%s: %s\r\n",
			    hdr->header, hdr->value);
		}

		kore_buf_append(buf, "\r\n", 2);
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
				*out = kore_malloc(r);
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
	size_t			clen, len;
	u_int8_t		*end_headers;
	int			h, i, v, skip, bytes_left;
	char			*request[4], *host[3], *hbuf;
	char			*p, *headers[HTTP_REQ_HEADER_MAX];
	struct connection	*c = (struct connection *)nb->owner;

	kore_debug("http_header_recv(%p)", nb);

	if (nb->len < 4)
		return (KORE_RESULT_OK);

	end_headers = kore_mem_find(nb->buf, nb->offset, "\r\n\r\n", 4);
	if (end_headers == NULL)
		return (KORE_RESULT_OK);

	*end_headers = '\0';
	end_headers += 4;
	nb->flags |= NETBUF_FORCE_REMOVE;
	len = end_headers - nb->buf;
	hbuf = (char *)nb->buf;

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2)
		return (KORE_RESULT_ERROR);

	if ((strlen(headers[0]) > 3 && strncasecmp(headers[0], "get", 3)) &&
	    (strlen(headers[0]) > 4 && strncasecmp(headers[0], "post", 4)))
		return (KORE_RESULT_ERROR);

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3)
		return (KORE_RESULT_ERROR);

	host[0] = NULL;
	for (i = 0; i < h; i++) {
		if (strncasecmp(headers[i], "host",
		    MIN(strlen(headers[i]), strlen("host"))))
			continue;

		v = kore_split_string(headers[i], ":", host, 3);
		if (v != 2)
			return (KORE_RESULT_ERROR);

		if (strlen(host[0]) != 4 || strncasecmp(host[0], "host", 4) ||
		    strlen(host[1]) < 4)
			return (KORE_RESULT_ERROR);

		host[1]++;
		skip = i;
		break;
	}

	if (host[0] == NULL)
		return (KORE_RESULT_ERROR);

	if (!http_request_new(c, NULL, host[1], request[0], request[1], &req))
		return (KORE_RESULT_ERROR);

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
		hdr = kore_pool_get(&http_header_pool);
		hdr->header = kore_strdup(headers[i]);
		hdr->value = kore_strdup(p);
		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);

		if (req->agent == NULL &&
		    !strcasecmp(hdr->header, "user-agent"))
			req->agent = kore_strdup(hdr->value);
	}

	if (req->method == HTTP_METHOD_POST) {
		if (!http_request_header_get(req, "content-length", &p)) {
			kore_debug("POST but no content-length");
			req->flags |= HTTP_REQUEST_DELETE;
			return (KORE_RESULT_ERROR);
		}

		clen = kore_strtonum(p, 10, 0, UINT_MAX, &v);
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
		if (bytes_left > 0) {
			kore_debug("%ld/%ld (%ld - %ld) more bytes for POST",
			    bytes_left, clen, nb->offset, len);
			net_recv_queue(c, bytes_left,
			    0, &nnb, http_post_data_recv);
			nnb->extra = req;
		} else if (bytes_left == 0) {
			req->flags |= HTTP_REQUEST_COMPLETE;
		} else {
			kore_debug("bytes_left would become zero (%ld)", clen);
			return (KORE_RESULT_ERROR);
		}
	}

	return (KORE_RESULT_OK);
}

int
http_populate_arguments(struct http_request *req)
{
	u_int32_t		len;
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

		if (val[1] == NULL)
			len = 0;
		else
			len = strlen(val[1]);

		http_argument_add(req, val[0], val[1], len);
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

int
http_argument_urldecode(char *arg)
{
	u_int8_t	v;
	int		err;
	size_t		len;
	char		*p, *in, h[5];

	p = arg;
	in = arg;
	len = strlen(arg);

	while (*p != '\0' && p < (arg + len)) {
		if (*p == '+')
			*p = ' ';
		if (*p != '%') {
			*in++ = *p++;
			continue;
		}

		if ((p + 2) >= (arg + len)) {
			kore_debug("overflow in '%s'", arg);
			return (KORE_RESULT_ERROR);
		}

		if (!isxdigit(*(p + 1)) || !isxdigit(*(p + 2))) {
			*in++ = *p++;
			continue;
		}

		h[0] = '0';
		h[1] = 'x';
		h[2] = *(p + 1);
		h[3] = *(p + 2);
		h[4] = '\0';

		v = kore_strtonum(h, 16, 32, 127, &err);
		if (err != KORE_RESULT_OK)
			return (err);

		*in++ = (char)v;
		p += 3;
	}

	*in = '\0';
	return (KORE_RESULT_OK);
}

int
http_argument_multiple_lookup(struct http_request *req, struct http_arg *args)
{
	int		i, c;

	c = 0;
	for (i = 0; args[i].name != NULL; i++) {
		if (!http_argument_lookup(req, args[i].name,
		    &(args[i].value))) {
			args[i].value = NULL;
		} else {
			c++;
		}
	}

	return (c);
}

void
http_argument_multiple_free(struct http_arg *args)
{
	int		i;

	for (i = 0; args[i].name != NULL; i++) {
		if (args[i].value != NULL)
			kore_mem_free(args[i].value);
	}
}

void
http_argument_add(struct http_request *req, char *name,
    char *value, u_int32_t len)
{
	struct http_arg		*q;

	q = kore_malloc(sizeof(struct http_arg));
	q->name = kore_strdup(name);

	if (len > 0) {
		q->value = kore_malloc(len + 1);
		kore_strlcpy(q->value, value, len + 1);
	} else {
		q->value = NULL;
	}

	TAILQ_INSERT_TAIL(&(req->arguments), q, list);
}

void
http_file_add(struct http_request *req, char *name, char *filename,
    u_int8_t *data, u_int32_t len)
{
	struct http_file	*f;

	f = kore_malloc(sizeof(struct http_file));
	f->len = len;
	f->data = data;
	f->name = kore_strdup(name);
	f->filename = kore_strdup(filename);

	TAILQ_INSERT_TAIL(&(req->files), f, list);
}

int
http_file_lookup(struct http_request *req, char *name, char **fname,
    u_int8_t **data, u_int32_t *len)
{
	struct http_file	*f;

	TAILQ_FOREACH(f, &(req->files), list) {
		if (!strcmp(f->name, name)) {
			*len = f->len;
			*data = f->data;
			*fname = f->filename;
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

int
http_populate_multipart_form(struct http_request *req, int *v)
{
	int		h, i, c;
	u_int32_t	blen, slen, len;
	u_int8_t	*s, *end, *e, *end_headers, *data;
	char		*d, *val, *type, *boundary, *fname;
	char		*headers[5], *args[5], *opt[5], *name;

	*v = 0;

	if (req->method != HTTP_METHOD_POST)
		return (KORE_RESULT_ERROR);

	if (!http_request_header_get(req, "content-type", &type))
		return (KORE_RESULT_ERROR);

	h = kore_split_string(type, ";", args, 3);
	if (h != 2) {
		kore_mem_free(type);
		return (KORE_RESULT_ERROR);
	}

	if (strcasecmp(args[0], "multipart/form-data")) {
		kore_mem_free(type);
		return (KORE_RESULT_ERROR);
	}

	if ((val = strchr(args[1], '=')) == NULL) {
		kore_mem_free(type);
		return (KORE_RESULT_ERROR);
	}

	val++;
	slen = strlen(val);
	boundary = kore_malloc(slen + 3);
	snprintf(boundary, slen + 3, "--%s", val);
	slen = strlen(boundary);

	kore_mem_free(type);

	req->multipart_body = http_post_data_bytes(req, &blen);
	if (slen < 3 || blen < (slen * 2)) {
		kore_mem_free(boundary);
		return (KORE_RESULT_ERROR);
	}

	end = req->multipart_body + blen - 2;
	if (end < req->multipart_body || (end - 2) < req->multipart_body) {
		kore_mem_free(boundary);
		return (KORE_RESULT_ERROR);
	}

	if (memcmp((end - slen - 2), boundary, slen) ||
	    memcmp((end - 2), "--", 2)) {
		kore_mem_free(boundary);
		return (KORE_RESULT_ERROR);
	}

	v = 0;
	s = req->multipart_body + slen + 2;
	while (s < end) {
		e = kore_mem_find(s, end - s, boundary, slen);
		if (e == NULL) {
			kore_mem_free(boundary);
			return (KORE_RESULT_ERROR);
		}

		*(e - 2) = '\0';
		end_headers = kore_mem_find(s, (e - 2) - s, "\r\n\r\n", 4);
		if (end_headers == NULL) {
			kore_mem_free(boundary);
			return (KORE_RESULT_ERROR);
		}

		*end_headers = '\0';
		data = end_headers + 4;

		h = kore_split_string((char *)s, "\r\n", headers, 5);
		for (i = 0; i < h; i++) {
			c = kore_split_string(headers[i], ":", args, 5);
			if (c != 2)
				continue;

			/* Ignore other headers for now. */
			if (strcasecmp(args[0], "content-disposition"))
				continue;

			for (d = args[1]; isspace(*d); d++)
				;

			c = kore_split_string(d, ";", opt, 5);
			if (strcasecmp(opt[0], "form-data"))
				continue;

			if ((val = strchr(opt[1], '=')) == NULL)
				continue;
			if (strlen(val) < 3)
				continue;

			val++;
			kore_strip_chars(val, '"', &name);

			if (opt[2] == NULL) {
				http_argument_add(req, name,
				    (char *)data, (e - 2) - data);
				kore_mem_free(name);
				continue;
			}

			for (d = opt[2]; isspace(*d); d++)
				;

			len = MIN(strlen("filename="), strlen(d));
			if (!strncasecmp(d, "filename=", len)) {
				if ((val = strchr(d, '=')) == NULL) {
					kore_mem_free(name);
					continue;
				}

				val++;
				kore_strip_chars(val, '"', &fname);
				if (strlen(fname) > 0) {
					http_file_add(req, name, fname,
					    data, (e - 2) - data);
				}

				kore_mem_free(fname);
			} else {
				kore_debug("got unknown: %s", opt[2]);
			}

			kore_mem_free(name);
		}

		s = e + slen + 2;
	}

	kore_mem_free(boundary);

	return (KORE_RESULT_OK);
}

char *
http_post_data_text(struct http_request *req)
{
	u_int32_t	len;
	u_int8_t	*data;
	char		*text;

	data = kore_buf_release(req->post_data, &len);
	req->post_data = NULL;
	len++;

	text = kore_malloc(len);
	kore_strlcpy(text, (char *)data, len);
	kore_mem_free(data);

	return (text);
}

u_int8_t *
http_post_data_bytes(struct http_request *req, u_int32_t *len)
{
	u_int8_t	*data;

	data = kore_buf_release(req->post_data, len);
	req->post_data = NULL;

	return (data);
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

static char *
http_status_text(int status)
{
	char		*r;

	switch (status) {
	case HTTP_STATUS_CONTINUE:
		r = "Continue";
		break;
	case HTTP_STATUS_SWITCHING_PROTOCOLS:
		r = "Switching Protocols";
		break;
	case HTTP_STATUS_OK:
		r = "OK";
		break;
	case HTTP_STATUS_CREATED:
		r = "Created";
		break;
	case HTTP_STATUS_ACCEPTED:
		r = "Accepted";
		break;
	case HTTP_STATUS_NON_AUTHORITATIVE:
		r = "Non-Authoritative Information";
		break;
	case HTTP_STATUS_NO_CONTENT:
		r = "No Content";
		break;
	case HTTP_STATUS_RESET_CONTENT:
		r = "Reset Content";
		break;
	case HTTP_STATUS_PARTIAL_CONTENT:
		r = "Partial Content";
		break;
	case HTTP_STATUS_MULTIPLE_CHOICES:
		r = "Multiple Choices";
		break;
	case HTTP_STATUS_MOVED_PERMANENTLY:
		r = "Moved Permanently";
		break;
	case HTTP_STATUS_FOUND:
		r = "Found";
		break;
	case HTTP_STATUS_SEE_OTHER:
		r = "See Other";
		break;
	case HTTP_STATUS_NOT_MODIFIED:
		r = "Not Modified";
		break;
	case HTTP_STATUS_USE_PROXY:
		r = "Use Proxy";
		break;
	case HTTP_STATUS_TEMPORARY_REDIRECT:
		r = "Temporary Redirect";
		break;
	case HTTP_STATUS_BAD_REQUEST:
		r = "Bad Request";
		break;
	case HTTP_STATUS_UNAUTHORIZED:
		r = "Unauthorized";
		break;
	case HTTP_STATUS_PAYMENT_REQUIRED:
		r = "Payment Required";
		break;
	case HTTP_STATUS_FORBIDDEN:
		r = "Forbidden";
		break;
	case HTTP_STATUS_NOT_FOUND:
		r = "Not Found";
		break;
	case HTTP_STATUS_METHOD_NOT_ALLOWED:
		r = "Method Not Allowed";
		break;
	case HTTP_STATUS_NOT_ACCEPTABLE:
		r = "Not Acceptable";
		break;
	case HTTP_STATUS_PROXY_AUTH_REQUIRED:
		r = "Proxy Authentication Required";
		break;
	case HTTP_STATUS_REQUEST_TIMEOUT:
		r = "Request Time-out";
		break;
	case HTTP_STATUS_CONFLICT:
		r = "Conflict";
		break;
	case HTTP_STATUS_GONE:
		r = "Gone";
		break;
	case HTTP_STATUS_LENGTH_REQUIRED:
		r = "Length Required";
		break;
	case HTTP_STATUS_PRECONDITION_FAILED:
		r = "Precondition Failed";
		break;
	case HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE:
		r = "Request Entity Too Large";
		break;
	case HTTP_STATUS_REQUEST_URI_TOO_LARGE:
		r = "Request-URI Too Large";
		break;
	case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
		r = "Unsupported Media Type";
		break;
	case HTTP_STATUS_REQUEST_RANGE_INVALID:
		r = "Requested range not satisfiable";
		break;
	case HTTP_STATUS_EXPECTATION_FAILED:
		r = "Expectation Failed";
		break;
	case HTTP_STATUS_INTERNAL_ERROR:
		r = "Internal Server Error";
		break;
	case HTTP_STATUS_NOT_IMPLEMENTED:
		r = "Not Implemented";
		break;
	case HTTP_STATUS_BAD_GATEWAY:
		r = "Bad Gateway";
		break;
	case HTTP_STATUS_SERVICE_UNAVAILABLE:
		r = "Service Unavailable";
		break;
	case HTTP_STATUS_GATEWAY_TIMEOUT:
		r = "Gateway Time-out";
		break;
	case HTTP_STATUS_BAD_VERSION:
		r = "HTTP Version not supported";
		break;
	default:
		r = "";
		break;
	}

	return (r);
}
