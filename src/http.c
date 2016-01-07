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

#include <ctype.h>
#include <inttypes.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

static int		http_body_recv(struct netbuf *);
static void		http_error_response(struct connection *, int);
static void		http_argument_add(struct http_request *, const char *,
			    void *, u_int32_t, int);
static void		http_file_add(struct http_request *, const char *,
			    const char *, u_int8_t *, u_int32_t);
static void		http_response_normal(struct http_request *,
			    struct connection *, int, void *, u_int32_t);

static struct kore_buf			*header_buf;
static char				http_version[32];
static u_int16_t			http_version_len;
static TAILQ_HEAD(, http_request)	http_requests;
static TAILQ_HEAD(, http_request)	http_requests_sleeping;
static struct kore_pool			http_request_pool;
static struct kore_pool			http_header_pool;
static struct kore_pool			http_host_pool;
static struct kore_pool			http_path_pool;

int		http_request_count = 0;
u_int32_t	http_request_limit = HTTP_REQUEST_LIMIT;
u_int64_t	http_hsts_enable = HTTP_HSTS_ENABLE;
u_int16_t	http_header_max = HTTP_HEADER_MAX_LEN;
u_int16_t	http_keepalive_time = HTTP_KEEPALIVE_TIME;
u_int64_t	http_body_max = HTTP_BODY_MAX_LEN;

void
http_init(void)
{
	int		prealloc, l;

	TAILQ_INIT(&http_requests);
	TAILQ_INIT(&http_requests_sleeping);

	header_buf = kore_buf_create(1024);

	l = snprintf(http_version, sizeof(http_version),
	    "server: kore (%d.%d.%d-%s)\r\n", KORE_VERSION_MAJOR,
	    KORE_VERSION_MINOR, KORE_VERSION_PATCH, KORE_VERSION_STATE);
	if (l == -1 || (size_t)l >= sizeof(http_version))
		fatal("http_init(): http_version buffer too small");

	http_version_len = l;

	prealloc = MIN((worker_max_connections / 10), 1000);
	kore_pool_init(&http_request_pool, "http_request_pool",
	    sizeof(struct http_request), prealloc);
	kore_pool_init(&http_header_pool, "http_header_pool",
	    sizeof(struct http_header), prealloc * HTTP_REQ_HEADER_MAX);

	kore_pool_init(&http_host_pool,
	    "http_host_pool", KORE_DOMAINNAME_LEN, prealloc);
	kore_pool_init(&http_path_pool,
	    "http_path_pool", HTTP_URI_LEN, prealloc);
}

int
http_request_new(struct connection *c, const char *host,
    const char *method, const char *path, const char *version,
    struct http_request **out)
{
	char				*p;
	struct http_request		*req;
	int				m, flags;
	size_t				hostlen, pathlen;

	kore_debug("http_request_new(%p, %s, %s, %s, %s)", c, host,
	    method, path, version);

	if ((hostlen = strlen(host)) >= KORE_DOMAINNAME_LEN - 1) {
		http_error_response(c, 500);
		return (KORE_RESULT_ERROR);
	}

	if ((pathlen = strlen(path)) >= HTTP_URI_LEN - 1) {
		http_error_response(c, 414);
		return (KORE_RESULT_ERROR);
	}

	if (strcasecmp(version, "http/1.1")) {
		http_error_response(c, 505);
		return (KORE_RESULT_ERROR);
	}

	if (!strcasecmp(method, "get")) {
		m = HTTP_METHOD_GET;
		flags = HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "delete")) {
		m = HTTP_METHOD_DELETE;
		flags = HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "post")) {
		m = HTTP_METHOD_POST;
		flags = HTTP_REQUEST_EXPECT_BODY;
	} else if (!strcasecmp(method, "put")) {
		m = HTTP_METHOD_PUT;
		flags = HTTP_REQUEST_EXPECT_BODY;
	} else if (!strcasecmp(method, "head")) {
		m = HTTP_METHOD_HEAD;
		flags = HTTP_REQUEST_COMPLETE;
	} else {
		http_error_response(c, 400);
		return (KORE_RESULT_ERROR);
	}

	req = kore_pool_get(&http_request_pool);
	req->end = 0;
	req->total = 0;
	req->start = 0;
	req->owner = c;
	req->status = 0;
	req->method = m;
	req->hdlr = NULL;
	req->agent = NULL;
	req->flags = flags;
	req->fsm_state = 0;
	req->http_body = NULL;
	req->hdlr_extra = NULL;
	req->query_string = NULL;
	req->multipart_body = NULL;

	if ((p = strrchr(host, ':')) != NULL)
		*p = '\0';

	req->host = kore_pool_get(&http_host_pool);
	(void)memcpy(req->host, host, hostlen);
	req->host[hostlen] = '\0';

	req->path = kore_pool_get(&http_path_pool);
	(void)memcpy(req->path, path, pathlen);
	req->path[pathlen] = '\0';

	if ((req->query_string = strchr(req->path, '?')) != NULL)
		*(req->query_string)++ = '\0';

	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));
	TAILQ_INIT(&(req->arguments));
	TAILQ_INIT(&(req->files));

#if defined(KORE_USE_TASKS)
	LIST_INIT(&(req->tasks));
#endif

#if defined(KORE_USE_PGSQL)
	LIST_INIT(&(req->pgsqls));
#endif

	http_request_count++;
	TAILQ_INSERT_HEAD(&http_requests, req, list);
	TAILQ_INSERT_TAIL(&(c->http_requests), req, olist);

	if (out != NULL)
		*out = req;

	return (KORE_RESULT_OK);
}

void
http_request_sleep(struct http_request *req)
{
	if (!(req->flags & HTTP_REQUEST_SLEEPING)) {
		kore_debug("http_request_sleep: %p napping", req);

		req->flags |= HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests, req, list);
		TAILQ_INSERT_TAIL(&http_requests_sleeping, req, list);
	}
}

void
http_request_wakeup(struct http_request *req)
{
	if (req->flags & HTTP_REQUEST_SLEEPING) {
		kore_debug("http_request_wakeup: %p woke up", req);

		req->flags &= ~HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests_sleeping, req, list);
		TAILQ_INSERT_TAIL(&http_requests, req, list);
	}
}

void
http_process(void)
{
	u_int32_t			count;
	struct http_request		*req, *next;

	count = 0;
	for (req = TAILQ_FIRST(&http_requests); req != NULL; req = next) {
		if (count >= http_request_limit)
			break;

		next = TAILQ_NEXT(req, list);
		if (req->flags & HTTP_REQUEST_DELETE) {
			http_request_free(req);
			continue;
		}

		/* Sleeping requests should be in http_requests_sleeping. */
		if (req->flags & HTTP_REQUEST_SLEEPING)
			fatal("http_process: sleeping request on list");

		if (!(req->flags & HTTP_REQUEST_COMPLETE))
			continue;

		count++;
		http_process_request(req, 0);
	}
}

void
http_process_request(struct http_request *req, int retry_only)
{
	struct kore_module_handle	*hdlr;
	int				r, (*cb)(struct http_request *);

	kore_debug("http_process_request: %p->%p (%s)",
	    req->owner, req, req->path);

	if (req->flags & HTTP_REQUEST_DELETE)
		return;

	if (req->hdlr != NULL)
		hdlr = req->hdlr;
	else
		hdlr = kore_module_handler_find(req->host, req->path);

	req->start = kore_time_ms();
	if (hdlr == NULL) {
		r = http_generic_404(req);
	} else {
		if (req->hdlr != hdlr && hdlr->auth != NULL)
			r = kore_auth_run(req, hdlr->auth);
		else
			r = KORE_RESULT_OK;

		switch (r) {
		case KORE_RESULT_OK:
			req->hdlr = hdlr;
			cb = hdlr->addr;
			worker->active_hdlr = hdlr;
			r = cb(req);
			worker->active_hdlr = NULL;
			break;
		case KORE_RESULT_RETRY:
			break;
		case KORE_RESULT_ERROR:
			/*
			 * Set r to KORE_RESULT_OK so we can properly
			 * flush the result from kore_auth_run().
			 */
			r = KORE_RESULT_OK;
			break;
		default:
			fatal("kore_auth() returned unknown %d", r);
		}
	}
	req->end = kore_time_ms();
	req->total += req->end - req->start;

	if (retry_only == 1 && r != KORE_RESULT_RETRY)
		fatal("http_process_request: expected RETRY but got %d", r);

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
		return;
	default:
		fatal("A page handler returned an unknown result: %d", r);
	}

	if (hdlr != NULL && hdlr->dom->accesslog != -1)
		kore_accesslog(req);

	req->flags |= HTTP_REQUEST_DELETE;
}

void
http_response_header(struct http_request *req,
    const char *header, const char *value)
{
	struct http_header	*hdr;

	kore_debug("http_response_header(%p, %s, %s)", req, header, value);

	hdr = kore_pool_get(&http_header_pool);
	hdr->header = kore_strdup(header);
	hdr->value = kore_strdup(value);
	TAILQ_INSERT_TAIL(&(req->resp_headers), hdr, list);
}

void
http_request_free(struct http_request *req)
{
#if defined(KORE_USE_TASKS)
	struct kore_task	*t, *nt;
	int			pending_tasks;
#endif
#if defined(KORE_USE_PGSQL)
	struct kore_pgsql	*pgsql;
#endif
	struct http_file	*f, *fnext;
	struct http_arg		*q, *qnext;
	struct http_header	*hdr, *next;

#if defined(KORE_USE_TASKS)
	pending_tasks = 0;
	for (t = LIST_FIRST(&(req->tasks)); t != NULL; t = nt) {
		nt = LIST_NEXT(t, rlist);
		if (!kore_task_finished(t)) {
			pending_tasks++;
		} else {
			kore_task_destroy(t);
		}
	}

	if (pending_tasks) {
		kore_debug("http_request_free %d pending tasks", pending_tasks);
		return;
	}
#endif

#if defined(KORE_USE_PGSQL)
	while (!LIST_EMPTY(&(req->pgsqls))) {
		pgsql = LIST_FIRST(&(req->pgsqls));
		kore_pgsql_cleanup(pgsql);
	}

	if (req->flags & HTTP_REQUEST_PGSQL_QUEUE)
		kore_pgsql_queue_remove(req);
#endif

	kore_debug("http_request_free: %p->%p", req->owner, req);

	kore_pool_put(&http_host_pool, req->host);
	kore_pool_put(&http_path_pool, req->path);

	req->host = NULL;
	req->path = NULL;

	TAILQ_REMOVE(&http_requests, req, list);
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
		if (q->s_value != NULL)
			kore_mem_free(q->s_value);

		kore_mem_free(q);
	}

	for (f = TAILQ_FIRST(&(req->files)); f != NULL; f = fnext) {
		fnext = TAILQ_NEXT(f, list);
		TAILQ_REMOVE(&(req->files), f, list);

		kore_mem_free(f->filename);
		kore_mem_free(f->name);
		kore_mem_free(f);
	}

	if (req->http_body != NULL)
		kore_buf_free(req->http_body);
	if (req->multipart_body != NULL)
		kore_mem_free(req->multipart_body);

	if (req->hdlr_extra != NULL &&
	    !(req->flags & HTTP_REQUEST_RETAIN_EXTRA))
		kore_mem_free(req->hdlr_extra);

	kore_pool_put(&http_request_pool, req);
	http_request_count--;
}

void
http_response(struct http_request *req, int status, void *d, u_int32_t l)
{
	kore_debug("http_response(%p, %d, %p, %d)", req, status, d, l);

	req->status = status;

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
	case CONN_PROTO_WEBSOCKET:
		http_response_normal(req, req->owner, status, d, l);
		break;
	default:
		fatal("http_response() bad proto %d", req->owner->proto);
		/* NOTREACHED. */
	}
}

void
http_response_stream(struct http_request *req, int status, void *base,
    u_int64_t len, int (*cb)(struct netbuf *), void *arg)
{
	struct netbuf		*nb;

	req->status = status;

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
		http_response_normal(req, req->owner, status, NULL, len);
		break;
	default:
		fatal("http_response_stream() bad proto %d", req->owner->proto);
		/* NOTREACHED. */
	}

	if (req->method != HTTP_METHOD_HEAD) {
		net_send_stream(req->owner, base, len, cb, &nb);
		nb->extra = arg;
	}
}

int
http_request_header(struct http_request *req, const char *header, char **out)
{
	struct http_header	*hdr;

	TAILQ_FOREACH(hdr, &(req->req_headers), list) {
		if (!strcasecmp(hdr->header, header)) {
			*out = hdr->value;
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

int
http_header_recv(struct netbuf *nb)
{
	size_t			len;
	u_int64_t		clen;
	struct http_header	*hdr;
	struct http_request	*req;
	u_int8_t		*end_headers;
	int			h, i, v, skip, bytes_left;
	char			*request[4], *host[3], *hbuf;
	char			*p, *headers[HTTP_REQ_HEADER_MAX];
	struct connection	*c = (struct connection *)nb->owner;

	kore_debug("http_header_recv(%p)", nb);

	if (nb->b_len < 4)
		return (KORE_RESULT_OK);

	skip = 4;
	end_headers = kore_mem_find(nb->buf, nb->s_off, "\r\n\r\n", 4);
	if (end_headers == NULL) {
		end_headers = kore_mem_find(nb->buf, nb->s_off, "\n\n", 2);
		if (end_headers == NULL)
			return (KORE_RESULT_OK);
		skip = 2;
	}

	*end_headers = '\0';
	end_headers += skip;
	nb->flags |= NETBUF_FORCE_REMOVE;
	len = end_headers - nb->buf;
	hbuf = (char *)nb->buf;

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2) {
		http_error_response(c, 400);
		return (KORE_RESULT_OK);
	}

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3) {
		http_error_response(c, 400);
		return (KORE_RESULT_OK);
	}

	skip = 0;
	host[0] = NULL;
	for (i = 0; i < h; i++) {
		if (strncasecmp(headers[i], "host", 4))
			continue;

		v = kore_split_string(headers[i], ":", host, 3);
		if (v != 2) {
			http_error_response(c, 400);
			return (KORE_RESULT_OK);
		}

		if ((host[1] - host[0]) != 5 ||
		    strncasecmp(host[0], "host", 4) || host[1] == '\0') {
			http_error_response(c, 400);
			return (KORE_RESULT_OK);
		}

		host[1]++;
		skip = i;
		break;
	}

	if (host[0] == NULL) {
		http_error_response(c, 400);
		return (KORE_RESULT_OK);
	}

	if (!http_request_new(c, host[1],
	    request[0], request[1], request[2], &req))
		return (KORE_RESULT_OK);

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
			req->agent = hdr->value;
	}

	if (req->flags & HTTP_REQUEST_EXPECT_BODY) {
		if (!http_request_header(req, "content-length", &p)) {
			kore_debug("expected body but no content-length");
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 411);
			return (KORE_RESULT_OK);
		}

		clen = kore_strtonum(p, 10, 0, LONG_MAX, &v);
		if (v == KORE_RESULT_ERROR) {
			kore_debug("content-length invalid: %s", p);
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 411);
			return (KORE_RESULT_OK);
		}

		if (clen == 0) {
			req->flags |= HTTP_REQUEST_COMPLETE;
			req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
			return (KORE_RESULT_OK);
		}

		if (clen > http_body_max) {
			kore_log(LOG_NOTICE, "body too large (%ld > %ld)",
			    clen, http_body_max);
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 411);
			return (KORE_RESULT_OK);
		}

		req->http_body = kore_buf_create(clen);
		kore_buf_append(req->http_body, end_headers,
		    (nb->s_off - len));

		bytes_left = clen - (nb->s_off - len);
		if (bytes_left > 0) {
			kore_debug("%ld/%ld (%ld - %ld) more bytes for body",
			    bytes_left, clen, nb->s_off, len);
			net_recv_reset(c, bytes_left, http_body_recv);
			c->rnb->extra = req;
			c->rnb->flags &= ~NETBUF_CALL_CB_ALWAYS;
		} else if (bytes_left == 0) {
			req->flags |= HTTP_REQUEST_COMPLETE;
			req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
		} else {
			kore_debug("bytes_left would become zero (%ld)", clen);
			http_error_response(req->owner, 500);
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
		if (req->http_body == NULL)
			return (0);
		query = http_body_text(req);
	} else {
		if (req->query_string == NULL)
			return (0);
		query = kore_strdup(req->query_string);
	}

	count = 0;
	v = kore_split_string(query, "&", args, HTTP_MAX_QUERY_ARGS);
	for (i = 0; i < v; i++) {
		c = kore_split_string(args[i], "=", val, 3);
		if (c != 1 && c != 2) {
			kore_debug("malformed query argument");
			continue;
		}

		if (val[1] != NULL) {
			len = strlen(val[1]);
			http_argument_add(req, val[0], val[1],
			    len, HTTP_ARG_TYPE_STRING);
			count++;
		}
	}

	kore_mem_free(query);
	return (count);
}

int
http_argument_get(struct http_request *req, const char *name,
    void **out, void *nout, u_int32_t *len, int type)
{
	struct http_arg		*q;

	if (len != NULL)
		*len = 0;

	TAILQ_FOREACH(q, &(req->arguments), list) {
		if (!strcmp(q->name, name)) {
			switch (type) {
			case HTTP_ARG_TYPE_RAW:
				if (len != NULL)
					*len = q->len;
				*out = q->value;
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_BYTE:
				COPY_ARG_TYPE(*(u_int8_t *)q->value,
				    len, u_int8_t);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_INT16:
				COPY_AS_INTTYPE(SHRT_MIN, SHRT_MAX, int16_t);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_UINT16:
				COPY_AS_INTTYPE(0, USHRT_MAX, u_int16_t);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_INT32:
				COPY_AS_INTTYPE(INT_MIN, INT_MAX, int32_t);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_UINT32:
				COPY_AS_INTTYPE(0, UINT_MAX, u_int32_t);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_INT64:
				COPY_AS_INTTYPE_64(int64_t, 1);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_UINT64:
				COPY_AS_INTTYPE_64(u_int64_t, 0);
				return (KORE_RESULT_OK);
			case HTTP_ARG_TYPE_STRING:
				CACHE_STRING();
				*out = q->s_value;
				if (len != NULL)
					*len = q->s_len - 1;
				return (KORE_RESULT_OK);
			default:
				return (KORE_RESULT_ERROR);
			}
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

		v = kore_strtonum(h, 16, 0, 255, &err);
		if (err != KORE_RESULT_OK)
			return (err);

		*in++ = (char)v;
		p += 3;
	}

	*in = '\0';
	return (KORE_RESULT_OK);
}

int
http_file_lookup(struct http_request *req, const char *name, char **fname,
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
	int		h, i, c, l;
	u_int32_t	blen, slen, len;
	u_int8_t	*s, *end, *e, *end_headers, *data;
	char		*d, *val, *type, *boundary, *fname;
	char		*headers[5], *args[5], *opt[5], *name;

	*v = 0;

	if (req->method != HTTP_METHOD_POST)
		return (KORE_RESULT_ERROR);

	if (!http_request_header(req, "content-type", &type))
		return (KORE_RESULT_ERROR);

	h = kore_split_string(type, ";", args, 3);
	if (h != 2)
		return (KORE_RESULT_ERROR);

	if (strcasecmp(args[0], "multipart/form-data"))
		return (KORE_RESULT_ERROR);

	if ((val = strchr(args[1], '=')) == NULL)
		return (KORE_RESULT_ERROR);

	val++;
	slen = strlen(val);
	boundary = kore_malloc(slen + 3);
	if (!kore_snprintf(boundary, slen + 3, &l, "--%s", val)) {
		kore_mem_free(boundary);
		return (KORE_RESULT_ERROR);
	}

	slen = l;

	req->multipart_body = http_body_bytes(req, &blen);
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
			if (c < 2)
				continue;

			if (strcasecmp(opt[0], "form-data"))
				continue;

			if ((val = strchr(opt[1], '=')) == NULL)
				continue;
			if (strlen(val) < 3)
				continue;

			val++;
			kore_strip_chars(val, '"', &name);

			if (opt[2] == NULL) {
				*v = *v + 1;
				http_argument_add(req, name,
				    data, (e - 2) - data, HTTP_ARG_TYPE_STRING);
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
					*v = *v + 1;
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

int
http_generic_404(struct http_request *req)
{
	kore_debug("http_generic_404(%s, %d, %s)",
	    req->host, req->method, req->path);

	http_response(req, 404, NULL, 0);

	return (KORE_RESULT_OK);
}

char *
http_body_text(struct http_request *req)
{
	u_int32_t	len;
	u_int8_t	*data;
	char		*text;

	if (req->http_body == NULL)
		return (NULL);

	data = kore_buf_release(req->http_body, &len);
	req->http_body = NULL;
	len++;

	text = kore_malloc(len);
	kore_strlcpy(text, (char *)data, len);
	kore_mem_free(data);

	return (text);
}

u_int8_t *
http_body_bytes(struct http_request *req, u_int32_t *len)
{
	u_int8_t	*data;

	if (req->http_body == NULL)
		return (NULL);

	data = kore_buf_release(req->http_body, len);
	req->http_body = NULL;

	return (data);
}

int
http_state_run(struct http_state *states, u_int8_t elm,
    struct http_request *req)
{
	int		r, done;

	done = 0;

	while (!done) {
		if (req->fsm_state >= elm) {
			fatal("http_state_run: fsm_state > elm (%d/%d)",
			    req->fsm_state, elm);
		}

		kore_debug("http_state_run: running %s",
		    states[req->fsm_state].name);

		r = states[req->fsm_state].cb(req);
		switch (r) {
		case HTTP_STATE_ERROR:
			return (KORE_RESULT_OK);
		case HTTP_STATE_RETRY:
			return (KORE_RESULT_RETRY);
		case HTTP_STATE_CONTINUE:
			break;
		case HTTP_STATE_COMPLETE:
			done = 1;
			break;
		default:
			fatal("http_state_run: unknown return value %d", r);
		}
	}

	req->fsm_state = 0;
	kore_debug("http_state_run(%p): done", req);

	return (KORE_RESULT_OK);
}

static void
http_argument_add(struct http_request *req, const char *name,
    void *value, u_int32_t len, int type)
{
	struct http_arg			*q;
	struct kore_handler_params	*p;

	if (len == 0 || value == NULL) {
		kore_debug("http_argument_add: with NULL value");
		return;
	}

	TAILQ_FOREACH(p, &(req->hdlr->params), list) {
		if (p->method != req->method)
			continue;

		if (!strcmp(p->name, name)) {
			if (type == HTTP_ARG_TYPE_STRING) {
				http_argument_urldecode(value);
				len = strlen(value);
			}

			if (kore_validator_check(req, p->validator, value)) {
				q = kore_malloc(sizeof(struct http_arg));
				q->len = len;
				q->s_value = NULL;
				q->name = kore_strdup(name);
				q->value = kore_malloc(len);
				memcpy(q->value, value, len);
				TAILQ_INSERT_TAIL(&(req->arguments), q, list);
			}

			return;
		}
	}
}

static void
http_file_add(struct http_request *req, const char *name, const char *filename,
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

static int
http_body_recv(struct netbuf *nb)
{
	struct http_request	*req = (struct http_request *)nb->extra;

	kore_buf_append(req->http_body, nb->buf, nb->s_off);

	req->flags |= HTTP_REQUEST_COMPLETE;
	req->flags &= ~HTTP_REQUEST_EXPECT_BODY;

	nb->extra = NULL;
	nb->flags |= NETBUF_CALL_CB_ALWAYS;

	kore_debug("received all body data for request %p", req);

	return (KORE_RESULT_OK);
}

static void
http_error_response(struct connection *c, int status)
{
	kore_debug("http_error_response(%p, %d)", c, status);

	switch (c->proto) {
	case CONN_PROTO_HTTP:
		http_response_normal(NULL, c, status, NULL, 0);
		break;
	default:
		fatal("http_error_response() bad proto %d", c->proto);
		/* NOTREACHED. */
	}
}

static void
http_response_normal(struct http_request *req, struct connection *c,
    int status, void *d, u_int32_t len)
{
	struct http_header	*hdr;
	char			*conn;
	int			connection_close;

	header_buf->offset = 0;

	kore_buf_appendf(header_buf, "HTTP/1.1 %d %s\r\n",
	    status, http_status_text(status));
	kore_buf_append(header_buf, http_version, http_version_len);

	if (c->flags & CONN_CLOSE_EMPTY)
		connection_close = 1;
	else
		connection_close = 0;

	if (connection_close == 0 && req != NULL) {
		if (http_request_header(req, "connection", &conn)) {
			if ((*conn == 'c' || *conn == 'C') &&
			    !strcasecmp(conn, "close"))
				connection_close = 1;
		}
	}

	/* Note that req CAN be NULL. */
	if (req != NULL && req->owner->proto != CONN_PROTO_WEBSOCKET) {
		if (http_keepalive_time && connection_close == 0) {
			kore_buf_appendf(header_buf,
			    "connection: keep-alive\r\n");
			kore_buf_appendf(header_buf,
			    "keep-alive: timeout=%d\r\n", http_keepalive_time);
		} else {
			c->flags |= CONN_CLOSE_EMPTY;
			kore_buf_appendf(header_buf, "connection: close\r\n");
		}
	}

	if (http_hsts_enable) {
		kore_buf_appendf(header_buf, "strict-transport-security: ");
		kore_buf_appendf(header_buf,
		    "max-age=%" PRIu64 "; includeSubDomains\r\n",
		    http_hsts_enable);
	}

	if (req != NULL) {
		TAILQ_FOREACH(hdr, &(req->resp_headers), list) {
			kore_buf_appendf(header_buf, "%s: %s\r\n",
			    hdr->header, hdr->value);
		}

		if (status != 204 && status >= 200 &&
		    !(req->flags & HTTP_REQUEST_NO_CONTENT_LENGTH)) {
			kore_buf_appendf(header_buf,
			    "content-length: %d\r\n", len);
		}
	} else {
		if (status != 204 && status >= 200) {
			kore_buf_appendf(header_buf,
			    "content-length: %d\r\n", len);
		}
	}

	kore_buf_append(header_buf, "\r\n", 2);
	net_send_queue(c, header_buf->data, header_buf->offset);

	if (d != NULL && req != NULL && req->method != HTTP_METHOD_HEAD)
		net_send_queue(c, d, len);

	if (!(c->flags & CONN_CLOSE_EMPTY))
		net_recv_reset(c, http_header_max, http_header_recv);
}

const char *
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
