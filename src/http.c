/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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
#include <netinet/in.h>

#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <float.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

#if defined(KORE_USE_CURL)
#include "curl.h"
#endif

static struct {
	const char	*ext;
	const char	*type;
} builtin_media[] = {
	{ "gif",	"image/gif" },
	{ "png",	"image/png" },
	{ "jpeg",	"image/jpeg" },
	{ "jpg",	"image/jpeg" },
	{ "zip",	"application/zip" },
	{ "pdf",	"application/pdf" },
	{ "json",	"application/json" },
	{ "js",		"application/javascript" },
	{ "htm",	"text/html" },
	{ "txt",	"text/plain" },
	{ "css",	"text/css" },
	{ "html",	"text/html" },
	{ NULL,		NULL },
};

#define HTTP_MAP_LIMIT		127

/*
 * token      = 1*<any CHAR except CTLs or separators>
 * separators = "(" | ")" | "<" | ">" | "@"
 *            | "," | ";" | ":" | "\" | <">
 *            | "/" | "[" | "]" | "?" | "="
 *            | "{" | "}" | SP | HT
 */
static const char http_token[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, '!' , 0x00, '#' , '$' , '%' , '&' , '\'',
	0x00, 0x00, '*' , '+' , 0x00, '-' , '.' , 0x00,
	'0' , '1' , '2' , '3' , '4' , '5' , '6' , '7' ,
	'8' , '9' , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 'A' , 'B' , 'C' , 'D' , 'E' , 'F' , 'G' ,
	'H' , 'I' , 'J' , 'K' , 'L' , 'M' , 'N' , 'O' ,
	'P' , 'Q' , 'R' , 'S' , 'T' , 'U' , 'V' , 'W' ,
	'X' , 'Y' , 'Z' , 0x00, 0x00, 0x00, '^' , '_' ,
	'`' , 'a' , 'b' , 'c' , 'd' , 'e' , 'f' , 'g' ,
	'h' , 'i' , 'j' , 'k' , 'l' , 'm' , 'n' , 'o' ,
	'p' , 'q' , 'r' , 's' , 't' , 'u' , 'v' , 'w' ,
	'x' , 'y' , 'z' , 0x00, '|' , 0x00, '~' , 0x00
};

/*
 * field-content  = <the OCTETs making up the field-value
 *                   and consisting of either *TEXT or combinations
 *                   of token, separators, and quoted-string>
 */
static const char http_field_content[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	' ' , '!' , '"' , '#' , '$' , '%' , '&' , '\'',
	'(' , ')' , '*' , '+' , ',' , '-' , '.' , '/' ,
	'0' , '1' , '2' , '3' , '4' , '5' , '6' , '7' ,
	'8' , '9' , ':' , ';' , '<' , '=' , '>' , '?' ,
	'@' , 'A' , 'B' , 'C' , 'D' , 'E' , 'F' , 'G' ,
	'H' , 'I' , 'J' , 'K' , 'L' , 'M' , 'N' , 'O' ,
	'P' , 'Q' , 'R' , 'S' , 'T' , 'U' , 'V' , 'W' ,
	'X' , 'Y' , 'Z' , '[' , '\\', ']' , '^' , '_' ,
	'`' , 'a' , 'b' , 'c' , 'd' , 'e' , 'f' , 'g' ,
	'h' , 'i' , 'j' , 'k' , 'l' , 'm' , 'n' , 'o' ,
	'p' , 'q' , 'r' , 's' , 't' , 'u' , 'v' , 'w' ,
	'x' , 'y' , 'z' , '{' , '|' , '}' , '~' , 0x00
};

/*
 * Fixed "pretty" HTTP error HTML page.
 */
static const char *pretty_error_fmt =
	"<html>\n<head>\n\t<title>%d %s</title>"
	"</head>\n<body>\n\t"
	"<h1>%d %s</h1>\n"
	"</body>\n</html>\n";

static int	http_body_recv(struct netbuf *);
static int	http_release_buffer(struct netbuf *);
static void	http_error_response(struct connection *, int);
static int	http_data_convert(void *, void **, void *, int);
static void	http_write_response_cookie(struct http_cookie *);
static int	http_body_update(struct http_request *, const void *, size_t);
static void	http_argument_add(struct http_request *, char *, char *,
		    int, int);
static int	http_check_redirect(struct http_request *,
		    struct kore_domain *);
static void	http_response_normal(struct http_request *,
		    struct connection *, int, const void *, size_t);
static void	multipart_add_field(struct http_request *, struct kore_buf *,
		    char *, const char *, const int);
static void	multipart_file_add(struct http_request *, struct kore_buf *,
		    const char *, const char *, const char *, const int);
static int	multipart_find_data(struct kore_buf *, struct kore_buf *,
		    size_t *, struct http_request *, const void *, size_t);
static int	multipart_parse_headers(struct http_request *,
		    struct kore_buf *, struct kore_buf *,
		    const char *, const int);

static struct http_request	*http_request_new(struct connection *,
				    const char *, const char *, char *,
				    const char *);

static struct kore_buf			*header_buf;
static struct kore_buf			*ckhdr_buf;
static char				http_version[64];
static u_int16_t			http_version_len;
static TAILQ_HEAD(, http_request)	http_requests;
static TAILQ_HEAD(, http_request)	http_requests_sleeping;
static LIST_HEAD(, http_media_type)	http_media_types;
static struct kore_pool			http_request_pool;
static struct kore_pool			http_cookie_pool;
static struct kore_pool			http_body_path;
static struct kore_pool			http_rlq_pool;

struct kore_pool			http_header_pool;

int		http_pretty_error = 0;
u_int32_t	http_request_count = 0;
u_int32_t	http_request_ms = HTTP_REQUEST_MS;
u_int16_t	http_body_timeout = HTTP_BODY_TIMEOUT;
u_int32_t	http_request_limit = HTTP_REQUEST_LIMIT;
u_int64_t	http_hsts_enable = HTTP_HSTS_ENABLE;
u_int16_t	http_header_max = HTTP_HEADER_MAX_LEN;
u_int16_t	http_keepalive_time = HTTP_KEEPALIVE_TIME;
u_int16_t	http_header_timeout = HTTP_HEADER_TIMEOUT;

size_t		http_body_max = HTTP_BODY_MAX_LEN;
char		*http_body_disk_path = HTTP_BODY_DISK_PATH;
u_int64_t	http_body_disk_offload = HTTP_BODY_DISK_OFFLOAD;

void
http_parent_init(void)
{
	LIST_INIT(&http_media_types);
}

void
http_init(void)
{
	int		prealloc, l, i;

	TAILQ_INIT(&http_requests);
	TAILQ_INIT(&http_requests_sleeping);

	header_buf = kore_buf_alloc(HTTP_HEADER_BUFSIZE);
	ckhdr_buf = kore_buf_alloc(HTTP_COOKIE_BUFSIZE);

	if (!http_version_len) {
		l = snprintf(http_version, sizeof(http_version),
		    "server: kore (%s)\r\n", kore_version);
		if (l == -1 || (size_t)l >= sizeof(http_version))
			fatal("http_init(): http_version buffer too small");

		http_version_len = l;
	}

	prealloc = MIN((worker_max_connections / 10), 1000);
	kore_pool_init(&http_request_pool, "http_request_pool",
	    sizeof(struct http_request), http_request_limit);
	kore_pool_init(&http_header_pool, "http_header_pool",
	    sizeof(struct http_header), prealloc * HTTP_REQ_HEADER_MAX);
	kore_pool_init(&http_cookie_pool, "http_cookie_pool",
		sizeof(struct http_cookie), prealloc * HTTP_MAX_COOKIES);
	kore_pool_init(&http_rlq_pool, "http_rlq_pool",
		sizeof(struct http_runlock_queue), http_request_limit);

	kore_pool_init(&http_body_path,
	    "http_body_path", HTTP_BODY_PATH_MAX, prealloc);

	for (i = 0; builtin_media[i].ext != NULL; i++) {
		if (!http_media_register(builtin_media[i].ext,
		    builtin_media[i].type)) {
			fatal("duplicate media type for %s",
			    builtin_media[i].ext);
		}
	}
}

void
http_cleanup(void)
{
	if (header_buf != NULL) {
		kore_buf_free(header_buf);
		header_buf = NULL;
	}

	if (ckhdr_buf != NULL) {
		kore_buf_free(ckhdr_buf);
		ckhdr_buf = NULL;
	}

	kore_pool_cleanup(&http_request_pool);
	kore_pool_cleanup(&http_header_pool);
	kore_pool_cleanup(&http_body_path);
}

void
http_server_version(const char *version)
{
	int		l;

	l = snprintf(http_version, sizeof(http_version),
	    "server: %s\r\n", version);
	if (l == -1 || (size_t)l >= sizeof(http_version))
		fatal("http_server_version(): http_version buffer too small");

	http_version_len = l;
}

int
http_check_timeout(struct connection *c, u_int64_t now)
{
	u_int64_t	d;

	if (c->http_timeout == 0)
		return (KORE_RESULT_OK);

	if (now > c->http_start)
		d = now - c->http_start;
	else
		d = 0;

	if (d >= c->http_timeout) {
		http_error_response(c, HTTP_STATUS_REQUEST_TIMEOUT);
		kore_connection_disconnect(c);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

void
http_request_sleep(struct http_request *req)
{
	if (!(req->flags & HTTP_REQUEST_SLEEPING)) {
		req->flags |= HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests, req, list);
		TAILQ_INSERT_TAIL(&http_requests_sleeping, req, list);
	}
}

void
http_request_wakeup(struct http_request *req)
{
	if (req->flags & HTTP_REQUEST_SLEEPING) {
		req->flags &= ~HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests_sleeping, req, list);
		TAILQ_INSERT_TAIL(&http_requests, req, list);
	}
}

void
http_process(void)
{
	u_int64_t			total;
	struct http_request		*req, *next;

	total = 0;

	for (req = TAILQ_FIRST(&http_requests); req != NULL; req = next) {
		if (total >= http_request_ms)
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

		http_process_request(req);
		total += req->ms;

		if (req->flags & HTTP_REQUEST_DELETE)
			http_request_free(req);
	}
}

void
http_process_request(struct http_request *req)
{
	int		r;

	if (req->flags & HTTP_REQUEST_DELETE || req->rt == NULL)
		return;

	req->start = kore_time_ms();
	if (req->rt->auth != NULL && !(req->flags & HTTP_REQUEST_AUTHED))
		r = kore_auth_run(req, req->rt->auth);
	else
		r = KORE_RESULT_OK;

	switch (r) {
	case KORE_RESULT_OK:
		r = kore_runtime_http_request(req->rt->rcall, req);
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
	req->end = kore_time_ms();
	req->ms = req->end - req->start;
	req->total += req->ms;

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

	if (req->rt->dom->accesslog)
		kore_accesslog(req);

	req->flags |= HTTP_REQUEST_DELETE;
}

void
http_response_header(struct http_request *req,
    const char *header, const char *value)
{
	struct http_header	*hdr;

	hdr = NULL;

	TAILQ_FOREACH(hdr, &req->resp_headers, list) {
		if (!strcasecmp(hdr->header, header)) {
			TAILQ_REMOVE(&req->resp_headers, hdr, list);
			kore_free(hdr->header);
			kore_free(hdr->value);
			break;
		}
	}

	if (hdr == NULL)
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
#if defined(KORE_USE_CURL)
	struct kore_curl	*client;
#endif
	struct http_file	*f, *fnext;
	struct http_arg		*q, *qnext;
	struct http_header	*hdr, *next;
	struct http_cookie	*ck, *cknext;

	if (req->rt != NULL && req->rt->on_free != NULL)
		kore_runtime_http_request_free(req->rt->on_free, req);

	if (req->runlock != NULL) {
		LIST_REMOVE(req->runlock, list);
		req->runlock = NULL;
	}

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

	if (pending_tasks)
		return;
#endif

#if defined(KORE_USE_PYTHON)
	if (req->py_coro != NULL) {
		kore_python_coro_delete(req->py_coro);
		req->py_coro = NULL;
	}
	if (req->py_validator != NULL) {
		kore_python_coro_delete(req->py_validator);
		req->py_validator = NULL;
	}
	Py_XDECREF(req->py_req);
#endif
#if defined(KORE_USE_PGSQL)
	while (!LIST_EMPTY(&(req->pgsqls))) {
		pgsql = LIST_FIRST(&(req->pgsqls));
		kore_pgsql_cleanup(pgsql);
	}
#endif
#if defined(KORE_USE_CURL)
	while (!LIST_EMPTY(&req->chandles)) {
		client = LIST_FIRST(&req->chandles);
		kore_curl_cleanup(client);
	}
#endif
	kore_free(req->headers);

	req->host = NULL;
	req->path = NULL;
	req->headers = NULL;

	TAILQ_REMOVE(&http_requests, req, list);
	if (req->owner != NULL)
		TAILQ_REMOVE(&(req->owner->http_requests), req, olist);

	for (hdr = TAILQ_FIRST(&(req->resp_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);
		TAILQ_REMOVE(&(req->resp_headers), hdr, list);
		kore_free(hdr->header);
		kore_free(hdr->value);
		kore_pool_put(&http_header_pool, hdr);
	}

	for (hdr = TAILQ_FIRST(&(req->req_headers)); hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);
		TAILQ_REMOVE(&(req->req_headers), hdr, list);
		kore_pool_put(&http_header_pool, hdr);
	}

	for (ck = TAILQ_FIRST(&(req->resp_cookies)); ck != NULL; ck = cknext) {
		cknext = TAILQ_NEXT(ck, list);
		TAILQ_REMOVE(&(req->resp_cookies), ck, list);
		kore_free(ck->name);
		kore_free(ck->value);
		kore_free(ck->path);
		kore_free(ck->domain);
		kore_pool_put(&http_cookie_pool, ck);
	}

	for (ck = TAILQ_FIRST(&(req->req_cookies)); ck != NULL; ck = cknext) {
		cknext = TAILQ_NEXT(ck, list);
		TAILQ_REMOVE(&(req->req_cookies), ck, list);
		kore_free(ck->name);
		kore_free(ck->value);
		kore_pool_put(&http_cookie_pool, ck);
	}

	for (q = TAILQ_FIRST(&(req->arguments)); q != NULL; q = qnext) {
		qnext = TAILQ_NEXT(q, list);
		TAILQ_REMOVE(&(req->arguments), q, list);
		kore_free(q->name);
		kore_free(q->s_value);
		kore_free(q);
	}

	for (f = TAILQ_FIRST(&(req->files)); f != NULL; f = fnext) {
		fnext = TAILQ_NEXT(f, list);
		TAILQ_REMOVE(&(req->files), f, list);
		kore_free(f->filename);
		kore_free(f->name);
		kore_free(f);
	}

	if (req->http_body != NULL)
		kore_buf_free(req->http_body);

	if (req->http_body_fd != -1)
		(void)close(req->http_body_fd);

	if (req->http_body_path != NULL) {
		if (unlink(req->http_body_path) == -1 && errno != ENOENT) {
			kore_log(LOG_NOTICE, "failed to unlink %s: %s",
			    req->http_body_path, errno_s);
		}
		kore_pool_put(&http_body_path, req->http_body_path);
	}

	if (req->hdlr_extra != NULL &&
	    !(req->flags & HTTP_REQUEST_RETAIN_EXTRA))
		kore_free(req->hdlr_extra);

	kore_pool_put(&http_request_pool, req);
	http_request_count--;
}

void
http_serveable(struct http_request *req, const void *data, size_t len,
    const char *etag, const char *type)
{
	const char		*match;

	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "get");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

	if (http_request_header(req, "if-none-match", &match)) {
		if (!strcmp(match, etag)) {
			http_response(req, HTTP_STATUS_NOT_MODIFIED, NULL, 0);
			return;
		}
	}

	http_response_header(req, "etag", etag);
	http_response_header(req, "content-type", type);
	http_response(req, HTTP_STATUS_OK, data, len);
}

void
http_response(struct http_request *req, int code, const void *d, size_t l)
{
	if (req->owner == NULL)
		return;

	req->status = code;

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
	case CONN_PROTO_WEBSOCKET:
		http_response_normal(req, req->owner, code, d, l);
		break;
	default:
		fatal("%s: bad proto %d", __func__, req->owner->proto);
		/* NOTREACHED. */
	}
}

void
http_response_close(struct http_request *req, int code, const void *d, size_t l)
{
	if (req->owner == NULL)
		return;

	req->status = code;
	req->owner->flags |= CONN_CLOSE_EMPTY;

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
	case CONN_PROTO_WEBSOCKET:
		http_response_normal(req, req->owner, code, d, l);
		break;
	default:
		fatal("%s: bad proto %d", __func__, req->owner->proto);
		/* NOTREACHED. */
	}
}

void
http_response_json(struct http_request *req, int status,
    struct kore_json_item *json)
{
	struct kore_buf		*buf;

	if (req->owner == NULL)
		return;

	buf = kore_buf_alloc(1024);
	kore_json_item_tobuf(json, buf);
	kore_json_item_free(json);

	req->status = status;
	http_response_header(req, "content-type", "application/json");

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
		http_response_stream(req, status, buf->data, buf->offset,
		    http_release_buffer, buf);
		break;
	default:
		fatal("%s: bad proto %d", __func__, req->owner->proto);
		/* NOTREACHED. */
	}
}

void
http_response_stream(struct http_request *req, int status, void *base,
    size_t len, int (*cb)(struct netbuf *), void *arg)
{
	struct netbuf		*nb;

	if (req->owner == NULL)
		return;

	req->status = status;

	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
		http_response_normal(req, req->owner, status, NULL, len);
		break;
	default:
		fatal("%s: bad proto %d", __func__, req->owner->proto);
		/* NOTREACHED. */
	}

	net_send_stream(req->owner, base, len, cb, &nb);
	nb->extra = arg;

	if (req->method == HTTP_METHOD_HEAD) {
		nb->s_off = nb->b_len;
		net_remove_netbuf(req->owner, nb);
	}
}

void
http_response_fileref(struct http_request *req, int status,
    struct kore_fileref *ref)
{
	struct tm	*tm;
	time_t		mtime;
	char		tbuf[128];
	const char	*media_type, *modified;

	if (req->owner == NULL)
		return;

	media_type = http_media_type(ref->path);
	if (media_type != NULL)
		http_response_header(req, "content-type", media_type);

	if (http_request_header(req, "if-modified-since", &modified)) {
		mtime = kore_date_to_time(modified);
		if (mtime == ref->mtime_sec) {
			kore_fileref_release(ref);
			http_response(req, HTTP_STATUS_NOT_MODIFIED, NULL, 0);
			return;
		}
	}

	if ((tm = gmtime(&ref->mtime_sec)) != NULL) {
		if (strftime(tbuf, sizeof(tbuf),
		    "%a, %d %b %Y %H:%M:%S GMT", tm) > 0) {
			http_response_header(req, "last-modified", tbuf);
		}
	}

	req->status = status;
	switch (req->owner->proto) {
	case CONN_PROTO_HTTP:
		http_response_normal(req, req->owner, status, NULL, ref->size);
		break;
	default:
		fatal("http_response_fd() bad proto %d", req->owner->proto);
		/* NOTREACHED. */
	}

	if (req->method != HTTP_METHOD_HEAD)
		net_send_fileref(req->owner, ref);
	else
		kore_fileref_release(ref);
}

int
http_request_header(struct http_request *req, const char *header,
    const char **out)
{
	struct http_header	*hdr;

	TAILQ_FOREACH(hdr, &(req->req_headers), list) {
		if (!strcasecmp(hdr->header, header)) {
			*out = hdr->value;
			return (KORE_RESULT_OK);
		}
	}

	if (!strcasecmp(header, "host")) {
		*out = req->host;
		return (KORE_RESULT_OK);
	}

	return (KORE_RESULT_ERROR);
}

int
http_request_header_get(struct http_request *req, const char *header,
    void **out, void *nout, int type)
{
	struct http_header	*hdr;

	if (type == HTTP_ARG_TYPE_STRING)
		fatal("%s: cannot be called with type string", __func__);

	TAILQ_FOREACH(hdr, &req->req_headers, list) {
		if (strcasecmp(hdr->header, header))
			continue;

		if (http_data_convert(hdr->value, out, nout, type))
			return (KORE_RESULT_OK);

		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_ERROR);
}

int
http_request_cookie(struct http_request *req, const char *cookie, char **out)
{
	struct http_cookie	*ck;

	TAILQ_FOREACH(ck, &(req->req_cookies), list) {
		if (!strcasecmp(ck->name, cookie)) {
			*out = ck->value;
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

int
http_header_recv(struct netbuf *nb)
{
	struct connection	*c;
	size_t			len;
	struct http_header	*hdr;
	struct http_request	*req;
	u_int8_t		*end_headers;
	int			h, i, v, skip, l;
	char			*headers[HTTP_REQ_HEADER_MAX];
	char			*value, *host, *request[4], *hbuf;

	c = nb->owner;

	if (nb->b_len < 4)
		return (KORE_RESULT_OK);

	if (!isalpha(nb->buf[0])) {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (KORE_RESULT_ERROR);
	}

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
	len = end_headers - nb->buf;
	hbuf = (char *)nb->buf;

	h = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
	if (h < 2) {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (KORE_RESULT_OK);
	}

	v = kore_split_string(headers[0], " ", request, 4);
	if (v != 3) {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (KORE_RESULT_OK);
	}

	skip = 0;
	host = NULL;
	for (i = 0; i < h; i++) {
		if (strncasecmp(headers[i], "host", 4))
			continue;

		if ((host = http_validate_header(headers[i])) == NULL) {
			http_error_response(c, HTTP_STATUS_BAD_REQUEST);
			return (KORE_RESULT_OK);
		}

		if (*host == '\0') {
			http_error_response(c, HTTP_STATUS_BAD_REQUEST);
			return (KORE_RESULT_OK);
		}

		skip = i;
		break;
	}

	if (host == NULL) {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (KORE_RESULT_OK);
	}

	req = http_request_new(c, host, request[0], request[1], request[2]);
	if (req == NULL)
		return (KORE_RESULT_OK);

	/* take full ownership of the buffer. */
	req->headers = nb->buf;
	nb->buf = NULL;
	nb->m_len = 0;

	for (i = 1; i < h; i++) {
		if (i == skip)
			continue;

		if ((value = http_validate_header(headers[i])) == NULL) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(c, HTTP_STATUS_BAD_REQUEST);
			return (KORE_RESULT_OK);
		}

		if (*value == '\0') {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(c, HTTP_STATUS_BAD_REQUEST);
			return (KORE_RESULT_OK);
		}

		hdr = kore_pool_get(&http_header_pool);
		hdr->header = headers[i];
		hdr->value = value;
		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);

		if (req->agent == NULL &&
		    !strcasecmp(hdr->header, "user-agent"))
			req->agent = hdr->value;

		if (req->referer == NULL &&
		    !strcasecmp(hdr->header, "referer"))
			req->referer = hdr->value;
	}

	if (req->flags & HTTP_REQUEST_EXPECT_BODY) {
		if (http_body_max == 0) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_METHOD_NOT_ALLOWED);
			return (KORE_RESULT_OK);
		}

		if (!http_request_header_uint64(req, "content-length",
		    &req->content_length)) {
			if (req->method == HTTP_METHOD_DELETE) {
				req->flags |= HTTP_REQUEST_COMPLETE;
				return (KORE_RESULT_OK);
			}

			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_LENGTH_REQUIRED);
			return (KORE_RESULT_OK);
		}

		if (req->content_length == 0) {
			req->flags |= HTTP_REQUEST_COMPLETE;
			req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
			return (KORE_RESULT_OK);
		}

		if (req->content_length > http_body_max) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE);
			return (KORE_RESULT_OK);
		}

		req->http_body_length = req->content_length;

		if (http_body_disk_offload > 0 &&
		    req->content_length > http_body_disk_offload) {
			req->http_body_path = kore_pool_get(&http_body_path);
			l = snprintf(req->http_body_path, HTTP_BODY_PATH_MAX,
			    "%s/http_body.XXXXXX", http_body_disk_path);
			if (l == -1 || (size_t)l >= HTTP_BODY_PATH_MAX) {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner,
				    HTTP_STATUS_INTERNAL_ERROR);
				return (KORE_RESULT_ERROR);
			}

			req->http_body = NULL;
			req->http_body_fd = mkstemp(req->http_body_path);
			if (req->http_body_fd == -1) {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner,
				    HTTP_STATUS_INTERNAL_ERROR);
				return (KORE_RESULT_OK);
			}
		} else {
			req->http_body_fd = -1;
			req->http_body = kore_buf_alloc(req->content_length);
		}

		SHA256Init(&req->hashctx);
		c->http_timeout = http_body_timeout * 1000;

		if (!http_body_update(req, end_headers, nb->s_off - len)) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_INTERNAL_ERROR);
			return (KORE_RESULT_OK);
		}
	} else {
		c->http_timeout = 0;
	}

	if (req->rt->on_headers != NULL) {
		if (!kore_runtime_http_request(req->rt->on_headers, req)) {
			req->flags |= HTTP_REQUEST_DELETE;
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_OK);
}

int
http_argument_get(struct http_request *req, const char *name,
    void **out, void *nout, int type)
{
	struct http_arg		*q;

	TAILQ_FOREACH(q, &(req->arguments), list) {
		if (strcmp(q->name, name))
			continue;

		if (http_data_convert(q->s_value, out, nout, type))
			return (KORE_RESULT_OK);

		break;
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

		if ((p + 2) >= (arg + len))
			return (KORE_RESULT_ERROR);

		if (!isxdigit((unsigned char)*(p + 1)) ||
		    !isxdigit((unsigned char)*(p + 2))) {
			*in++ = *p++;
			continue;
		}

		h[0] = '0';
		h[1] = 'x';
		h[2] = *(p + 1);
		h[3] = *(p + 2);
		h[4] = '\0';

		v = kore_strtonum(h, 16, 0x0, 0xff, &err);
		if (err != KORE_RESULT_OK)
			return (err);

		if (v <= 0x1f || v == 0x7f)
			return (KORE_RESULT_ERROR);

		*in++ = (char)v;
		p += 3;
	}

	*in = '\0';
	return (KORE_RESULT_OK);
}

struct http_file *
http_file_lookup(struct http_request *req, const char *name)
{
	struct http_file	*f;

	TAILQ_FOREACH(f, &(req->files), list) {
		if (!strcmp(f->name, name))
			return (f);
	}

	return (NULL);
}

ssize_t
http_file_read(struct http_file *file, void *buf, size_t len)
{
	ssize_t		ret;
	size_t		toread, off;

	if (file->length < file->offset)
		return (-1);
	if ((file->offset + len) < file->offset)
		return (-1);
	if ((file->position + file->offset) < file->position)
		return (-1);

	off = file->position + file->offset;
	toread = MIN(len, (file->length - file->offset));
	if (toread == 0)
		return (0);

	if (file->req->http_body_fd != -1) {
		if (lseek(file->req->http_body_fd, off, SEEK_SET) == -1) {
			kore_log(LOG_ERR, "http_file_read: lseek(%s): %s",
			    file->req->http_body_path, errno_s);
			return (-1);
		}

		for (;;) {
			ret = read(file->req->http_body_fd, buf, toread);
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				kore_log(LOG_ERR, "failed to read %s: %s",
				    file->req->http_body_path, errno_s);
				return (-1);
			}
			if (ret == 0)
				return (0);
			break;
		}
	} else if (file->req->http_body != NULL) {
		if (off > file->req->http_body->length)
			return (0);
		memcpy(buf, file->req->http_body->data + off, toread);
		ret = toread;
	} else {
		kore_log(LOG_ERR, "http_file_read: called without body");
		return (-1);
	}

	file->offset += (size_t)ret;
	return (ret);
}

void
http_file_rewind(struct http_file *file)
{
	file->offset = 0;
}

void
http_response_cookie(struct http_request *req, const char *name,
    const char *val, const char *path, time_t expires, u_int32_t maxage,
    struct http_cookie **out)
{
	char			*p;
	struct http_cookie	*ck;

	if (name == NULL || val == NULL)
		fatal("http_response_cookie: invalid parameters");

	ck = kore_pool_get(&http_cookie_pool);

	ck->maxage = maxage;
	ck->expires = expires;
	ck->name = kore_strdup(name);
	ck->value = kore_strdup(val);
	ck->domain = kore_strdup(req->host);
	ck->flags = HTTP_COOKIE_HTTPONLY | HTTP_COOKIE_SECURE;

	if ((p = strrchr(ck->domain, ':')) != NULL)
		*p = '\0';

	if (path != NULL)
		ck->path = kore_strdup(path);
	else
		ck->path = NULL;

	TAILQ_INSERT_TAIL(&(req->resp_cookies), ck, list);

	if (out != NULL)
		*out = ck;
}

void
http_populate_cookies(struct http_request *req)
{
	struct http_cookie	*ck;
	const char		*hdr;
	int			 i, v, n;
	char			*c, *header, *pair[3];
	char			*cookies[HTTP_MAX_COOKIES];

	if (!http_request_header(req, "cookie", &hdr))
		return;

	header = kore_strdup(hdr);
	v = kore_split_string(header, ";", cookies, HTTP_MAX_COOKIES);
	for (i = 0; i < v; i++) {
		for (c = cookies[i]; isspace(*(unsigned char *)c); c++)
			;

		n = kore_split_string(c, "=", pair, 3);
		if (n != 2)
			continue;

		ck = kore_pool_get(&http_cookie_pool);
		ck->name = kore_strdup(pair[0]);
		ck->value = kore_strdup(pair[1]);
		TAILQ_INSERT_TAIL(&(req->req_cookies), ck, list);
	}

	kore_free(header);
}

void
http_populate_post(struct http_request *req)
{
	ssize_t			ret;
	int			i, v;
	struct kore_buf		*body;
	char			data[BUFSIZ];
	char			*args[HTTP_MAX_QUERY_ARGS], *val[3], *string;

	if (req->method != HTTP_METHOD_POST)
		return;

	if (req->http_body != NULL) {
		body = NULL;
		req->http_body->offset = req->content_length;
		string = kore_buf_stringify(req->http_body, NULL);
		req->http_body_length = 0;
		req->http_body_offset = 0;
	} else {
		body = kore_buf_alloc(128);
		for (;;) {
			ret = http_body_read(req, data, sizeof(data));
			if (ret == -1)
				goto out;
			if (ret == 0)
				break;
			kore_buf_append(body, data, ret);
		}
		string = kore_buf_stringify(body, NULL);
	}

	v = kore_split_string(string, "&", args, HTTP_MAX_QUERY_ARGS);
	for (i = 0; i < v; i++) {
		kore_split_string(args[i], "=", val, 3);
		if (val[0] != NULL && val[1] != NULL)
			http_argument_add(req, val[0], val[1], 0, 1);
	}

out:
	if (body != NULL)
		kore_buf_free(body);
}

void
http_populate_qs(struct http_request *req)
{
	int		i, v;
	char		*query, *args[HTTP_MAX_QUERY_ARGS], *val[3];

	if (req->query_string == NULL)
		return;

	query = kore_strdup(req->query_string);
	v = kore_split_string(query, "&", args, HTTP_MAX_QUERY_ARGS);
	for (i = 0; i < v; i++) {
		kore_split_string(args[i], "=", val, 3);
		if (val[0] != NULL && val[1] != NULL)
			http_argument_add(req, val[0], val[1], 1, 1);
	}

	kore_free(query);
}

void
http_populate_multipart_form(struct http_request *req)
{
	const char		*hdr;
	int			h, blen;
	struct kore_buf		in, out;
	char			*type, *val, *args[3];
	char			boundary[HTTP_BOUNDARY_MAX];

	if (req->method != HTTP_METHOD_POST)
		return;

	if (!http_request_header(req, "content-type", &hdr))
		return;

	kore_buf_init(&in, 128);
	kore_buf_init(&out, 128);

	type = kore_strdup(hdr);
	h = kore_split_string(type, ";", args, 3);
	if (h != 2)
		goto cleanup;

	if (strcasecmp(args[0], "multipart/form-data"))
		goto cleanup;

	if ((val = strchr(args[1], '=')) == NULL)
		goto cleanup;

	val++;
	blen = snprintf(boundary, sizeof(boundary), "--%s", val);
	if (blen == -1 || (size_t)blen >= sizeof(boundary))
		goto cleanup;

	if (!multipart_find_data(&in, NULL, NULL, req, boundary, blen))
		goto cleanup;

	for (;;) {
		if (!multipart_find_data(&in, NULL, NULL, req, "\r\n", 2))
			break;
		if (in.offset < 4 && req->http_body_length == 0)
			break;
		if (!multipart_find_data(&in, &out, NULL, req, "\r\n\r\n", 4))
			break;
		if (!multipart_parse_headers(req, &in, &out, boundary, blen))
			break;

		kore_buf_reset(&out);
	}

cleanup:
	kore_free(type);
	kore_buf_cleanup(&in);
	kore_buf_cleanup(&out);
}

int
http_body_rewind(struct http_request *req)
{
	if (req->http_body_fd != -1) {
		if (lseek(req->http_body_fd, 0, SEEK_SET) == -1) {
			kore_log(LOG_ERR, "lseek(%s) failed: %s",
			    req->http_body_path, errno_s);
			return (KORE_RESULT_ERROR);
		}
	} else if (req->http_body != NULL) {
		kore_buf_reset(req->http_body);
	}

	req->http_body_offset = 0;
	req->http_body_length = req->content_length;

	return (KORE_RESULT_OK);
}

int
http_body_digest(struct http_request *req, char *out, size_t len)
{
	size_t		idx;
	int		slen;

	if (len != HTTP_BODY_DIGEST_STRLEN) {
		fatal("http_body_digest: bad len:%zu wanted:%u",
		    len, HTTP_BODY_DIGEST_STRLEN);
	}

	if (!(req->flags & HTTP_REQUEST_COMPLETE))
		return (KORE_RESULT_ERROR);

	for (idx = 0; idx < sizeof(req->http_body_digest); idx++) {
		slen = snprintf(out + (idx * 2), len - (idx * 2), "%02x",
		    req->http_body_digest[idx]);
		if (slen == -1 || (size_t)slen >= len)
			fatal("failed to create hex string");
	}

	return (KORE_RESULT_OK);
}

ssize_t
http_body_read(struct http_request *req, void *out, size_t len)
{
	ssize_t		ret;
	size_t		toread;

	toread = MIN(req->http_body_length, len);
	if (toread == 0)
		return (0);

	if (req->http_body_fd != -1) {
		for (;;) {
			ret = read(req->http_body_fd, out, toread);
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				kore_log(LOG_ERR, "failed to read %s: %s",
				    req->http_body_path, errno_s);
				return (-1);
			}
			if (ret == 0)
				return (0);
			break;
		}
	} else if (req->http_body != NULL) {
		memcpy(out,
		    (req->http_body->data + req->http_body->offset), toread);
		req->http_body->offset += toread;
		ret = toread;
	} else {
		kore_log(LOG_ERR, "http_body_read: called without body");
		return (-1);
	}

	req->http_body_length -= (size_t)ret;
	req->http_body_offset += (size_t)ret;

	return (ret);
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

	return (KORE_RESULT_OK);
}

int
http_state_exists(struct http_request *req)
{
	return (req->hdlr_extra != NULL);
}

void *
http_state_create(struct http_request *req, size_t len)
{
	if (req->hdlr_extra != NULL)
		fatal("http_state_create: state already exists");

	req->state_len = len;
	req->hdlr_extra = kore_calloc(1, len);

	return (req->hdlr_extra);
}

void *
http_state_get(struct http_request *req)
{
	return (req->hdlr_extra);
}

void
http_state_cleanup(struct http_request *req)
{
	kore_free(req->hdlr_extra);
	req->hdlr_extra = NULL;
}

void
http_start_recv(struct connection *c)
{
	c->http_start = kore_time_ms();
	c->http_timeout = http_header_timeout * 1000;
	net_recv_reset(c, http_header_max, http_header_recv);
}

void
http_runlock_init(struct http_runlock *lock)
{
	lock->owner = NULL;
	LIST_INIT(&lock->queue);
}

int
http_runlock_acquire(struct http_runlock *lock, struct http_request *req)
{
	if (lock->owner != NULL) {
		if (req->runlock != NULL)
			fatal("%s: request already waiting on lock", __func__);

		req->runlock = kore_pool_get(&http_rlq_pool);
		req->runlock->req = req;
		LIST_INSERT_HEAD(&lock->queue, req->runlock, list);

		http_request_sleep(req);
		return (KORE_RESULT_ERROR);
	}

	lock->owner = req;

	return (KORE_RESULT_OK);
}

void
http_runlock_release(struct http_runlock *lock, struct http_request *req)
{
	struct http_runlock_queue	*next;
	struct http_request		*nextreq;

	if (lock->owner != req)
		fatal("%s: calling request != owner of runlock", __func__);

	lock->owner = NULL;

	if ((next = LIST_FIRST(&lock->queue)) != NULL) {
		LIST_REMOVE(next, list);

		nextreq = next->req;
		nextreq->runlock = NULL;

		http_request_wakeup(nextreq);
		kore_pool_put(&http_rlq_pool, next);
	}
}

int
http_redirect_add(struct kore_domain *dom, const char *path, int status,
    const char *target)
{
	struct http_redirect	*rdr;

	rdr = kore_calloc(1, sizeof(*rdr));

	if (regcomp(&(rdr->rctx), path, REG_EXTENDED)) {
		kore_free(rdr);
		return (KORE_RESULT_ERROR);
	}

	rdr->status = status;

	if (target != NULL)
		rdr->target = kore_strdup(target);
	else
		rdr->target = NULL;

	TAILQ_INSERT_TAIL(&dom->redirects, rdr, list);

	return (KORE_RESULT_OK);
}

const char *
http_status_text(int status)
{
	const char	*r;

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
	case HTTP_STATUS_MISDIRECTED_REQUEST:
		r = "Misdirected Request";
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

const char *
http_method_text(int method)
{
	char		*r;

	switch(method) {
	case HTTP_METHOD_GET:
		r = "GET";
		break;
	case HTTP_METHOD_POST:
		r = "POST";
		break;
	case HTTP_METHOD_PUT:
		r = "PUT";
		break;
	case HTTP_METHOD_DELETE:
		r = "DELETE";
		break;
	case HTTP_METHOD_HEAD:
		r = "HEAD";
		break;
	case HTTP_METHOD_OPTIONS:
		r = "OPTIONS";
		break;
	case HTTP_METHOD_PATCH:
		r = "PATCH";
		break;
	default:
		r = "";
		break;
	}

	return (r);
}

int
http_method_value(const char *method)
{
	if (!strcasecmp(method, "GET"))
		return (HTTP_METHOD_GET);

	if (!strcasecmp(method, "POST"))
		return (HTTP_METHOD_POST);

	if (!strcasecmp(method, "PUT"))
		return (HTTP_METHOD_PUT);

	if (!strcasecmp(method, "DELETE"))
		return (HTTP_METHOD_DELETE);

	if (!strcasecmp(method, "HEAD"))
		return (HTTP_METHOD_HEAD);

	if (!strcasecmp(method, "OPTIONS"))
		return (HTTP_METHOD_OPTIONS);

	if (!strcasecmp(method, "PATCH"))
		return (HTTP_METHOD_PATCH);

	return (0);
}

int
http_media_register(const char *ext, const char *type)
{
	struct http_media_type	*media;

	LIST_FOREACH(media, &http_media_types, list) {
		if (!strcasecmp(media->ext, ext))
			return (KORE_RESULT_ERROR);
	}

	media = kore_calloc(1, sizeof(*media));
	media->ext = kore_strdup(ext);
	media->type = kore_strdup(type);

	LIST_INSERT_HEAD(&http_media_types, media, list);

	return (KORE_RESULT_OK);
}

const char *
http_media_type(const char *path)
{
	const char		*p;
	struct http_media_type	*media;

	if ((p = strrchr(path, '.')) == NULL)
		return (NULL);

	p++;
	if (*p == '\0')
		return (NULL);

	LIST_FOREACH(media, &http_media_types, list) {
		if (!strcasecmp(media->ext, p))
			return (media->type);
	}

	return (NULL);
}

char *
http_validate_header(char *header)
{
	u_int8_t	idx;
	char		*p, *value;

	for (p = header; *p != '\0'; p++) {
		idx = *p;
		if (idx > HTTP_MAP_LIMIT)
			return (NULL);

		if (*p == ':') {
			*(p)++ = '\0';
			break;
		}

		if (http_token[idx] == 0x00)
			return (NULL);
	}

	while (isspace(*(unsigned char *)p))
		p++;

	if (*p == '\0')
		return (NULL);

	value = p;
	while (*p != '\0') {
		idx = *p;
		if (idx > HTTP_MAP_LIMIT)
			return (NULL);
		if (http_field_content[idx] == 0x00)
			return (NULL);
		p++;
	}

	return (value);
}

static int
http_release_buffer(struct netbuf *nb)
{
	kore_buf_free(nb->extra);

	return (KORE_RESULT_OK);
}

static int
http_check_redirect(struct http_request *req, struct kore_domain *dom)
{
	int			idx;
	struct http_redirect	*rdr;
	const char		*uri;
	char			key[4];
	struct kore_buf		location;

	TAILQ_FOREACH(rdr, &dom->redirects, list) {
		if (!regexec(&(rdr->rctx), req->path,
		    HTTP_CAPTURE_GROUPS, req->cgroups, 0))
			break;
	}

	if (rdr == NULL)
		return (KORE_RESULT_ERROR);

	uri = NULL;
	kore_buf_init(&location, 128);

	if (rdr->target) {
		kore_buf_appendf(&location, "%s", rdr->target);

		if (req->query_string != NULL) {
			kore_buf_replace_string(&location, "$qs",
			    req->query_string, strlen(req->query_string));
		}

		/* Starts at 1 to skip the full path. */
		for (idx = 1; idx < HTTP_CAPTURE_GROUPS - 1; idx++) {
			if (req->cgroups[idx].rm_so == -1 ||
			    req->cgroups[idx].rm_eo == -1)
				break;

			(void)snprintf(key, sizeof(key), "$%d", idx);

			kore_buf_replace_string(&location, key,
			    req->path + req->cgroups[idx].rm_so,
			    req->cgroups[idx].rm_eo - req->cgroups[idx].rm_so);
		}

		uri = kore_buf_stringify(&location, NULL);
	}

	if (uri)
		http_response_header(req, "location", uri);

	http_response(req, rdr->status, NULL, 0);
	kore_buf_cleanup(&location);

	if (dom->accesslog)
		kore_accesslog(req);

	return (KORE_RESULT_OK);
}

static struct http_request *
http_request_new(struct connection *c, const char *host,
    const char *method, char *path, const char *version)
{
	struct kore_domain		*dom;
	struct http_request		*req;
	size_t				qsoff;
	char				*p, *hp;
	int				m, flags, exists;

	if (http_request_count >= http_request_limit) {
		http_error_response(c, HTTP_STATUS_SERVICE_UNAVAILABLE);
		return (NULL);
	}

	if (strlen(host) >= KORE_DOMAINNAME_LEN - 1) {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (NULL);
	}

	if (strlen(path) >= HTTP_URI_LEN - 1) {
		http_error_response(c, HTTP_STATUS_REQUEST_URI_TOO_LARGE);
		return (NULL);
	}

	if (strcasecmp(version, "http/1.1")) {
		if (strcasecmp(version, "http/1.0")) {
			http_error_response(c, HTTP_STATUS_BAD_VERSION);
			return (NULL);
		}

		flags = HTTP_VERSION_1_0;
	} else {
		flags = HTTP_VERSION_1_1;
	}

	if ((p = strchr(path, '?')) != NULL) {
		qsoff = p - path;
	} else {
		qsoff = 0;
	}

	hp = NULL;

	switch (c->family) {
	case AF_INET6:
		if (*host == '[') {
			if ((hp = strrchr(host, ']')) == NULL) {
				http_error_response(c, HTTP_STATUS_BAD_REQUEST);
				return (NULL);
			}
			hp++;
			if (*hp == ':')
				*hp = '\0';
			else
				hp = NULL;
		}
		break;
	default:
		if ((hp = strrchr(host, ':')) != NULL)
			*hp = '\0';
		break;
	}

	if (c->owner->server->tls && c->tls_sni != NULL) {
		if (strcasecmp(c->tls_sni, host)) {
			http_error_response(c, HTTP_STATUS_MISDIRECTED_REQUEST);
			return (NULL);
		}
	}

	if ((dom = kore_domain_lookup(c->owner->server, host)) == NULL) {
		http_error_response(c, HTTP_STATUS_NOT_FOUND);
		return (NULL);
	}

	if (dom->cafile != NULL && c->tls_cert == NULL) {
		http_error_response(c, HTTP_STATUS_FORBIDDEN);
		return (NULL);
	}

	if (hp != NULL)
		*hp = ':';

	if (!strcasecmp(method, "get")) {
		m = HTTP_METHOD_GET;
		flags |= HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "delete")) {
		m = HTTP_METHOD_DELETE;
		flags |= HTTP_REQUEST_EXPECT_BODY;
	} else if (!strcasecmp(method, "post")) {
		m = HTTP_METHOD_POST;
		flags |= HTTP_REQUEST_EXPECT_BODY;
	} else if (!strcasecmp(method, "put")) {
		m = HTTP_METHOD_PUT;
		flags |= HTTP_REQUEST_EXPECT_BODY;
	} else if (!strcasecmp(method, "head")) {
		m = HTTP_METHOD_HEAD;
		flags |= HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "options")) {
		m = HTTP_METHOD_OPTIONS;
		flags |= HTTP_REQUEST_COMPLETE;
	} else if (!strcasecmp(method, "patch")) {
		m = HTTP_METHOD_PATCH;
		flags |= HTTP_REQUEST_EXPECT_BODY;
	} else {
		http_error_response(c, HTTP_STATUS_BAD_REQUEST);
		return (NULL);
	}

	if (flags & HTTP_VERSION_1_0) {
		if (m != HTTP_METHOD_GET && m != HTTP_METHOD_POST &&
		    m != HTTP_METHOD_HEAD) {
			http_error_response(c, HTTP_STATUS_METHOD_NOT_ALLOWED);
			return (NULL);
		}
	}

	req = kore_pool_get(&http_request_pool);

	req->end = 0;
	req->total = 0;
	req->start = 0;
	req->owner = c;
	req->status = 0;
	req->method = m;
	req->agent = NULL;
	req->referer = NULL;
	req->runlock = NULL;
	req->flags = flags;
	req->fsm_state = 0;
	req->http_body = NULL;
	req->http_body_fd = -1;
	req->hdlr_extra = NULL;
	req->content_length = 0;
	req->query_string = NULL;
	req->http_body_length = 0;
	req->http_body_offset = 0;
	req->http_body_path = NULL;

	req->host = host;
	req->path = path;

#if defined(KORE_USE_PYTHON)
	req->py_req = NULL;
	req->py_coro = NULL;
	req->py_rqnext = NULL;
	req->py_validator = NULL;
#endif

	if (qsoff > 0) {
		req->query_string = path + qsoff;
		*(req->query_string)++ = '\0';
	} else {
		req->query_string = NULL;
	}

	/* Checked further down below if we need to 404. */
	exists = kore_route_lookup(req, dom, m, &req->rt);

	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));
	TAILQ_INIT(&(req->resp_cookies));
	TAILQ_INIT(&(req->req_cookies));
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

	if (http_check_redirect(req, dom)) {
		http_request_free(req);
		return (NULL);
	}

	if (exists == 0) {
		http_request_free(req);
		http_error_response(c, HTTP_STATUS_NOT_FOUND);
		return (NULL);
	}

	if (req->rt == NULL) {
		http_request_free(req);
		http_error_response(c, HTTP_STATUS_METHOD_NOT_ALLOWED);
		return (NULL);
	}

	return (req);
}

static int
multipart_find_data(struct kore_buf *in, struct kore_buf *out,
    size_t *olen, struct http_request *req, const void *needle, size_t len)
{
	ssize_t			ret;
	size_t			left;
	u_int8_t		*p, first, data[4096];

	if (olen != NULL)
		*olen = 0;

	first = *(const u_int8_t *)needle;
	for (;;) {
		if (in->offset < len) {
			ret = http_body_read(req, data, sizeof(data));
			if (ret == -1)
				return (KORE_RESULT_ERROR);
			if (ret == 0)
				return (KORE_RESULT_ERROR);

			kore_buf_append(in, data, ret);
			continue;
		}

		p = kore_mem_find(in->data, in->offset, &first, 1);
		if (p == NULL) {
			if (out != NULL)
				kore_buf_append(out, in->data, in->offset);
			if (olen != NULL)
				*olen += in->offset;
			kore_buf_reset(in);
			continue;
		}

		left = in->offset - (p - in->data);
		if (left < len) {
			if (out != NULL)
				kore_buf_append(out, in->data, (p - in->data));
			if (olen != NULL)
				*olen += (p - in->data);
			memmove(in->data, p, left);
			in->offset = left;
			continue;
		}

		if (!memcmp(p, needle, len)) {
			if (out != NULL)
				kore_buf_append(out, in->data, p - in->data);
			if (olen != NULL)
				*olen += (p - in->data);

			in->offset = left - len;
			if (in->offset > 0)
				memmove(in->data, p + len, in->offset);
			return (KORE_RESULT_OK);
		}

		if (out != NULL)
			kore_buf_append(out, in->data, (p - in->data) + 1);
		if (olen != NULL)
			*olen += (p - in->data) + 1;

		in->offset = left - 1;
		if (in->offset > 0)
			memmove(in->data, p + 1, in->offset);
	}

	return (KORE_RESULT_ERROR);
}

static int
multipart_parse_headers(struct http_request *req, struct kore_buf *in,
    struct kore_buf *hbuf, const char *boundary, const int blen)
{
	int		h, c, i;
	char		*headers[5], *args[5], *opt[5];
	char		*d, *val, *name, *fname, *string;

	string = kore_buf_stringify(hbuf, NULL);
	h = kore_split_string(string, "\r\n", headers, 5);
	for (i = 0; i < h; i++) {
		c = kore_split_string(headers[i], ":", args, 5);
		if (c != 2)
			continue;

		/* Ignore other headers for now. */
		if (strcasecmp(args[0], "content-disposition"))
			continue;

		for (d = args[1]; isspace(*(unsigned char *)d); d++)
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
			multipart_add_field(req, in, name, boundary, blen);
			kore_free(name);
			continue;
		}

		for (d = opt[2]; isspace(*(unsigned char *)d); d++)
			;

		if (!strncasecmp(d, "filename=", 9)) {
			if ((val = strchr(d, '=')) == NULL) {
				kore_free(name);
				continue;
			}

			val++;
			kore_strip_chars(val, '"', &fname);
			if (strlen(fname) > 0) {
				multipart_file_add(req,
				    in, name, fname, boundary, blen);
			}
			kore_free(fname);
		}

		kore_free(name);
	}

	return (KORE_RESULT_OK);
}

static void
multipart_add_field(struct http_request *req, struct kore_buf *in,
    char *name, const char *boundary, const int blen)
{
	struct kore_buf		*data;
	char			*string;

	data = kore_buf_alloc(128);

	if (!multipart_find_data(in, data, NULL, req, boundary, blen)) {
		kore_buf_free(data);
		return;
	}

	if (data->offset < 3) {
		kore_buf_free(data);
		return;
	}

	data->offset -= 2;
	string = kore_buf_stringify(data, NULL);
	http_argument_add(req, name, string, 0, 0);
	kore_buf_free(data);
}

static void
multipart_file_add(struct http_request *req, struct kore_buf *in,
    const char *name, const char *fname, const char *boundary, const int blen)
{
	struct http_file	*f;
	size_t			position, len;

	position = req->http_body_offset - in->offset;
	if (!multipart_find_data(in, NULL, &len, req, boundary, blen))
		return;

	if (len < 3)
		return;
	len -= 2;

	f = kore_malloc(sizeof(struct http_file));
	f->req = req;
	f->offset = 0;
	f->length = len;
	f->position = position;
	f->name = kore_strdup(name);
	f->filename = kore_strdup(fname);

	TAILQ_INSERT_TAIL(&(req->files), f, list);
}

static void
http_argument_add(struct http_request *req, char *name, char *value, int qs,
    int decode)
{
	struct http_arg			*q;
	struct kore_route_params	*p;

	if (decode) {
		if (!http_argument_urldecode(name))
			return;
	}

	TAILQ_FOREACH(p, &req->rt->params, list) {
		if (qs == 1 && !(p->flags & KORE_PARAMS_QUERY_STRING))
			continue;
		if (qs == 0 && (p->flags & KORE_PARAMS_QUERY_STRING))
			continue;

		if (p->method != req->method)
			continue;

		if (strcmp(p->name, name))
			continue;

		if (decode) {
			if (!http_argument_urldecode(value))
				return;
		}

		if (!kore_validator_check(req, p->validator, value))
			break;

		q = kore_malloc(sizeof(struct http_arg));
		q->name = kore_strdup(name);
		q->s_value = kore_strdup(value);
		TAILQ_INSERT_TAIL(&(req->arguments), q, list);
		break;
	}
}

static int
http_body_recv(struct netbuf *nb)
{
	struct http_request	*req = (struct http_request *)nb->extra;

	return (http_body_update(req, nb->buf, nb->s_off));
}

static int
http_body_update(struct http_request *req, const void *data, size_t len)
{
	ssize_t			ret;
	u_int64_t		bytes_left;

	SHA256Update(&req->hashctx, data, len);

	if (req->http_body_fd != -1) {
		ret = write(req->http_body_fd, data, len);
		if (ret == -1 || (size_t)ret != len) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_INTERNAL_ERROR);
			return (KORE_RESULT_ERROR);
		}
	} else if (req->http_body != NULL) {
		kore_buf_append(req->http_body, data, len);
	} else {
		req->flags |= HTTP_REQUEST_DELETE;
		http_error_response(req->owner,
		    HTTP_STATUS_INTERNAL_ERROR);
		return (KORE_RESULT_ERROR);
	}

	req->content_length -= len;

	if (req->content_length == 0) {
		req->owner->rnb->extra = NULL;
		http_request_wakeup(req);
		req->flags |= HTTP_REQUEST_COMPLETE;
		req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
		req->content_length = req->http_body_length;
		if (!http_body_rewind(req)) {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner,
			    HTTP_STATUS_INTERNAL_ERROR);
			return (KORE_RESULT_ERROR);
		}
		SHA256Final(req->http_body_digest, &req->hashctx);
	} else {
		bytes_left = req->content_length;
		net_recv_reset(req->owner,
		    MIN(bytes_left, NETBUF_SEND_PAYLOAD_MAX),
		    http_body_recv);
		req->owner->rnb->extra = req;
	}

	if (req->rt->on_body_chunk != NULL && len > 0) {
		kore_runtime_http_body_chunk(req->rt->on_body_chunk,
		    req, data, len);
	}

	return (KORE_RESULT_OK);
}

static void
http_error_response(struct connection *c, int status)
{
	c->flags |= CONN_CLOSE_EMPTY;

	switch (c->proto) {
	case CONN_PROTO_HTTP:
		http_response_normal(NULL, c, status, NULL, 0);
		break;
	default:
		fatal("http_error_response() bad proto %d", c->proto);
		/* NOTREACHED. */
	}

	if (!net_send_flush(c))
		kore_connection_disconnect(c);
}

static void
http_response_normal(struct http_request *req, struct connection *c,
    int status, const void *d, size_t len)
{
	struct kore_buf		buf;
	struct http_cookie	*ck;
	struct http_header	*hdr;
	char			version;
	const char		*conn, *text;
	int			connection_close, send_body;

	send_body = 1;
	text = http_status_text(status);

	kore_buf_reset(header_buf);

	if (req != NULL) {
		if (req->flags & HTTP_VERSION_1_0)
			version = '0';
		else
			version = '1';
	} else {
		version = '1';
	}

	kore_buf_appendf(header_buf, "HTTP/1.%c %d %s\r\n",
	    version, status, text);

	if (status == 100) {
		kore_buf_append(header_buf, "\r\n", 2);
		net_send_queue(c, header_buf->data, header_buf->offset);
		return;
	}

	kore_buf_append(header_buf, http_version, http_version_len);

	if ((c->flags & CONN_CLOSE_EMPTY) ||
	    (req != NULL && (req->flags & HTTP_VERSION_1_0))) {
		connection_close = 1;
	} else {
		connection_close = 0;
	}

	if (connection_close == 0 && req != NULL) {
		if (http_request_header(req, "connection", &conn)) {
			if ((*conn == 'c' || *conn == 'C') &&
			    !strcasecmp(conn, "close")) {
				connection_close = 1;
			}
		}
	}

	kore_buf_init(&buf, 1024);

	/* Note that req CAN be NULL. */
	if (req == NULL || req->owner->proto != CONN_PROTO_WEBSOCKET) {
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

	if (c->tls && http_hsts_enable) {
		kore_buf_appendf(header_buf, "strict-transport-security: ");
		kore_buf_appendf(header_buf,
		    "max-age=%" PRIu64 "; includeSubDomains\r\n",
		    http_hsts_enable);
	}

	if (http_pretty_error && d == NULL && status >= 400) {
		kore_buf_appendf(&buf, pretty_error_fmt,
		    status, text, status, text);

		d = buf.data;
		len = buf.offset;
	}

	if (req != NULL) {
		TAILQ_FOREACH(ck, &(req->resp_cookies), list)
			http_write_response_cookie(ck);

		TAILQ_FOREACH(hdr, &(req->resp_headers), list) {
			kore_buf_appendf(header_buf, "%s: %s\r\n",
			    hdr->header, hdr->value);
		}

		if (status != 204 && status >= 200 &&
		    !(req->flags & HTTP_REQUEST_NO_CONTENT_LENGTH)) {
			kore_buf_appendf(header_buf,
			    "content-length: %zu\r\n", len);
		}
	} else {
		if (status != 204 && status >= 200) {
			kore_buf_appendf(header_buf,
			    "content-length: %zu\r\n", len);
		}
	}

	kore_buf_append(header_buf, "\r\n", 2);
	net_send_queue(c, header_buf->data, header_buf->offset);

	if (req != NULL && req->method == HTTP_METHOD_HEAD)
		send_body = 0;

	if (d != NULL && send_body)
		net_send_queue(c, d, len);

	if (!(c->flags & CONN_CLOSE_EMPTY) && !(c->flags & CONN_IS_BUSY))
		http_start_recv(c);

	if (req != NULL)
		req->content_length = len;

	kore_buf_cleanup(&buf);
}

static void
http_write_response_cookie(struct http_cookie *ck)
{
	struct tm		tm;
	char			expires[HTTP_DATE_MAXSIZE];

	kore_buf_reset(ckhdr_buf);
	kore_buf_appendf(ckhdr_buf, "%s=%s", ck->name, ck->value);

	if (ck->path != NULL)
		kore_buf_appendf(ckhdr_buf, "; Path=%s", ck->path);
	if (ck->domain != NULL)
		kore_buf_appendf(ckhdr_buf, "; Domain=%s", ck->domain);

	if (ck->expires > 0) {
		if (gmtime_r(&ck->expires, &tm) == NULL) {
			kore_log(LOG_ERR, "gmtime_r(): %s", errno_s);
			return;
		}

		if (strftime(expires, sizeof(expires),
		    "%a, %d %b %y %H:%M:%S GMT", &tm) == 0) {
			kore_log(LOG_ERR, "strftime(): %s", errno_s);
			return;
		}

		kore_buf_appendf(ckhdr_buf, "; Expires=%s", expires);
	}

	if (ck->maxage > 0)
		kore_buf_appendf(ckhdr_buf, "; Max-Age=%u", ck->maxage);

	if (ck->flags & HTTP_COOKIE_HTTPONLY)
		kore_buf_appendf(ckhdr_buf, "; HttpOnly");
	if (ck->flags & HTTP_COOKIE_SECURE)
		kore_buf_appendf(ckhdr_buf, "; Secure");

	kore_buf_appendf(header_buf, "set-cookie: %s\r\n",
	    kore_buf_stringify(ckhdr_buf, NULL));
}

static int
http_data_convert(void *data, void **out, void *nout, int type)
{
	switch (type) {
	case HTTP_ARG_TYPE_RAW:
	case HTTP_ARG_TYPE_STRING:
		*out = data;
		return (KORE_RESULT_OK);
	case HTTP_ARG_TYPE_BYTE:
		COPY_ARG_TYPE(*(u_int8_t *)data, u_int8_t);
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
	case HTTP_ARG_TYPE_FLOAT:
		COPY_ARG_DOUBLE(-FLT_MAX, FLT_MAX, float);
		return (KORE_RESULT_OK);
	case HTTP_ARG_TYPE_DOUBLE:
		COPY_ARG_DOUBLE(-DBL_MAX, DBL_MAX, double);
		return (KORE_RESULT_OK);
	default:
		break;
	}

	return (KORE_RESULT_ERROR);
}
