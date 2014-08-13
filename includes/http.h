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

#ifndef __H_HTTP_H
#define __H_HTTP_H

#define HTTP_KEEPALIVE_TIME	20
#define HTTP_HSTS_ENABLE	31536000
#define HTTP_HEADER_MAX_LEN	4096
#define HTTP_POSTBODY_MAX_LEN	10240000
#define HTTP_URI_LEN		2000
#define HTTP_USERAGENT_LEN	256
#define HTTP_REQ_HEADER_MAX	25
#define HTTP_MAX_QUERY_ARGS	10
#define HTTP_MAX_COOKIES	10

#define HTTP_ARG_TYPE_RAW	0
#define HTTP_ARG_TYPE_BYTE	1
#define HTTP_ARG_TYPE_INT16	2
#define HTTP_ARG_TYPE_UINT16	3
#define HTTP_ARG_TYPE_INT32	4
#define HTTP_ARG_TYPE_UINT32	5
#define HTTP_ARG_TYPE_STRING	6
#define HTTP_ARG_TYPE_INT64	7
#define HTTP_ARG_TYPE_UINT64	8

#define HTTP_STATE_ERROR	0
#define HTTP_STATE_OK		1
#define HTTP_STATE_COMPLETE	2
#define HTTP_STATE_RETRY	3

struct http_header {
	char			*header;
	char			*value;

	TAILQ_ENTRY(http_header)	list;
};

struct http_arg {
	char			*name;
	void			*value;
	u_int32_t		len;

	char			*s_value;
	u_int32_t		s_len;

	TAILQ_ENTRY(http_arg)	list;
};

#define COPY_ARG_TYPE(v, l, t)				\
	do {						\
		if (l != NULL)				\
			*l = sizeof(t);			\
		*(t *)nout = v;				\
	} while (0);

#define COPY_ARG_INT64(type, sign)					\
	do {								\
		int err;						\
		type nval;						\
		nval = (type)kore_strtonum64(q->s_value, sign, &err);	\
		if (err != KORE_RESULT_OK)				\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_TYPE(nval, len, type);				\
	} while (0);

#define COPY_ARG_INT(min, max, type)					\
	do {								\
		int err;						\
		int64_t nval;						\
		nval = kore_strtonum(q->s_value, 10, min, max, &err);	\
		if (err != KORE_RESULT_OK)				\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_TYPE(nval, len, type);				\
	} while (0);

#define CACHE_STRING()							\
	do {								\
		if (q->s_value == NULL) {				\
			q->s_len = q->len + 1;				\
			q->s_value = kore_malloc(q->s_len);		\
			kore_strlcpy(q->s_value, q->value, q->s_len);	\
		}							\
	} while (0);

#define COPY_AS_INTTYPE_64(type, sign)					\
	do {								\
		if (nout == NULL)					\
			return (KORE_RESULT_ERROR);			\
		CACHE_STRING();						\
		COPY_ARG_INT64(type, sign);				\
	} while (0);

#define COPY_AS_INTTYPE(min, max, type)					\
	do {								\
		if (nout == NULL)					\
			return (KORE_RESULT_ERROR);			\
		CACHE_STRING();						\
		COPY_ARG_INT(min, max, type);				\
	} while (0);

#define http_argument_type(r, n, so, no, l, t)				\
	http_argument_get(r, n, so, no, l, t)

#define http_argument_get_string(n, o, l)				\
	http_argument_type(req, n, (void **)o, NULL, l, HTTP_ARG_TYPE_STRING)

#define http_argument_get_byte(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_BYTE)

#define http_argument_get_uint16(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_UINT16)

#define http_argument_get_int16(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_INT16)

#define http_argument_get_uint32(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_UINT32)

#define http_argument_get_int32(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_INT32)

#define http_argument_get_uint64(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_UINT64)

#define http_argument_get_int64(n, o)					\
	http_argument_type(req, n, NULL, o, NULL, HTTP_ARG_TYPE_INT64)


struct http_file {
	char			*name;
	char			*filename;

	u_int8_t		*data;
	u_int32_t		len;

	TAILQ_ENTRY(http_file)	list;
};

#define HTTP_METHOD_GET		0
#define HTTP_METHOD_POST	1

#define HTTP_REQUEST_COMPLETE		0x01
#define HTTP_REQUEST_DELETE		0x02
#define HTTP_REQUEST_SLEEPING		0x04

#define HTTP_PGSQL_MAX			20
struct kore_pgsql;
struct kore_task;

struct http_request {
	u_int8_t			method;
	u_int8_t			flags;
	u_int8_t			fsm_state;
	int				status;
	u_int64_t			start;
	u_int64_t			end;
	u_int64_t			total;
	char				host[KORE_DOMAINNAME_LEN];
	char				path[HTTP_URI_LEN];
	char				*agent;
	struct connection		*owner;
	struct spdy_stream		*stream;
	struct kore_buf			*post_data;
	void				*hdlr_extra;
	char				*query_string;
	u_int8_t			*multipart_body;

	struct kore_module_handle	*hdlr;
	struct kore_task		*task;
	struct kore_pgsql		*pgsql[HTTP_PGSQL_MAX];

	TAILQ_HEAD(, http_header)		req_headers;
	TAILQ_HEAD(, http_header)		resp_headers;
	TAILQ_HEAD(, http_arg)			arguments;
	TAILQ_HEAD(, http_file)			files;
	TAILQ_ENTRY(http_request)		list;
	TAILQ_ENTRY(http_request)		olist;
};

struct http_state {
	const char		*name;
	int			(*cb)(struct http_request *);
};

extern int		http_request_count;
extern u_int16_t	http_header_max;
extern u_int64_t	http_postbody_max;
extern u_int64_t	http_hsts_enable;
extern u_int16_t	http_keepalive_time;

void		http_init(void);
void		http_process(void);
time_t		http_date_to_time(char *);
void		http_request_free(struct http_request *);
void		http_request_sleep(struct http_request *);
void		http_request_wakeup(struct http_request *);
char		*http_post_data_text(struct http_request *);
void		http_process_request(struct http_request *, int);
u_int8_t	*http_post_data_bytes(struct http_request *, u_int32_t *);
void		http_response(struct http_request *, int, void *, u_int32_t);
void		http_response_stream(struct http_request *, int, void *,
		    u_int64_t, int (*cb)(struct netbuf *), void *);
int		http_request_header(struct http_request *,
		    const char *, char **);
void		http_response_header(struct http_request *,
		    const char *, const char *);
int		http_request_new(struct connection *, struct spdy_stream *,
		    const char *, const char *, const char *, const char *,
		    struct http_request **);
int		http_state_run(struct http_state *, u_int8_t,
		    struct http_request *);

int		http_argument_urldecode(char *);
int		http_header_recv(struct netbuf *);
int		http_generic_404(struct http_request *);
int		http_populate_arguments(struct http_request *);
int		http_populate_multipart_form(struct http_request *, int *);
int		http_argument_get(struct http_request *,
		    const char *, void **, void *, u_int32_t *, int);
int		http_file_lookup(struct http_request *, const char *, char **,
		    u_int8_t **, u_int32_t *);

void		kore_accesslog(struct http_request *);

enum http_status_code {
	HTTP_STATUS_CONTINUE			= 100,
	HTTP_STATUS_SWITCHING_PROTOCOLS		= 101,
	HTTP_STATUS_OK				= 200,
	HTTP_STATUS_CREATED			= 201,
	HTTP_STATUS_ACCEPTED			= 202,
	HTTP_STATUS_NON_AUTHORITATIVE		= 203,
	HTTP_STATUS_NO_CONTENT			= 204,
	HTTP_STATUS_RESET_CONTENT		= 205,
	HTTP_STATUS_PARTIAL_CONTENT		= 206,
	HTTP_STATUS_MULTIPLE_CHOICES		= 300,
	HTTP_STATUS_MOVED_PERMANENTLY		= 301,
	HTTP_STATUS_FOUND			= 302,
	HTTP_STATUS_SEE_OTHER			= 303,
	HTTP_STATUS_NOT_MODIFIED		= 304,
	HTTP_STATUS_USE_PROXY			= 305,
	HTTP_STATUS_TEMPORARY_REDIRECT		= 307,
	HTTP_STATUS_BAD_REQUEST			= 400,
	HTTP_STATUS_UNAUTHORIZED		= 401,
	HTTP_STATUS_PAYMENT_REQUIRED		= 402,
	HTTP_STATUS_FORBIDDEN			= 403,
	HTTP_STATUS_NOT_FOUND			= 404,
	HTTP_STATUS_METHOD_NOT_ALLOWED		= 405,
	HTTP_STATUS_NOT_ACCEPTABLE		= 406,
	HTTP_STATUS_PROXY_AUTH_REQUIRED		= 407,
	HTTP_STATUS_REQUEST_TIMEOUT		= 408,
	HTTP_STATUS_CONFLICT			= 409,
	HTTP_STATUS_GONE			= 410,
	HTTP_STATUS_LENGTH_REQUIRED		= 411,
	HTTP_STATUS_PRECONDITION_FAILED		= 412,
	HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE	= 413,
	HTTP_STATUS_REQUEST_URI_TOO_LARGE	= 414,
	HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE	= 415,
	HTTP_STATUS_REQUEST_RANGE_INVALID	= 416,
	HTTP_STATUS_EXPECTATION_FAILED		= 417,
	HTTP_STATUS_INTERNAL_ERROR		= 500,
	HTTP_STATUS_NOT_IMPLEMENTED		= 501,
	HTTP_STATUS_BAD_GATEWAY			= 502,
	HTTP_STATUS_SERVICE_UNAVAILABLE		= 503,
	HTTP_STATUS_GATEWAY_TIMEOUT		= 504,
	HTTP_STATUS_BAD_VERSION			= 505
};

#endif /* !__H_HTTP_H */
