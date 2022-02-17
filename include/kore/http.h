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

#if !defined(KORE_NO_HTTP)

#ifndef __H_HTTP_H
#define __H_HTTP_H

#include <sys/types.h>
#include <sys/queue.h>

#include "sha2.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Keep the http_populate_get symbol around. */
#define http_populate_get	http_populate_qs

#define HTTP_KEEPALIVE_TIME	20
#define HTTP_HSTS_ENABLE	31536000
#define HTTP_HEADER_MAX_LEN	4096
#define HTTP_BODY_MAX_LEN	1024000
#define HTTP_URI_LEN		2000
#define HTTP_USERAGENT_LEN	256
#define HTTP_REFERER_LEN	256
#define HTTP_REQ_HEADER_MAX	25
#define HTTP_MAX_QUERY_ARGS	20
#define HTTP_MAX_COOKIES	10
#define HTTP_MAX_COOKIENAME	255
#define HTTP_HEADER_BUFSIZE	1024
#define HTTP_COOKIE_BUFSIZE	1024
#define HTTP_DATE_MAXSIZE	255
#define HTTP_REQUEST_LIMIT	1000
#define HTTP_REQUEST_MS		10
#define HTTP_BODY_DISK_PATH	"tmp_files"
#define HTTP_BODY_DISK_OFFLOAD	0
#define HTTP_BODY_PATH_MAX	256
#define HTTP_BOUNDARY_MAX	80
#define HTTP_HEADER_TIMEOUT	10
#define HTTP_BODY_TIMEOUT	60

#define HTTP_ARG_TYPE_RAW	0
#define HTTP_ARG_TYPE_BYTE	1
#define HTTP_ARG_TYPE_INT16	2
#define HTTP_ARG_TYPE_UINT16	3
#define HTTP_ARG_TYPE_INT32	4
#define HTTP_ARG_TYPE_UINT32	5
#define HTTP_ARG_TYPE_STRING	6
#define HTTP_ARG_TYPE_INT64	7
#define HTTP_ARG_TYPE_UINT64	8
#define HTTP_ARG_TYPE_FLOAT	9
#define HTTP_ARG_TYPE_DOUBLE	10

#define HTTP_STATE_ERROR	0
#define HTTP_STATE_CONTINUE	1
#define HTTP_STATE_COMPLETE	2
#define HTTP_STATE_RETRY	3

struct http_runlock_queue {
	struct http_request		*req;
	LIST_ENTRY(http_runlock_queue)	list;
};

struct http_runlock {
	struct http_request		*owner;
	LIST_HEAD(, http_runlock_queue)	queue;
};

struct http_header {
	char			*header;
	char			*value;

	TAILQ_ENTRY(http_header)	list;
};

#define HTTP_COOKIE_HTTPONLY	0x0001
#define HTTP_COOKIE_SECURE	0x0002

struct http_cookie {
	char				*name;
	char				*value;
	char				*path;
	char				*domain;
	u_int32_t			maxage;
	time_t				expires;
	u_int16_t			flags;

	TAILQ_ENTRY(http_cookie)	list;
};

struct http_arg {
	char			*name;
	char			*s_value;

	TAILQ_ENTRY(http_arg)	list;
};

#define COPY_ARG_TYPE(v, t)				\
	do {						\
		*(t *)nout = v;				\
	} while (0)

#define COPY_ARG_INT64(type, sign)					\
	do {								\
		int err;						\
		type nval;						\
		nval = (type)kore_strtonum64(data, sign, &err);		\
		if (err != KORE_RESULT_OK)				\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_TYPE(nval, type);				\
	} while (0)

#define COPY_ARG_DOUBLE(min, max, type)					\
	do {								\
		int err;						\
		type nval;						\
		nval = kore_strtodouble(data, min, max, &err);		\
		if (err != KORE_RESULT_OK)				\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_TYPE(nval, type);				\
	} while (0)

#define COPY_ARG_INT(min, max, type)					\
	do {								\
		int err;						\
		int64_t nval;						\
		nval = kore_strtonum(data, 10, min, max, &err);		\
		if (err != KORE_RESULT_OK)				\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_TYPE(nval, type);				\
	} while (0)

#define COPY_AS_INTTYPE_64(type, sign)					\
	do {								\
		if (nout == NULL)					\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_INT64(type, sign);				\
	} while (0)

#define COPY_AS_INTTYPE(min, max, type)					\
	do {								\
		if (nout == NULL)					\
			return (KORE_RESULT_ERROR);			\
		COPY_ARG_INT(min, max, type);				\
	} while (0)

#define http_argument_get_string(r, n, o)				\
	http_argument_get(r, n, (void **)o, NULL, HTTP_ARG_TYPE_STRING)

#define http_argument_get_byte(r, n, o)					\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_BYTE)

#define http_argument_get_uint16(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT16)

#define http_argument_get_int16(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_INT16)

#define http_argument_get_uint32(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT32)

#define http_argument_get_int32(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_INT32)

#define http_argument_get_uint64(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT64)

#define http_argument_get_int64(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_INT64)

#define http_argument_get_float(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_FLOAT)

#define http_argument_get_double(r, n, o)				\
	http_argument_get(r, n, NULL, o, HTTP_ARG_TYPE_DOUBLE)

#define http_request_header_byte(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_BYTE)

#define http_request_header_uint16(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT16)

#define http_request_header_int16(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_INT16)

#define http_request_header_uint32(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT32)

#define http_request_header_int32(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_INT32)

#define http_request_header_uint64(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_UINT64)

#define http_request_header_int64(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_INT64)

#define http_request_header_float(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_FLOAT)

#define http_request_header_double(r, n, o)				\
	http_request_header_get(r, n, NULL, o, HTTP_ARG_TYPE_DOUBLE)

struct http_file {
	char			*name;
	char			*filename;
	size_t			position;
	size_t			offset;
	size_t			length;
	struct http_request	*req;
	TAILQ_ENTRY(http_file)	list;
};

#define HTTP_METHOD_GET		0x0001
#define HTTP_METHOD_POST	0x0002
#define HTTP_METHOD_PUT		0x0004
#define HTTP_METHOD_DELETE	0x0010
#define HTTP_METHOD_HEAD	0x0020
#define HTTP_METHOD_OPTIONS	0x0040
#define HTTP_METHOD_PATCH	0x0080

#define HTTP_METHOD_ALL		(HTTP_METHOD_GET | HTTP_METHOD_POST | \
    HTTP_METHOD_PUT | HTTP_METHOD_DELETE | HTTP_METHOD_HEAD | \
    HTTP_METHOD_OPTIONS | HTTP_METHOD_PATCH)

#define HTTP_REQUEST_COMPLETE		0x0001
#define HTTP_REQUEST_DELETE		0x0002
#define HTTP_REQUEST_SLEEPING		0x0004
#define HTTP_REQUEST_EXPECT_BODY	0x0020
#define HTTP_REQUEST_RETAIN_EXTRA	0x0040
#define HTTP_REQUEST_NO_CONTENT_LENGTH	0x0080
#define HTTP_REQUEST_AUTHED		0x0100

#define HTTP_VERSION_1_1		0x1000
#define HTTP_VERSION_1_0		0x2000

#define HTTP_VALIDATOR_IS_REQUEST	0x8000

#define HTTP_BODY_DIGEST_LEN		32
#define HTTP_BODY_DIGEST_STRLEN		((HTTP_BODY_DIGEST_LEN * 2) + 1)

#define HTTP_CAPTURE_GROUPS		17

struct reqcall;
struct kore_task;
struct http_client;

struct http_redirect {
	regex_t				rctx;
	int				status;
	char				*target;
	TAILQ_ENTRY(http_redirect)	list;
};

struct http_request {
	u_int8_t			method;
	u_int8_t			fsm_state;
	u_int16_t			flags;
	u_int16_t			status;
	u_int64_t			ms;
	u_int64_t			start;
	u_int64_t			end;
	u_int64_t			total;
	const char			*path;
	const char			*host;
	const char			*agent;
	const char			*referer;
	struct connection		*owner;
	SHA2_CTX			hashctx;
	u_int8_t			*headers;
	struct kore_buf			*http_body;
	int				http_body_fd;
	char				*http_body_path;
	u_int64_t			http_body_length;
	u_int64_t			http_body_offset;
	u_int64_t			content_length;
	void				*hdlr_extra;
	size_t				state_len;
	char				*query_string;
	struct kore_route		*rt;
	struct http_runlock_queue	*runlock;
	void				(*onfree)(struct http_request *);

#if defined(KORE_USE_PYTHON)
	void				*py_req;
	void				*py_coro;
	void				*py_validator;
	struct reqcall			*py_rqnext;
#endif

	regmatch_t	cgroups[HTTP_CAPTURE_GROUPS];
	u_int8_t	http_body_digest[HTTP_BODY_DIGEST_LEN];

#if defined(KORE_USE_CURL)
	LIST_HEAD(, kore_curl)		chandles;
#endif

#if defined(KORE_USE_TASKS)
	LIST_HEAD(, kore_task)		tasks;
#endif

#if defined(KORE_USE_PGSQL)
	LIST_HEAD(, kore_pgsql)		pgsqls;
#endif

	TAILQ_HEAD(, http_cookie)	req_cookies;
	TAILQ_HEAD(, http_cookie)	resp_cookies;
	TAILQ_HEAD(, http_header)	req_headers;
	TAILQ_HEAD(, http_header)	resp_headers;
	TAILQ_HEAD(, http_arg)		arguments;
	TAILQ_HEAD(, http_file)		files;
	TAILQ_ENTRY(http_request)	list;
	TAILQ_ENTRY(http_request)	olist;
};

#define KORE_HTTP_STATE(f)		{ #f, f }

struct http_state {
	const char		*name;
	int			(*cb)(struct http_request *);
};

struct http_media_type {
	char				*ext;
	char				*type;
	LIST_ENTRY(http_media_type)	list;
};

extern size_t		http_body_max;
extern u_int16_t	http_body_timeout;
extern u_int16_t	http_header_max;
extern u_int16_t	http_header_timeout;
extern u_int32_t	http_request_ms;
extern u_int64_t	http_hsts_enable;
extern u_int16_t	http_keepalive_time;
extern u_int32_t	http_request_limit;
extern u_int32_t	http_request_count;
extern u_int64_t	http_body_disk_offload;
extern int		http_pretty_error;
extern char		*http_body_disk_path;
extern struct kore_pool	http_header_pool;

void		kore_accesslog(struct http_request *);

void		http_init(void);
void		http_parent_init(void);
void		http_cleanup(void);
void 		http_server_version(const char *);
void		http_process(void);
const char	*http_status_text(int);
const char	*http_method_text(int);
time_t		http_date_to_time(char *);
char		*http_validate_header(char *);
int		http_method_value(const char *);
void		http_start_recv(struct connection *);
void		http_request_free(struct http_request *);
void		http_request_sleep(struct http_request *);
void		http_request_wakeup(struct http_request *);
void		http_process_request(struct http_request *);
int		http_body_rewind(struct http_request *);
int		http_media_register(const char *, const char *);
int		http_check_timeout(struct connection *, u_int64_t);
ssize_t		http_body_read(struct http_request *, void *, size_t);
int		http_body_digest(struct http_request *, char *, size_t);

int		http_redirect_add(struct kore_domain *,
		    const char *, int, const char *);
void		http_response(struct http_request *, int, const void *, size_t);
void		http_response_json(struct http_request *, int,
		    struct kore_json_item *);
void		http_response_close(struct http_request *, int,
		    const void *, size_t);
void		http_response_fileref(struct http_request *, int,
		    struct kore_fileref *);
void		http_serveable(struct http_request *, const void *,
		    size_t, const char *, const char *);
void		http_response_stream(struct http_request *, int, void *,
		    size_t, int (*cb)(struct netbuf *), void *);
int		http_request_header(struct http_request *,
		    const char *, const char **);
void		http_response_header(struct http_request *,
		    const char *, const char *);
int		http_state_run(struct http_state *, u_int8_t,
		    struct http_request *);
int	 	http_request_cookie(struct http_request *,
		    const char *, char **);
void		http_response_cookie(struct http_request *, const char *,
		    const char *, const char *, time_t, u_int32_t,
		    struct http_cookie **);

void		http_runlock_init(struct http_runlock *);
void		http_runlock_release(struct http_runlock *,
		    struct http_request *);
int		http_runlock_acquire(struct http_runlock *,
		    struct http_request *);

const char	*http_media_type(const char *);
void		*http_state_get(struct http_request *);
int		http_state_exists(struct http_request *);
void		http_state_cleanup(struct http_request *);
void		*http_state_create(struct http_request *, size_t);

int		http_argument_urldecode(char *);
int		http_header_recv(struct netbuf *);
void		http_populate_qs(struct http_request *);
void		http_populate_post(struct http_request *);
void		http_populate_multipart_form(struct http_request *);
void		http_populate_cookies(struct http_request *);
int		http_argument_get(struct http_request *,
		    const char *, void **, void *, int);
int		http_request_header_get(struct http_request *,
		    const char *, void **, void *, int);

void			http_file_rewind(struct http_file *);
ssize_t			http_file_read(struct http_file *, void *, size_t);
struct http_file	*http_file_lookup(struct http_request *, const char *);

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
	HTTP_STATUS_MISDIRECTED_REQUEST		= 421,
	HTTP_STATUS_INTERNAL_ERROR		= 500,
	HTTP_STATUS_NOT_IMPLEMENTED		= 501,
	HTTP_STATUS_BAD_GATEWAY			= 502,
	HTTP_STATUS_SERVICE_UNAVAILABLE		= 503,
	HTTP_STATUS_GATEWAY_TIMEOUT		= 504,
	HTTP_STATUS_BAD_VERSION			= 505
};
#if defined(__cplusplus)
}
#endif
#endif /* !__H_HTTP_H */

#endif /* ! KORE_NO_HTTP */
