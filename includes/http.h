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

#define HTTP_HEADER_MAX_LEN	8192
#define HTTP_URI_LEN		2000
#define HTTP_USERAGENT_LEN	256
#define HTTP_REQ_HEADER_MAX	25
#define HTTP_MAX_QUERY_ARGS	10

struct http_header {
	char			*header;
	char			*value;

	TAILQ_ENTRY(http_header)	list;
};

struct http_arg {
	char			*name;
	char			*value;

	TAILQ_ENTRY(http_arg)	list;
};

#define HTTP_METHOD_GET		0
#define HTTP_METHOD_POST	1

#define HTTP_REQUEST_COMPLETE	0x01
#define HTTP_REQUEST_DELETE	0x02

struct http_request {
	u_int8_t		method;
	u_int8_t		flags;
	int			status;
	u_int64_t		start;
	u_int64_t		end;
	char			*host;
	char			*path;
	char			*agent;
	struct connection	*owner;
	struct spdy_stream	*stream;
	struct kore_buf		*post_data;

	TAILQ_HEAD(, http_header)	req_headers;
	TAILQ_HEAD(, http_header)	resp_headers;
	TAILQ_HEAD(, http_arg)		arguments;
	TAILQ_ENTRY(http_request)	list;
};

extern int	http_request_count;

void		http_init(void);
void		http_process(void);
time_t		http_date_to_time(char *);
void		http_request_free(struct http_request *);
int		http_response(struct http_request *, int,
		    u_int8_t *, u_int32_t);
int		http_request_header_get(struct http_request *, char *, char **);
void		http_response_header_add(struct http_request *, char *, char *);
int		http_request_new(struct connection *, struct spdy_stream *,
		    char *, char *, char *, struct http_request **);

int		http_generic_404(struct http_request *);
int		http_header_recv(struct netbuf *);
char		*http_post_data_text(struct http_request *);
int		http_populate_arguments(struct http_request *);
int		http_argument_lookup(struct http_request *,
		    const char *, char **);

void		kore_accesslog(struct http_request *);

#endif /* !__H_HTTP_H */
