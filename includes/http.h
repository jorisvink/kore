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

struct http_header {
	char			*header;
	char			*value;

	TAILQ_ENTRY(http_header)	list;
};

struct http_request {
	char			*host;
	char			*method;
	char			*path;

	struct connection	*owner;
	struct spdy_stream	*stream;

	TAILQ_HEAD(, http_header)	headers;
	TAILQ_ENTRY(http_request)	list;
};

void		http_init(void);
void		http_process(void);
time_t		http_date_to_time(char *);
void		http_request_free(struct http_request *);
int		http_response(struct http_request *, int,
		    u_int8_t *, u_int32_t);
int		http_request_header_get(struct http_request *, char *, char **);
void		http_response_header_add(struct http_request *, char *, char *);
int		http_request_new(struct connection *, struct spdy_stream *,
		    char *, char *, char *);

#endif /* !__H_HTTP_H */
