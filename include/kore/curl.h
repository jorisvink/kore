/*
 * Copyright (c) 2019-2022 Joris Vink <joris@coders.se>
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

#ifndef __H_CURL_H
#define __H_CURL_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <curl/curl.h>

#include "http.h"

#define KORE_CURL_TIMEOUT			60
#define KORE_CURL_RECV_MAX			(1024 * 1024 * 2)

#define KORE_CURL_FLAG_HTTP_PARSED_HEADERS	0x0001
#define KORE_CURL_FLAG_BOUND			0x0002

#define KORE_CURL_SYNC				0x1000
#define KORE_CURL_ASYNC				0x2000

#define KORE_CURL_TYPE_CUSTOM			1
#define KORE_CURL_TYPE_HTTP_CLIENT		2

struct kore_curl {
	int			type;
	int			flags;
	CURLcode		result;

	char			*url;
	CURL			*handle;
	struct kore_buf		*response;

	struct http_request	*req;
	void			*arg;
	void			(*cb)(struct kore_curl *, void *);

	char			errbuf[CURL_ERROR_SIZE];

	/* For the simplified HTTP api. */
	struct {
		long				status;
		struct curl_slist		*hdrlist;

		struct kore_buf			*tosend;
		struct kore_buf			*headers;

		TAILQ_HEAD(, http_header)	resp_hdrs;
	} http;

	LIST_ENTRY(kore_curl)		list;
};

extern u_int16_t	kore_curl_timeout;
extern u_int64_t	kore_curl_recv_max;

void	kore_curl_sysinit(void);
void	kore_curl_do_timeout(void);
void	kore_curl_run_scheduled(void);
void	kore_curl_run(struct kore_curl *);
void	kore_curl_cleanup(struct kore_curl *);
int	kore_curl_success(struct kore_curl *);
void	kore_curl_run_sync(struct kore_curl *);
void	kore_curl_logerror(struct kore_curl *);
int	kore_curl_init(struct kore_curl *, const char *, int);

size_t	kore_curl_tobuf(char *, size_t, size_t, void *);
size_t	kore_curl_frombuf(char *, size_t, size_t, void *);

void	kore_curl_http_parse_headers(struct kore_curl *);
void	kore_curl_http_set_header(struct kore_curl *, const char *,
	    const char *);
int	kore_curl_http_get_header(struct kore_curl *, const char *,
	    const char **);
void	kore_curl_http_setup(struct kore_curl *, int, const void *, size_t);

char	*kore_curl_response_as_string(struct kore_curl *);
void	kore_curl_response_as_bytes(struct kore_curl *,
	    const u_int8_t **, size_t *);

void	kore_curl_bind_request(struct kore_curl *, struct http_request *);
void	kore_curl_bind_callback(struct kore_curl *,
	    void (*cb)(struct kore_curl *, void *), void *);

const char	*kore_curl_strerror(struct kore_curl *);

#if defined(__cplusplus)
}
#endif

#endif
