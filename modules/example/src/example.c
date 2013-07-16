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

#include "static.h"

int		serve_style_css(struct http_request *);
int		serve_index(struct http_request *);
int		serve_intro(struct http_request *);
int		serve_b64test(struct http_request *);
int		serve_spdyreset(struct http_request *);

void		test_base64(u_int8_t *, u_int32_t, struct kore_buf *);

char *b64tests[] = {
	"1234567890",
	"One two three four five",
	"Man",
	"any carnal pleasure.",
	"any carnal pleasure",
	"any carnal pleas",
	"I am a nobody, nobody is perfect, therefor I am.",
	NULL
};

int
serve_style_css(struct http_request *req)
{
	int		ret;
	char		*date;
	time_t		tstamp;

	tstamp = 0;
	if (http_request_header_get(req, "if-modified-since", &date)) {
		tstamp = kore_date_to_time(date);
		kore_mem_free(date);

		kore_debug("header was present with %ld", tstamp);
	}

	if (tstamp != 0 && tstamp <= static_mtime_css_style) {
		ret = http_response(req, 304, NULL, 0);
	} else {
		date = kore_time_to_date(static_mtime_css_style);
		if (date != NULL)
			http_response_header_add(req, "last-modified", date);

		http_response_header_add(req, "content-type", "text/css");
		ret = http_response(req, 200, static_css_style,
		    static_len_css_style);
	}

	return (ret);
}

int
serve_index(struct http_request *req)
{
	int		ret;

	http_response_header_add(req, "content-type", "text/html");
	ret = http_response(req, 200, static_html_index,
	    static_len_html_index);

	return (ret);
}

int
serve_intro(struct http_request *req)
{
	int		ret;

	http_response_header_add(req, "content-type", "image/jpg");
	ret = http_response(req, 200, static_jpg_intro,
	    static_len_jpg_intro);

	return (ret);
}

int
serve_b64test(struct http_request *req)
{
	int			i, ret;
	u_int32_t		len;
	struct kore_buf		*res;
	u_int8_t		*data;

	res = kore_buf_create(1024);
	for (i = 0; b64tests[i] != NULL; i++)
		test_base64((u_int8_t *)b64tests[i], strlen(b64tests[i]), res);

	data = kore_buf_release(res, &len);

	http_response_header_add(req, "content-type", "text/plain");
	ret = http_response(req, 200, data, len);
	kore_mem_free(data);

	return (ret);
}

int
serve_spdyreset(struct http_request *req)
{
	spdy_session_teardown(req->owner, SPDY_SESSION_ERROR_OK);
	return (KORE_RESULT_OK);
}

void
test_base64(u_int8_t *src, u_int32_t slen, struct kore_buf *res)
{
	char		*in;
	u_int32_t	len;
	u_int8_t	*out;

	kore_buf_appendf(res, "test '%s'\n", src);

	if (!kore_base64_encode(src, slen, &in)) {
		kore_buf_appendf(res, "encoding '%s' failed\n", src);
	} else {
		kore_buf_appendf(res, "encoded: '%s'\n", in);

		if (!kore_base64_decode(in, &out, &len)) {
			kore_buf_appendf(res, "decoding failed\n");
		} else {
			kore_buf_appendf(res, "decoded: ");
			kore_buf_append(res, out, len);
			kore_buf_appendf(res, "\n");
			kore_mem_free(out);
		}

		kore_mem_free(in);
	}

	kore_buf_appendf(res, "\n");
}
