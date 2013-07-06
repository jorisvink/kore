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
