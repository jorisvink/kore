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

#include <kore/kore.h>
#include <kore/http.h>

#include <yajl/yajl_tree.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	ssize_t			ret;
	struct kore_buf		*buf;
	char			*body;
	yajl_val		node, v;
	char			eb[1024];
	u_int8_t		data[BUFSIZ];
	const char		*path[] = { "foo", "bar", NULL };

	/* We only allow POST/PUT methods. */
	if (req->method != HTTP_METHOD_POST &&
	    req->method != HTTP_METHOD_PUT) {
		http_response_header(req, "allow", "POST, PUT");
		http_response(req, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/*
	 * Read the entire received body into a memory buffer.
	 */
	buf = kore_buf_create(128);
	for (;;) {
		ret = http_body_read(req, data, sizeof(data));
		if (ret == -1) {
			kore_buf_free(buf);
			kore_log(LOG_NOTICE, "error reading body");
			http_response(req, 500, NULL, 0);
			return (KORE_RESULT_OK);
		}

		if (ret == 0)
			break;

		kore_buf_append(buf, data, ret);
	}

	/* Grab our body data as a NUL-terminated string. */
	body = kore_buf_stringify(buf, NULL);

	/* Parse the body via yajl now. */
	node = yajl_tree_parse(body, eb, sizeof(eb));
	if (node == NULL) {
		if (strlen(eb)) {
			kore_log(LOG_NOTICE, "parse error: %s", eb);
		} else {
			kore_log(LOG_NOTICE, "parse error: unknown");
		}

		kore_buf_free(buf);
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Reuse old buffer, don't need it anymore for body. */
	kore_buf_reset(buf);

	/* Attempt to grab foo.bar from the JSON tree. */
	v = yajl_tree_get(node, path, yajl_t_string);
	if (v == NULL) {
		kore_buf_appendf(buf, "no such path: foo.bar\n");
	} else {
		kore_buf_appendf(buf, "foo.bar = '%s'\n", YAJL_GET_STRING(v));
	}

	/* Release the JSON tree now. */
	yajl_tree_free(node);

	/* Respond to the client. */
	http_response(req, 200, buf->data, buf->offset);
	kore_buf_free(buf);

	return (KORE_RESULT_OK);
}
