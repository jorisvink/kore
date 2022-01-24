/*
 * Copyright (c) 2019 Joris Vink <joris@coders.se>
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

int		page(struct http_request *);

int
page(struct http_request *req)
{
	struct kore_buf		buf;
	struct kore_json	json;
	struct kore_json_item	*item;

	kore_buf_init(&buf, 128);
	kore_json_init(&json, req->http_body->data, req->http_body->length);

	if (!kore_json_parse(&json)) {
		kore_buf_appendf(&buf, "%s\n", kore_json_strerror());
	} else {
		item = kore_json_find_string(json.root, "foo/bar");
		if (item != NULL) {
			kore_buf_appendf(&buf,
			    "foo.bar = '%s'\n", item->data.string);
		} else {
			kore_buf_appendf(&buf, "foo.bar %s\n",
			    kore_json_strerror());
		}

		item = kore_json_find_integer_u64(json.root, "foo/integer");
		if (item != NULL) {
			kore_buf_appendf(&buf,
			    "foo.integer = '%" PRIu64 "'\n", item->data.u64);
		} else {
			kore_buf_appendf(&buf, "foo.integer %s\n",
			    kore_json_strerror());
		}
	}

	http_response(req, 200, buf.data, buf.offset);

	kore_buf_cleanup(&buf);
	kore_json_cleanup(&json);

	return (KORE_RESULT_OK);
}
