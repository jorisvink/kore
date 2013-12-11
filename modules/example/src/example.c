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
int		serve_file_upload(struct http_request *);
int		serve_lock_test(struct http_request *);
int		serve_validator(struct http_request *);
int		serve_params_test(struct http_request *);

void		my_callback(void);
int		v_example_func(char *);
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

int
serve_file_upload(struct http_request *req)
{
	int			r;
	u_int8_t		*d;
	struct kore_buf		*b;
	u_int32_t		len;
	char			*name, buf[BUFSIZ];

	b = kore_buf_create(static_len_html_upload);
	kore_buf_append(b, static_html_upload, static_len_html_upload);

	if (req->method == HTTP_METHOD_POST) {
		http_populate_multipart_form(req, &r);
		if (http_argument_get_string("firstname", &name, &len)) {
			kore_buf_replace_string(b, "$firstname$", name, len);
		} else {
			kore_buf_replace_string(b, "$firstname$", NULL, 0);
		}

		if (http_file_lookup(req, "file", &name, &d, &len)) {
			snprintf(buf, sizeof(buf), "%s is %d bytes", name, len);
			kore_buf_replace_string(b,
			    "$upload$", buf, strlen(buf));
		} else {
			kore_buf_replace_string(b, "$upload$", NULL, 0);
		}
	} else {
		kore_buf_replace_string(b, "$upload$", NULL, 0);
		kore_buf_replace_string(b, "$firstname$", NULL, 0);
	}

	d = kore_buf_release(b, &len);

	http_response_header_add(req, "content-type", "text/html");
	r = http_response(req, 200, d, len);
	kore_mem_free(d);

	return (r);
}

int
serve_lock_test(struct http_request *req)
{
	kore_log(LOG_NOTICE, "lock-test called on worker %d", worker->id);
	kore_worker_acceptlock_release();

	return (http_response(req, 200, (u_int8_t *)"OK", 2));
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

int
serve_validator(struct http_request *req)
{
	if (kore_validator_run("v_example", "test"))
		kore_log(LOG_NOTICE, "v_example ok (expected)");
	else
		kore_log(LOG_NOTICE, "v_example failed");

	if (kore_validator_run("v_regex", "/test/123"))
		kore_log(LOG_NOTICE, "regex #1 ok");
	else
		kore_log(LOG_NOTICE, "regex #1 failed (expected)");

	if (kore_validator_run("v_regex", "/test/joris"))
		kore_log(LOG_NOTICE, "regex #2 ok (expected)");
	else
		kore_log(LOG_NOTICE, "regex #2 failed");

	return (http_response(req, 200, (u_int8_t *)"OK", 2));
}

int
serve_params_test(struct http_request *req)
{
	struct kore_buf		*b;
	u_int8_t		*d;
	u_int32_t		len;
	int			r, i;
	char			*test, name[10];

	http_populate_arguments(req);

	b = kore_buf_create(static_len_html_params);
	kore_buf_append(b, static_html_params, static_len_html_params);

	/*
	 * The GET parameters will be filtered out on POST.
	 */
	if (http_argument_get_string("arg1", &test, &len)) {
		kore_buf_replace_string(b, "$arg1$", test, len);
	} else {
		kore_buf_replace_string(b, "$arg1$", NULL, 0);
	}

	if (http_argument_get_string("arg2", &test, &len)) {
		kore_buf_replace_string(b, "$arg2$", test, len);
	} else {
		kore_buf_replace_string(b, "$arg2$", NULL, 0);
	}

	if (req->method == HTTP_METHOD_GET) {
		kore_buf_replace_string(b, "$test1$", NULL, 0);
		kore_buf_replace_string(b, "$test2$", NULL, 0);
		kore_buf_replace_string(b, "$test3$", NULL, 0);

		if (http_argument_get_uint16("id", &r))
			kore_log(LOG_NOTICE, "id: %d", r);
		else
			kore_log(LOG_NOTICE, "No id set");

		http_response_header_add(req, "content-type", "text/html");
		d = kore_buf_release(b, &len);
		r = http_response(req, 200, d, len);
		kore_mem_free(d);

		return (r);
	}

	for (i = 1; i < 4; i++) {
		snprintf(name, sizeof(name), "test%d", i);
		if (http_argument_get_string(name, &test, &len)) {
			snprintf(name, sizeof(name), "$test%d$", i);
			kore_buf_replace_string(b, name, test, len);
		} else {
			snprintf(name, sizeof(name), "$test%d$", i);
			kore_buf_replace_string(b, name, NULL, 0);
		}
	}

	http_response_header_add(req, "content-type", "text/html");
	d = kore_buf_release(b, &len);
	r = http_response(req, 200, d, len);
	kore_mem_free(d);

	return (r);
}

void
my_callback(void)
{
	if (worker != NULL)
		kore_log(LOG_NOTICE, "running on worker %d", worker->id);
	else
		kore_log(LOG_NOTICE, "running from parent");
}

int
v_example_func(char *data)
{
	kore_log(LOG_NOTICE, "v_example_func called");

	if (!strcmp(data, "test"))
		return (KORE_RESULT_OK);

	return (KORE_RESULT_ERROR);
}
