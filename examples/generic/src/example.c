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

#include <kore/kore.h>
#include <kore/http.h>

#include <openssl/sha.h>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "assets.h"

int		example_load(int);

int		serve_b64test(struct http_request *);
int		serve_file_upload(struct http_request *);
int		serve_validator(struct http_request *);
int		serve_params_test(struct http_request *);
int		serve_private(struct http_request *);
int		serve_private_test(struct http_request *);

int		v_example_func(struct http_request *, char *);
int		v_session_validate(struct http_request *, char *);
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
example_load(int state)
{
	switch (state) {
	case KORE_MODULE_LOAD:
		kore_log(LOG_NOTICE, "module loading");

		/* Set server version */
		http_server_version("Server/0.1");
		break;
	case KORE_MODULE_UNLOAD:
		kore_log(LOG_NOTICE, "module unloading");
		break;
	default:
		kore_log(LOG_NOTICE, "state %d unknown!", state);
		break;
	}

	return (KORE_RESULT_OK);
}

int
serve_b64test(struct http_request *req)
{
	int			i;
	size_t			len;
	struct kore_buf		*res;
	u_int8_t		*data;

	res = kore_buf_alloc(1024);
	for (i = 0; b64tests[i] != NULL; i++)
		test_base64((u_int8_t *)b64tests[i], strlen(b64tests[i]), res);

	data = kore_buf_release(res, &len);

	http_response_header(req, "content-type", "text/plain");
	http_response(req, 200, data, len);
	kore_free(data);

	return (KORE_RESULT_OK);
}

int
serve_file_upload(struct http_request *req)
{
	u_int8_t		*d;
	struct kore_buf		*b;
	struct http_file	*f;
	size_t			len;
	char			*name, buf[BUFSIZ];

	b = kore_buf_alloc(asset_len_upload_html);
	kore_buf_append(b, asset_upload_html, asset_len_upload_html);

	if (req->method == HTTP_METHOD_POST) {
		if (req->http_body_fd != -1)
			kore_log(LOG_NOTICE, "file is on disk");

		http_populate_multipart_form(req);
		if (http_argument_get_string(req, "firstname", &name)) {
			kore_buf_replace_string(b, "$firstname$",
			    name, strlen(name));
		} else {
			kore_buf_replace_string(b, "$firstname$", NULL, 0);
		}

		if ((f = http_file_lookup(req, "file")) != NULL) {
			(void)snprintf(buf, sizeof(buf),
			    "%s is %ld bytes", f->filename, f->length);
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

	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, d, len);
	kore_free(d);

	return (KORE_RESULT_OK);
}

void
test_base64(u_int8_t *src, u_int32_t slen, struct kore_buf *res)
{
	char		*in;
	size_t		len;
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
			kore_free(out);
		}

		kore_free(in);
	}

	kore_buf_appendf(res, "\n");
}

int
serve_validator(struct http_request *req)
{
	if (kore_validator_run(NULL, "v_example", "test"))
		kore_log(LOG_NOTICE, "v_example ok (expected)");
	else
		kore_log(LOG_NOTICE, "v_example failed");

	if (kore_validator_run(NULL, "v_regex", "/test/123"))
		kore_log(LOG_NOTICE, "regex #1 ok");
	else
		kore_log(LOG_NOTICE, "regex #1 failed (expected)");

	if (kore_validator_run(NULL, "v_regex", "/test/joris"))
		kore_log(LOG_NOTICE, "regex #2 ok (expected)");
	else
		kore_log(LOG_NOTICE, "regex #2 failed");

	http_response(req, 200, "OK", 2);

	return (KORE_RESULT_OK);
}

int
serve_params_test(struct http_request *req)
{
	struct kore_buf		*b;
	u_int8_t		*d;
	size_t			len;
	int			r, i;
	char			*test, name[10];

	if (req->method == HTTP_METHOD_GET)
		http_populate_get(req);
	else if (req->method == HTTP_METHOD_POST)
		http_populate_post(req);

	b = kore_buf_alloc(asset_len_params_html);
	kore_buf_append(b, asset_params_html, asset_len_params_html);

	/*
	 * The GET parameters will be filtered out on POST.
	 */
	if (http_argument_get_string(req, "arg1", &test)) {
		kore_buf_replace_string(b, "$arg1$", test, strlen(test));
	} else {
		kore_buf_replace_string(b, "$arg1$", NULL, 0);
	}

	if (http_argument_get_string(req, "arg2", &test)) {
		kore_buf_replace_string(b, "$arg2$", test, strlen(test));
	} else {
		kore_buf_replace_string(b, "$arg2$", NULL, 0);
	}

	if (req->method == HTTP_METHOD_GET) {
		kore_buf_replace_string(b, "$test1$", NULL, 0);
		kore_buf_replace_string(b, "$test2$", NULL, 0);
		kore_buf_replace_string(b, "$test3$", NULL, 0);

		if (http_argument_get_uint16(req, "id", &r))
			kore_log(LOG_NOTICE, "id: %d", r);
		else
			kore_log(LOG_NOTICE, "No id set");

		http_response_header(req, "content-type", "text/html");
		d = kore_buf_release(b, &len);
		http_response(req, 200, d, len);
		kore_free(d);

		return (KORE_RESULT_OK);
	}

	for (i = 1; i < 4; i++) {
		(void)snprintf(name, sizeof(name), "test%d", i);
		if (http_argument_get_string(req, name, &test)) {
			(void)snprintf(name, sizeof(name), "$test%d$", i);
			kore_buf_replace_string(b, name, test, strlen(test));
		} else {
			(void)snprintf(name, sizeof(name), "$test%d$", i);
			kore_buf_replace_string(b, name, NULL, 0);
		}
	}

	http_response_header(req, "content-type", "text/html");
	d = kore_buf_release(b, &len);
	http_response(req, 200, d, len);
	kore_free(d);

	return (KORE_RESULT_OK);
}

int
serve_private(struct http_request *req)
{
	http_response_header(req, "content-type", "text/html");
	http_response_header(req, "set-cookie", "session_id=test123");
	http_response(req, 200, asset_private_html, asset_len_private_html);

	return (KORE_RESULT_OK);
}

int
v_example_func(struct http_request *req, char *data)
{
	kore_log(LOG_NOTICE, "v_example_func called");

	if (!strcmp(data, "test"))
		return (KORE_RESULT_OK);

	return (KORE_RESULT_ERROR);
}

int
v_session_validate(struct http_request *req, char *data)
{
	kore_log(LOG_NOTICE, "v_session_validate: %s", data);

	if (!strcmp(data, "test123"))
		return (KORE_RESULT_OK);

	return (KORE_RESULT_ERROR);
}
