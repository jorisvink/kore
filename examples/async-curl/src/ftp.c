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

/*
 * This example is the same as the HTTP one (see src/http.c) except
 * we fetch an FTP URL.
 */

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/curl.h>

int		ftp(struct http_request *);

static int	state_setup(struct http_request *);
static int	state_result(struct http_request *);

static struct http_state states[] = {
	KORE_HTTP_STATE(state_setup),
	KORE_HTTP_STATE(state_result)
};

int
ftp(struct http_request *req)
{
	return (http_state_run(states, 2, req));
}

static int
state_setup(struct http_request *req)
{
	struct kore_curl	*client;

	client = http_state_create(req, sizeof(*client));

	if (!kore_curl_init(client,
	    "http://ftp.eu.openbsd.org/pub/OpenBSD/README", KORE_CURL_ASYNC)) {
		http_response(req, 500, NULL, 0);
		return (HTTP_STATE_COMPLETE);
	}

	kore_curl_bind_request(client, req);
	kore_curl_run(client);

	req->fsm_state = 1;
	return (HTTP_STATE_RETRY);
}

static int
state_result(struct http_request *req)
{
	size_t			len;
	const u_int8_t		*body;
	struct kore_curl	*client;

	client = http_state_get(req);

	if (!kore_curl_success(client)) {
		kore_curl_logerror(client);
		http_response(req, 500, NULL, 0);
	} else {
		kore_curl_response_as_bytes(client, &body, &len);
		http_response(req, HTTP_STATUS_OK, body, len);
	}

	kore_curl_cleanup(client);

	return (HTTP_STATE_COMPLETE);
}
