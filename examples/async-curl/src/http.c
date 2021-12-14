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
 * This example demonstrates how easy it is to perform asynchronous
 * HTTP client requests using the integrated libcurl support.
 *
 * In this example we setup 2 states for an HTTP request:
 *	1) setup
 *		We initialize the HTTP request and fire it off.
 *		This will put our HTTP request to sleep and it be woken up
 *		by Kore when a response is available or something went wrong.
 *
 *	2) result
 *		After we have woken up we have access to the result.
 */

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/curl.h>

int		http(struct http_request *);

static int	state_setup(struct http_request *);
static int	state_result(struct http_request *);

/* Our states. */
static struct http_state states[] = {
	KORE_HTTP_STATE(state_setup),
	KORE_HTTP_STATE(state_result)
};

/* Transcend into the HTTP state machine for a request. */
int
http(struct http_request *req)
{
	return (http_state_run(states, 2, req));
}

/*
 * Setup the HTTP client request using the integrated curl API and the easy
 * to use HTTP client api.
 */
static int
state_setup(struct http_request *req)
{
	struct kore_curl	*client;

	client = http_state_create(req, sizeof(*client));

	/* Initialize curl. */
	if (!kore_curl_init(client, "https://kore.io", KORE_CURL_ASYNC)) {
		http_response(req, 500, NULL, 0);
		return (HTTP_STATE_COMPLETE);
	}

	/* Setup our HTTP client request. */
	kore_curl_http_setup(client, HTTP_METHOD_GET, NULL, 0);

	/* Add some headers. */
	kore_curl_http_set_header(client, "x-source", "from-example");

	/* We could opt to override some settings ourselves if we wanted. */
	/* curl_easy_setopt(client->handle, CURLOPT_SSL_VERIFYHOST, 0); */
	/* curl_easy_setopt(client->handle, CURLOPT_SSL_VERIFYPEER, 0); */

	/*
	 * Bind the HTTP client request to our HTTP request so we get woken
	 * up once a response is available.
	 *
	 * This will put us to sleep.
	 */
	kore_curl_bind_request(client, req);

	/*
	 * Now fire off the request onto the event loop.
	 */
	kore_curl_run(client);

	/* Make sure we go onto the next state once woken up. */
	req->fsm_state = 1;

	/* Tell Kore we can't complete this immediately. */
	return (HTTP_STATE_RETRY);
}

/*
 * This state is called when a result for the HTTP request call is
 * available to us.
 */
static int
state_result(struct http_request *req)
{
	size_t			len;
	const u_int8_t		*body;
	const char		*header;
	struct kore_curl	*client;

	/* Get the state attached to the HTTP request. */
	client = http_state_get(req);

	/* Check if we were successful, if not log an error. */
	if (!kore_curl_success(client)) {
		kore_curl_logerror(client);
		http_response(req, 500, NULL, 0);
	} else {
		/*
		 * Success! We now have the body available to us.
		 */
		kore_curl_response_as_bytes(client, &body, &len);

		/* We could check the existence of a header: */
		if (kore_curl_http_get_header(client, "server", &header))
			printf("got server header: '%s'\n", header);

		/*
		 * Respond to our client with the status and body from
		 * the HTTP client request we did.
		 */
		http_response(req, client->http.status, body, len);
	}

	/* Cleanup. */
	kore_curl_cleanup(client);

	/* State is now finished. */
	return (HTTP_STATE_COMPLETE);
}
