/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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
 * In this example, we use the background tasks available in Kore
 * to fire off a POST to our /post_back page handler containing
 * the user argument that was passed to us in our GET request to /.
 *
 * This illustrates how Kore its background tasks in effect work and
 * how to operate on the channel in order to pass data back and forth.
 *
 * You need libcurl installed for this to build (including headers)
 *
 * Read README.md on how to build and run this example.
 */

#include <curl/curl.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/tasks.h>

int		run_curl(struct kore_task *);
int		post_back(struct http_request *);
int		page_handler(struct http_request *);
size_t		curl_write_cb(char *, size_t, size_t, void *);

struct rstate {
	struct kore_task	task;
};

int
page_handler(struct http_request *req)
{
	u_int32_t	len;
	struct rstate	*state;
	char		*user, result[64];

	/*
	 * Lets check if a task has been created yet, this is important
	 * as we only want to fire this off once and we will be called
	 * again once it has been created.
	 *
	 * In this example, we'll store our state with our task in hdlr_extra.
	 */
	if (req->hdlr_extra == NULL) {
		/* Grab the user argument */
		http_populate_get(req);
		if (!http_argument_get_string(req, "user", &user)) {
			http_response(req, 500, "ERROR\n", 6);
			return (KORE_RESULT_OK);
		}

		/*
		 * Allocate rstate and bind it to the hdlr_extra field.
		 * Kore automatically frees this when freeing the result.
		 */
		state = kore_malloc(sizeof(*state));
		req->hdlr_extra = state;

		/*
		 * Create a new task that will execute the run_curl()
		 * function and bind it to our request.
		 *
		 * Binding a task to a request means Kore will reschedule
		 * the page handler for that request to refire after the
		 * task has completed or when it writes on the task channel.
		 */
		kore_task_create(&state->task, run_curl);
		kore_task_bind_request(&state->task, req);

		/*
		 * Start the task and write the user we received in our
		 * GET request to its channel.
		 */
		kore_task_run(&state->task);
		kore_task_channel_write(&state->task, user, strlen(user));

		/*
		 * Tell Kore to retry us later.
		 */
		return (KORE_RESULT_RETRY);
	} else {
		state = req->hdlr_extra;
	}

	/*
	 * Our page handler is scheduled to be called when either the
	 * task finishes or has written data onto the channel.
	 *
	 * In order to distinguish between the two we can inspect the
	 * state of the task.
	 */
	if (kore_task_state(&state->task) != KORE_TASK_STATE_FINISHED) {
		http_request_sleep(req);
		return (KORE_RESULT_RETRY);
	}

	/*
	 * Task is finished, check the result.
	 */
	if (kore_task_result(&state->task) != KORE_RESULT_OK) {
		kore_task_destroy(&state->task);
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/*
	 * Lets read what our task has written to the channel.
	 *
	 * kore_task_channel_read() will return the amount of bytes
	 * that it received for that read. If the returned bytes is
	 * larger then the buffer you passed this is a sign of truncation
	 * and should be treated carefully.
	 */
	len = kore_task_channel_read(&state->task, result, sizeof(result));
	if (len > sizeof(result)) {
		http_response(req, 500, NULL, 0);
	} else {
		http_response(req, 200, result, len);
	}

	/* We good, destroy the task. */
	kore_task_destroy(&state->task);

	return (KORE_RESULT_OK);
}

int
post_back(struct http_request *req)
{
	char		*user;

	if (req->method != HTTP_METHOD_POST) {
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	http_populate_post(req);
	if (!http_argument_get_string(req, "user", &user)) {
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Simply echo the supplied user argument back. */
	http_response(req, 200, user, strlen(user));

	return (KORE_RESULT_OK);
}

/*
 * This is the function that is executed by our task which is created
 * in the page_handler() callback.
 *
 * It sets up a CURL POST request to /post_back passing along the
 * user argument which it receives from its channel from page_handler().
 */
int
run_curl(struct kore_task *t)
{
	struct kore_buf		*b;
	u_int32_t		len;
	CURLcode		res;
	u_int8_t		*data;
	CURL			*curl;
	char			user[64], fields[128];

	/*
	 * Read the channel in order to obtain the user argument
	 * that was written to it by page_handler().
	 */
	len = kore_task_channel_read(t, user, sizeof(user));
	if (len > sizeof(user))
		return (KORE_RESULT_ERROR);

	if (!kore_snprintf(fields, sizeof(fields),
	    NULL, "user=%.*s", len, user))
		return (KORE_RESULT_ERROR);

	if ((curl = curl_easy_init()) == NULL)
		return (KORE_RESULT_ERROR);

	b = kore_buf_alloc(128);

	/* Do CURL magic. */
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
#if !defined(KORE_NO_TLS)
	curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1:8888/post_back");
#else
	curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8888/post_back");
#endif

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		kore_buf_free(b);
		curl_easy_cleanup(curl);
		return (KORE_RESULT_ERROR);
	}

	/*
	 * Grab the response from the CURL request and write the
	 * result back to the task channel.
	 */
	data = kore_buf_release(b, &len);
	kore_task_channel_write(t, data, len);
	kore_free(data);

	return (KORE_RESULT_OK);
}

size_t
curl_write_cb(char *ptr, size_t size, size_t nmemb, void *udata)
{
	struct kore_buf		*b = udata;

	kore_buf_append(b, ptr, size * nmemb);
	return (size * nmemb);
}
