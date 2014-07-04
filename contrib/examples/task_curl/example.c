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
 * The page_handler() page handler is not called until the background
 * task it fired off has completed.
 *
 * You need libcurl installed for this to build (including headers)
 *
 * Compile using build.sh, afterwards start using:
 *	# kore -nc module.conf (depending on where kore is installed)
 *
 * Test using:
 *	# curl -k https://127.0.0.1:4443/?user=foobar
 *
 * If the result echo'd back matches what you specified, its all green.
 */

#include <curl/curl.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/tasks.h>

int		run_curl(struct kore_task *);
int		post_back(struct http_request *);
int		page_handler(struct http_request *);
size_t		curl_write_cb(char *, size_t, size_t, void *);

int
page_handler(struct http_request *req)
{
	u_int32_t	len;
	char		*user, result[64];

	/*
	 * Lets check if a task has been created yet, this is important
	 * as we only want to fire this off once and we will be called
	 * again once it has been created.
	 */
	if (req->task == NULL) {
		/* Grab the user argument */
		http_populate_arguments(req);
		if (!http_argument_get_string("user", &user, &len)) {
			http_response(req, 500, "ERROR\n", 6);
			return (KORE_RESULT_OK);
		}

		/*
		 * Create a new task that will execute the run_curl()
		 * function and bind it to our request.
		 *
		 * Binding a task to a request means Kore will reschedule
		 * the page handler for that request to refire after the
		 * task has completed.
		 */
		kore_task_create(&req->task, run_curl);
		kore_task_bind_request(req->task, req);

		/*
		 * Start the task and write the user we received in our
		 * GET request to its channel.
		 */
		kore_task_run(req->task);
		kore_task_channel_write(req->task, user, len);

		/*
		 * Tell Kore to retry us later.
		 */
		return (KORE_RESULT_RETRY);
	}

	/*
	 * When we come back here, our background task is finished
	 * and we can check its result.
	 */
	if (kore_task_result(req->task) != KORE_RESULT_OK) {
		kore_task_destroy(req->task);
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
	len = kore_task_channel_read(req->task, result, sizeof(result));
	if (len > sizeof(result)) {
		http_response(req, 500, NULL, 0);
	} else {
		http_response(req, 200, result, len);
	}

	/* We good, destroy the task. */
	kore_task_destroy(req->task);

	return (KORE_RESULT_OK);
}

int
post_back(struct http_request *req)
{
	u_int32_t	len;
	char		*user;

	if (req->method != HTTP_METHOD_POST) {
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	http_populate_arguments(req);
	if (!http_argument_get_string("user", &user, &len)) {
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Simply echo the supplied user argument back. */
	http_response(req, 200, user, len);

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
	int			l;
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

	l = snprintf(fields, sizeof(fields), "user=%.*s", len, user);
	if (l == -1 || (size_t)l >= sizeof(fields))
		return (KORE_RESULT_ERROR);

	if ((curl = curl_easy_init()) == NULL)
		return (KORE_RESULT_ERROR);

	b = kore_buf_create(128);

	/* Do CURL magic. */
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1:4443/post_back");

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
	kore_mem_free(data);

	return (KORE_RESULT_OK);
}

size_t
curl_write_cb(char *ptr, size_t size, size_t nmemb, void *udata)
{
	struct kore_buf		*b = udata;

	kore_buf_append(b, ptr, size * nmemb);
	return (size * nmemb);
}
