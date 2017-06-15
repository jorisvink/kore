/*
 * Copyright (c) 2015 Joris Vink <joris@coders.se>
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

/*
 * This example demonstrates how to use the messaging framework
 * in Kore. This framework allows you to send messages between
 * your workers with custom callbacks defined per message ID.
 */

/* Your code shouldn't use IDs < 100. */
#define MY_MESSAGE_ID		100

int	init(int);
int	page(struct http_request *);
int	page_shutdown(struct http_request *req);
void	received_message(struct kore_msg *, const void *);

/* Initialization callback. */
int
init(int state)
{
	if (state == KORE_MODULE_UNLOAD)
		return (KORE_RESULT_OK);

	/*
	 * Register our message callback when the module is initialized.
	 * kore_msg_register() fails if the message ID already exists,
	 * but in our case that is OK.
	 */
	(void)kore_msg_register(MY_MESSAGE_ID, received_message);

	return (KORE_RESULT_OK);
}

/*
 * Callback for receiving a message MY_MESSAGE_ID.
 */
void
received_message(struct kore_msg *msg, const void *data)
{
	kore_log(LOG_INFO, "got message from %u (%d bytes): %.*s", msg->src,
	    msg->length, msg->length, (const char *)data);
}

/*
 * Page request which will send a message to all other workers
 * with the ID set to MY_MESSAGE_ID and a payload of "hello".
 */
int
page(struct http_request *req)
{
	/* Send to all workers first. */
	kore_msg_send(KORE_MSG_WORKER_ALL, MY_MESSAGE_ID, "hello", 5);

	/* Now send something to worker number #2 only. */
	kore_msg_send(2, MY_MESSAGE_ID, "hello number 2", 14);

	http_response(req, 200, NULL, 0);
	return (KORE_RESULT_OK);
}

/*
 * Page request which will send a message to the parent
 * requesting process shutdown.
 */
int
page_shutdown(struct http_request *req)
{
	/* Send shutdown request to parent. */
	kore_msg_send(KORE_MSG_PARENT, KORE_MSG_SHUTDOWN, "1", 1);

	http_response(req, 200, NULL, 0);
	return (KORE_RESULT_OK);
}
