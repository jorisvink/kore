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

/*
 * This example demos Kore its task and websocket capabilities.
 *
 * It will spawn a task which connects to a named pipe and writes
 * responses to all connected websocket clients.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/tasks.h>
#include <kore/hooks.h>

#include <fcntl.h>
#include <unistd.h>

#include "assets.h"

int		init(int);
int		page(struct http_request *);
int		page_ws_connect(struct http_request *);

void		websocket_connect(struct connection *);
void		websocket_disconnect(struct connection *);
void		websocket_message(struct connection *,
		    u_int8_t, void *, size_t);

int		pipe_reader(struct kore_task *);
void		pipe_data_available(struct kore_task *);

/* Our pipe reader. */
struct kore_task	pipe_task;

void
kore_worker_configure(void)
{
	/* Only do this on a dedicated worker. */
	if (worker->id != 1)
		return;

	/* Create our task. */
	kore_task_create(&pipe_task, pipe_reader);

	/* Bind a callback whenever data is available from task. */
	kore_task_bind_callback(&pipe_task, pipe_data_available);

	/* Start the task. */
	kore_task_run(&pipe_task);
}

/* Called whenever we get a new websocket connection. */
void
websocket_connect(struct connection *c)
{
	kore_log(LOG_NOTICE, "%p: connected", c);
}

/* Called whenever we receive a websocket message from a client. */
void
websocket_message(struct connection *c, u_int8_t op, void *data, size_t len)
{
	/* Not doing anything with this. */
}

/* Called whenever a websocket goes away. */
void
websocket_disconnect(struct connection *c)
{
	kore_log(LOG_NOTICE, "%p: disconnecting", c);
}

/* The / page. */
int
page(struct http_request *req)
{
	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_frontend_html, asset_len_frontend_html);

	return (KORE_RESULT_OK);
}

/* The /connect page. */
int
page_ws_connect(struct http_request *req)
{
	kore_websocket_handshake(req, "websocket_connect",
	    "websocket_message", "websocket_disconnect");
	return (KORE_RESULT_OK);
}

/*
 * The pipe reader task. This task simply waits for a writer end
 * on a named pipe and reads from it. The bytes read are written
 * on the task channel because the task does not own any connection
 * data structures and shouldn't reference them directly.
 */
int
pipe_reader(struct kore_task *t)
{
	int		fd;
	ssize_t		ret;
	u_int8_t	buf[BUFSIZ];

	fd = -1;

	kore_log(LOG_INFO, "pipe_reader starting");

	/* Just run forever. */
	for (;;) {
		/* Attempt to open the pipe if needed. */
		if (fd == -1) {
			kore_log(LOG_NOTICE, "waiting for writer");

			if ((fd = open("/tmp/pipe", O_RDONLY)) == -1) {
				kore_log(LOG_NOTICE, "failed to open pipe");
				sleep(1);
				continue;
			}

			kore_log(LOG_NOTICE, "writer connected");
		}

		/* Got a writer on the other end so start reading. */
		ret = read(fd, buf, sizeof(buf));
		if (ret == -1) {
			kore_log(LOG_ERR, "read error on pipe");
			(void)close(fd);
			fd = -1;
			continue;
		}

		if (ret == 0) {
			kore_log(LOG_NOTICE, "writer disconnected");
			(void)close(fd);
			fd = -1;
			continue;
		}

		kore_log(LOG_NOTICE, "got %ld bytes from pipe", ret);

		/*
		 * Write data on the task channel so our main event loop
		 * will call the registered callback.
		 */
		kore_task_channel_write(t, buf, ret);
	}

	return (KORE_RESULT_OK);
}

/* Called on the main event loop whenever a task event fires. */
void
pipe_data_available(struct kore_task *t)
{
	size_t		len;
	u_int8_t	buf[BUFSIZ];

	/* Deal with the task finishing, we could restart it from here. */
	if (kore_task_finished(t)) {
		kore_log(LOG_WARNING, "task finished");
		return;
	}

	/* Read data from the task channel. */
	len = kore_task_channel_read(t, buf, sizeof(buf));
	if (len > sizeof(buf))
		kore_log(LOG_WARNING, "truncated data from task");

	/* Broadcast it to all connected websocket clients. */
	kore_log(LOG_NOTICE, "got %zu bytes from task", len);

	kore_websocket_broadcast(NULL, WEBSOCKET_OP_TEXT,
	    buf, len, WEBSOCKET_BROADCAST_GLOBAL);
}
