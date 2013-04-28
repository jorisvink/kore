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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spdy.h"
#include "kore.h"
static int		spdy_ctrl_frame_syn_stream(struct netbuf *);
static int		spdy_ctrl_frame_settings(struct netbuf *);

int
spdy_frame_recv(struct netbuf *nb)
{
	struct spdy_ctrl_frame	*ctrl;
	int			(*cb)(struct netbuf *);
	struct connection	*c = (struct connection *)nb->owner;
	struct spdy_frame	*frame = (struct spdy_frame *)nb->buf;

	frame->frame_1 = ntohl(frame->frame_1);
	frame->frame_2 = ntohl(frame->frame_2);

	c->spdy_cur_frame = *frame;
	if (SPDY_CONTROL_FRAME(frame)) {
		kore_log("received control frame");

		ctrl = (struct spdy_ctrl_frame *)frame;
		kore_log("type is %d", ctrl->type);
		kore_log("version is %d", ctrl->version);
		kore_log("length is %d", ctrl->length);

		switch (ctrl->type) {
		case SPDY_CTRL_FRAME_SYN_STREAM:
			cb = spdy_ctrl_frame_syn_stream;
			break;
		case SPDY_CTRL_FRAME_SETTINGS:
			cb = spdy_ctrl_frame_settings;
			break;
		default:
			cb = NULL;
			break;
		}

		if (cb != NULL) {
			net_recv_queue(c, ctrl->length, cb);
		} else {
			kore_log("no callback for type %d", ctrl->type);
		}
	} else {
		kore_log("received data frame");
	}

	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_syn_stream(struct netbuf *nb)
{
	kore_log("-- SPDY_SYN_STREAM");
	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_settings(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;

	kore_log("-- SPDY_SETTINGS");
	net_recv_queue(c, SPDY_FRAME_SIZE, spdy_frame_recv);

	return (KORE_RESULT_OK);
}
