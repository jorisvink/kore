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
	int			(*cb)(struct netbuf *), r;
	struct connection	*c = (struct connection *)nb->owner;
	struct spdy_frame	*frame = (struct spdy_frame *)nb->buf;

	frame->frame_1 = ntohl(frame->frame_1);
	frame->frame_2 = ntohl(frame->frame_2);

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
			r = net_recv_expand(c, nb, ctrl->length, cb);
		} else {
			kore_log("no callback for type %d", ctrl->type);
			r = KORE_RESULT_ERROR;
		}
	} else {
		r = KORE_RESULT_OK;
		kore_log("received data frame");
	}

	return (r);
}

static int
spdy_ctrl_frame_syn_stream(struct netbuf *nb)
{
	u_int16_t			*b;
	struct spdy_ctrl_frame		*ctrl;
	struct spdy_syn_stream		*syn;

	ctrl = (struct spdy_ctrl_frame *)nb->buf;
	syn = (struct spdy_syn_stream *)(nb->buf + SPDY_FRAME_SIZE);

	syn->stream_id = ntohl(syn->stream_id);
	syn->assoc_stream_id = ntohl(syn->assoc_stream_id);
	b = (u_int16_t *)&(syn->slot);
	*b = ntohl(*b);

	kore_log("stream id is %d", syn->stream_id);
	kore_log("assoc stream id is %d", syn->assoc_stream_id);
	kore_log("slot is %d", syn->slot);
	kore_log("priority is %d", syn->prio);

	kore_log("-- SPDY_SYN_STREAM");
	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_settings(struct netbuf *nb)
{
	int			r;
	struct connection	*c = (struct connection *)nb->owner;

	kore_log("-- SPDY_SETTINGS");
	r = net_recv_queue(c, SPDY_FRAME_SIZE, spdy_frame_recv);

	return (r);
}
