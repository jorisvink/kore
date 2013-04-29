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
#include <zlib.h>

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

struct spdy_stream *
spdy_stream_lookup(struct connection *c, u_int32_t id)
{
	struct spdy_stream	*s;

	TAILQ_FOREACH(s, &(c->spdy_streams), list) {
		if (s->stream_id == id)
			return (s);
	}

	return (NULL);
}

static int
spdy_ctrl_frame_syn_stream(struct netbuf *nb)
{
	u_int16_t			*b;
	struct spdy_stream		*s;
	z_stream			zlib;
	struct spdy_syn_stream		*syn;
	size_t				have;
	struct spdy_ctrl_frame		*ctrl;
	int				r, len;
	u_char				inflate_buffer[SPDY_ZLIB_CHUNK];
	struct connection		*c = (struct connection *)nb->owner;

	ctrl = (struct spdy_ctrl_frame *)nb->buf;
	syn = (struct spdy_syn_stream *)(nb->buf + SPDY_FRAME_SIZE);

	syn->stream_id = ntohl(syn->stream_id);
	syn->assoc_stream_id = ntohl(syn->assoc_stream_id);
	b = (u_int16_t *)&(syn->slot);
	*b = ntohl(*b);

	if ((syn->stream_id % 2) == 0 || syn->stream_id == 0) {
		kore_log("client sent incorrect id for SPDY_SYN_STREAM (%d)",
		    syn->stream_id);
		return (KORE_RESULT_ERROR);
	}

	if ((s = spdy_stream_lookup(c, syn->stream_id)) != NULL) {
		kore_log("duplicate SPDY_SYN_STREAM (%d)", syn->stream_id);
		return (KORE_RESULT_ERROR);
	}

	kore_log("compressed headers are %d bytes long", ctrl->length - 10);
	zlib.avail_in = 0;
	zlib.next_in = Z_NULL;
	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	if ((r = inflateInit(&zlib)) != Z_OK) {
		kore_log("inflateInit() failed: %d", r);
		return (KORE_RESULT_ERROR);
	}

	s = (struct spdy_stream *)kore_malloc(sizeof(*s));
	s->prio = syn->prio;
	s->flags = ctrl->flags;
	s->stream_id = syn->stream_id;
	s->header_block_len = ctrl->length;
	s->header_block = (u_int8_t *)kore_malloc(ctrl->length);

	have = 0;
	len = ctrl->length - 10;
	do {
		if (len > SPDY_ZLIB_CHUNK) {
			zlib.avail_in = SPDY_ZLIB_CHUNK;
			len -= SPDY_ZLIB_CHUNK;
		} else {
			zlib.avail_in = len;
			len = 0;
		}

		if (zlib.avail_in == 0)
			break;

		zlib.next_in = (u_char *)(syn + sizeof(struct spdy_syn_stream));
		do {
			zlib.avail_out = SPDY_ZLIB_CHUNK;
			zlib.next_out = inflate_buffer;

			r = inflate(&zlib, Z_SYNC_FLUSH);
			switch (r) {
			case Z_NEED_DICT:
				kore_log("I need a dict");
				break;
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				inflateEnd(&zlib);
				free(s->header_block);
				free(s);
				kore_log("inflate(): %d", r);
				return (KORE_RESULT_ERROR);
			}

			have += SPDY_ZLIB_CHUNK - zlib.avail_out;
			if (have > s->header_block_len) {
				s->header_block_len += ctrl->length;
				s->header_block =
				    (u_int8_t *)kore_realloc(s->header_block,
				    s->header_block_len);
			}

			memcpy((s->header_block + have), inflate_buffer,
			    SPDY_ZLIB_CHUNK - zlib.avail_out);
		} while (zlib.avail_out == 0);
	} while (r != Z_STREAM_END);

	inflateEnd(&zlib);
	TAILQ_INSERT_TAIL(&(c->spdy_streams), s, list);

	kore_log("SPDY_SYN_STREAM: %d:%d:%d", s->stream_id, s->flags, s->prio);
	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_settings(struct netbuf *nb)
{
	int			r;
	struct connection	*c = (struct connection *)nb->owner;

	kore_log("SPDY_SETTINGS");
	r = net_recv_queue(c, SPDY_FRAME_SIZE, spdy_frame_recv);

	return (r);
}
