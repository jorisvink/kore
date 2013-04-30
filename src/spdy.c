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
#include "http.h"

static int		spdy_ctrl_frame_syn_stream(struct netbuf *);
static int		spdy_ctrl_frame_settings(struct netbuf *);
static int		spdy_stream_get_header(struct spdy_stream *,
			    char *, char **);

static int		spdy_zlib_inflate(u_int8_t *, size_t,
			    u_int8_t **, u_int32_t *);
static int		spdy_zlib_deflate(u_int8_t *, size_t,
			    u_int8_t **, u_int32_t *);

int
spdy_frame_recv(struct netbuf *nb)
{
	struct spdy_ctrl_frame	ctrl;
	int			(*cb)(struct netbuf *), r;
	struct connection	*c = (struct connection *)nb->owner;

	if (SPDY_CONTROL_FRAME(net_read32(nb->buf))) {
		kore_log("received control frame");

		ctrl.version = net_read16(nb->buf) & 0x7fff;
		ctrl.type = net_read16(nb->buf + 2);
		ctrl.flags = *(u_int8_t *)(nb->buf + 4);
		ctrl.length = net_read32(nb->buf + 4) & 0xffffff;

		kore_log("type is %d", ctrl.type);
		kore_log("version is %d", ctrl.version);
		kore_log("length is %d", ctrl.length);
		kore_log("flags are %d", ctrl.flags);

		switch (ctrl.type) {
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
			r = net_recv_expand(c, nb, ctrl.length, cb);
		} else {
			kore_log("no callback for type %d", ctrl.type);
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
	struct spdy_stream		*s;
	struct spdy_syn_stream		syn;
	struct spdy_ctrl_frame		ctrl;
	u_int8_t			*src;
	char				*host, *method, *path;
	struct connection		*c = (struct connection *)nb->owner;

	ctrl.version = net_read16(nb->buf) & 0x7fff;
	ctrl.type = net_read16(nb->buf + 2);
	ctrl.flags = *(u_int8_t *)(nb->buf + 4);
	ctrl.length = net_read32(nb->buf + 4) & 0xffffff;

	syn.stream_id = net_read32(nb->buf + 8);
	syn.assoc_stream_id = net_read32(nb->buf + 12);
	syn.prio = net_read16(nb->buf + 16) & 0xe000;
	syn.slot = net_read16(nb->buf + 16) & 0x7;

	/* XXX need to send protocol errors here? */
	if ((syn.stream_id % 2) == 0 || syn.stream_id == 0) {
		kore_log("client sent incorrect id for SPDY_SYN_STREAM (%d)",
		    syn.stream_id);
		return (KORE_RESULT_ERROR);
	}

	if ((s = spdy_stream_lookup(c, syn.stream_id)) != NULL) {
		kore_log("duplicate SPDY_SYN_STREAM (%d)", syn.stream_id);
		return (KORE_RESULT_ERROR);
	}

	s = (struct spdy_stream *)kore_malloc(sizeof(*s));
	s->prio = syn.prio;
	s->flags = ctrl.flags;
	s->stream_id = syn.stream_id;
	s->header_block_len = 0;
	s->header_block = NULL;

	src = (nb->buf + SPDY_FRAME_SIZE + SPDY_SYNFRAME_SIZE);
	kore_log("compressed headers are %d bytes long", ctrl.length - 10);
	if (!spdy_zlib_inflate(src, (ctrl.length - SPDY_SYNFRAME_SIZE),
	    &(s->header_block), &(s->header_block_len))) {
		free(s->header_block);
		free(s);
		return (KORE_RESULT_ERROR);
	}

	s->header_pairs = net_read32(s->header_block);
	kore_log("got %d headers", s->header_pairs);

#define GET_HEADER(n, r)				\
	if (!spdy_stream_get_header(s, n, r)) {	\
		free(s->header_block);			\
		free(s);				\
		kore_log("no such header: %s", n);	\
		return (KORE_RESULT_ERROR);		\
	}

	GET_HEADER(":path", &path);
	GET_HEADER(":method", &method);
	GET_HEADER(":host", &host);
	if (!http_new_request(c, s, host, method, path)) {
		free(s->header_block);
		free(s);
		return (KORE_RESULT_ERROR);
	}

	free(path);
	free(method);
	free(host);

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

static int
spdy_stream_get_header(struct spdy_stream *s, char *header, char **out)
{
	u_int8_t		*p;
	char			*cmp;
	u_int32_t		i, nlen, vlen;

	p = s->header_block + 4;
	for (i = 0; i < s->header_pairs; i++) {
		nlen = net_read32(p);
		vlen = net_read32(p + nlen + 4);

		cmp = (char *)(p + 4);
		if (!strncasecmp(cmp, header, nlen)) {
			kore_log("found %s header", header);

			cmp = (char *)(p + nlen + 8);
			*out = (char *)kore_malloc(vlen + 1);
			kore_strlcpy(*out, cmp, vlen + 1);
			return (KORE_RESULT_OK);
		}

		kore_log("pair name %d bytes, value %d bytes", nlen, vlen);

		p += nlen + vlen + 8;
	}

	return (KORE_RESULT_ERROR);
}

static int
spdy_zlib_inflate(u_int8_t *src, size_t len, u_int8_t **dst, u_int32_t *olen)
{
	z_stream		zlib;
	size_t			have;
	int			r, ret;
	u_char			inflate_buffer[SPDY_ZLIB_CHUNK];

	kore_log("spdy_zlib_inflate(%p, %d)", src, len);

	zlib.avail_in = 0;
	zlib.next_in = Z_NULL;
	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	if ((r = inflateInit(&zlib)) != Z_OK) {
		kore_log("inflateInit() failed: %d", r);
		return (KORE_RESULT_ERROR);
	}

	*olen = 0;
	*dst = NULL;

	ret = -1;
	zlib.avail_in = len;
	zlib.next_in = src;
	while (ret == -1) {
		zlib.avail_out = SPDY_ZLIB_CHUNK;
		zlib.next_out = inflate_buffer;

		r = inflate(&zlib, Z_SYNC_FLUSH);
		switch (r) {
		case Z_NEED_DICT:
			r = inflateSetDictionary(&zlib, SPDY_dictionary_txt,
			    SPDY_ZLIB_DICT_SIZE);
			if (r != Z_OK) {
				inflateEnd(&zlib);
				kore_log("inflateSetDictionary(): %d", r);
					return (KORE_RESULT_ERROR);
			}

			continue;
		case Z_BUF_ERROR:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			ret = KORE_RESULT_ERROR;
			kore_log("inflate(): %d", r);
			break;
		case Z_OK:
			have = SPDY_ZLIB_CHUNK - zlib.avail_out;
			*olen += have;
			*dst = (u_int8_t *)kore_realloc(*dst, *olen);
			memcpy((*dst) + (*olen - have), inflate_buffer, have);

			if (zlib.avail_in != 0 || zlib.avail_out == 0)
				break;
			/* FALLTHROUGH */
		case Z_STREAM_END:
			ret = KORE_RESULT_OK;
			break;
		}
	}

	inflateEnd(&zlib);
	return (ret);
}

static int
spdy_zlib_deflate(u_int8_t *src, size_t len, u_int8_t **dst, u_int32_t *olen)
{
	z_stream		zlib;
	size_t			have;
	int			r, ret;
	u_char			deflate_buffer[SPDY_ZLIB_CHUNK];

	kore_log("spdy_zlib_deflate(%p, %d)", src, len);

	zlib.avail_in = 0;
	zlib.next_in = Z_NULL;
	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	if ((r = deflateInit(&zlib, -1)) != Z_OK) {
		kore_log("deflateInit() failed: %d", r);
		return (KORE_RESULT_ERROR);
	}

	r = deflateSetDictionary(&zlib, SPDY_dictionary_txt,
	    SPDY_ZLIB_DICT_SIZE);
	if (r != Z_OK) {
		deflateEnd(&zlib);
		kore_log("delfateSetDictionary(): %d", r);
		return (KORE_RESULT_ERROR);
	}

	*olen = 0;
	*dst = NULL;

	ret = -1;
	zlib.avail_in = len;
	zlib.next_in = src;
	while (ret == -1) {
		zlib.avail_out = SPDY_ZLIB_CHUNK;
		zlib.next_out = deflate_buffer;

		r = deflate(&zlib, Z_SYNC_FLUSH);
		switch (r) {
		case Z_BUF_ERROR:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			ret = KORE_RESULT_ERROR;
			kore_log("deflate(): %d", r);
			break;
		case Z_OK:
			have = SPDY_ZLIB_CHUNK - zlib.avail_out;
			*olen += have;
			*dst = (u_int8_t *)kore_realloc(*dst, *olen);
			memcpy((*dst) + (*olen - have), deflate_buffer, have);

			if (zlib.avail_in == 0 && zlib.avail_out != 0)
				ret = KORE_RESULT_OK;
			break;
		}
	}

	deflateEnd(&zlib);
	return (ret);
}
