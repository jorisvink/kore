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
#include <regex.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

static int		spdy_ctrl_frame_syn_stream(struct netbuf *);
static int		spdy_ctrl_frame_settings(struct netbuf *);
static int		spdy_ctrl_frame_ping(struct netbuf *);
static int		spdy_ctrl_frame_window(struct netbuf *);
static int		spdy_data_frame_recv(struct netbuf *);
static int		spdy_frame_send_done(struct netbuf *);
static void		spdy_update_wsize(struct connection *,
			    struct spdy_stream *, u_int32_t);
static void		spdy_stream_close(struct connection *,
			    struct spdy_stream *);

static int		spdy_zlib_inflate(struct connection *, u_int8_t *,
			    size_t, u_int8_t **, u_int32_t *);
static int		spdy_zlib_deflate(struct connection *, u_int8_t *,
			    size_t, u_int8_t **, u_int32_t *);

int
spdy_frame_recv(struct netbuf *nb)
{
	struct spdy_stream	*s;
	struct spdy_ctrl_frame	ctrl;
	struct spdy_data_frame	data;
	int			(*cb)(struct netbuf *), r;
	struct connection	*c = (struct connection *)nb->owner;

	kore_debug("spdy_frame_recv(%p)", nb);

	if (SPDY_CONTROL_FRAME(net_read32(nb->buf))) {
		kore_debug("received control frame");

		ctrl.version = net_read16(nb->buf) & 0x7fff;
		ctrl.type = net_read16(nb->buf + 2);
		ctrl.flags = *(u_int8_t *)(nb->buf + 4);
		ctrl.length = net_read32(nb->buf + 4) & 0xffffff;

		kore_debug("type is %d", ctrl.type);
		kore_debug("version is %d", ctrl.version);
		kore_debug("length is %d", ctrl.length);
		kore_debug("flags are %d", ctrl.flags);

		if (ctrl.version != 3) {
			kore_debug("protocol mismatch (recv version %d)",
			    ctrl.version);
			return (KORE_RESULT_ERROR);
		}

		switch (ctrl.type) {
		case SPDY_CTRL_FRAME_SYN_STREAM:
			cb = spdy_ctrl_frame_syn_stream;
			break;
		case SPDY_CTRL_FRAME_SETTINGS:
			cb = spdy_ctrl_frame_settings;
			break;
		case SPDY_CTRL_FRAME_PING:
			cb = spdy_ctrl_frame_ping;
			break;
		case SPDY_CTRL_FRAME_WINDOW:
			cb = spdy_ctrl_frame_window;
			break;
		default:
			cb = NULL;
			break;
		}

		if (cb != NULL) {
			r = net_recv_expand(c, nb, ctrl.length, cb);
		} else {
			kore_debug("no callback for type %d", ctrl.type);
			r = KORE_RESULT_OK;
		}
	} else {
		data.stream_id = net_read32(nb->buf) & ~(1 << 31);
		if ((s = spdy_stream_lookup(c, data.stream_id)) == NULL) {
			kore_debug("recv data frame for non existing stream");
			r = KORE_RESULT_ERROR;
		} else if (s->flags & FLAG_FIN) {
			kore_debug("received data frame but FLAG_FIN was set");
			r = KORE_RESULT_ERROR;
		} else {
			data.flags = *(u_int8_t *)(nb->buf + 4);
			data.length = net_read32(nb->buf + 4) & 0xffffff;

			r = net_recv_expand(c, nb, data.length,
			    spdy_data_frame_recv);
		}
	}

	if (r == KORE_RESULT_OK) {
		net_recv_queue(c, SPDY_FRAME_SIZE,
		    0, NULL, spdy_frame_recv);
	}

	return (r);
}

void
spdy_frame_send(struct connection *c, u_int16_t type, u_int8_t flags,
    u_int32_t len, struct spdy_stream *s, u_int32_t misc)
{
	struct netbuf		*nnb;
	u_int8_t		nb[12];
	u_int32_t		length;

	kore_debug("spdy_frame_send(%p, %d, %d, %d, %p, %d)",
	    c, type, flags, len, s, misc);

	length = 0;
	memset(nb, 0, sizeof(nb));
	switch (type) {
	case SPDY_CTRL_FRAME_PING:
	case SPDY_CTRL_FRAME_SYN_REPLY:
		net_write16(&nb[0], 3);
		nb[0] |= (1 << 7);
		net_write16(&nb[2], type);

		if (type != SPDY_CTRL_FRAME_PING) {
			net_write32(&nb[4], len + 4);
			nb[4] = flags;
			net_write32(&nb[8], s->stream_id);
		} else {
			net_write32(&nb[4], len);
			nb[4] = flags;
			net_write32(&nb[8], misc);
		}

		length = 12;
		break;
	case SPDY_DATA_FRAME:
		net_write32(&nb[0], s->stream_id);
		nb[0] &= ~(1 << 7);
		net_write32(&nb[4], len);
		nb[4] = flags;
		length = 8;
		break;
	}

	if (s != NULL && type == SPDY_DATA_FRAME) {
		net_send_queue(c, nb, length, 0, &nnb, spdy_frame_send_done);
		nnb->extra = s;
	} else {
		net_send_queue(c, nb, length, 0, NULL, NULL);
	}

	if (s != NULL) {
		if ((flags & FLAG_FIN) && (s->flags & FLAG_FIN))
			s->flags |= SPDY_STREAM_WILLCLOSE;
	}
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

struct spdy_header_block *
spdy_header_block_create(int delayed_alloc)
{
	struct spdy_header_block	*hblock;

	kore_debug("spdy_header_block_create()");

	hblock = (struct spdy_header_block *)kore_malloc(sizeof(*hblock));
	if (delayed_alloc == SPDY_HBLOCK_NORMAL) {
		hblock->header_block = (u_int8_t *)kore_malloc(128);
		hblock->header_block_len = 128;
		hblock->header_offset = 4;
	} else {
		hblock->header_block = NULL;
		hblock->header_block_len = 0;
		hblock->header_offset = 0;
	}

	hblock->header_pairs = 0;

	return (hblock);
}

void
spdy_header_block_add(struct spdy_header_block *hblock, char *name, char *value)
{
	u_int8_t		*p;
	u_int32_t		nlen, vlen;

	kore_debug("spdy_header_block_add(%p, %s, %s)", hblock, name, value);

	nlen = strlen(name);
	vlen = strlen(value);
	if ((nlen + vlen + hblock->header_offset) > hblock->header_block_len) {
		hblock->header_block_len += nlen + vlen + 128;
		hblock->header_block =
		    (u_int8_t *)kore_realloc(hblock->header_block,
		    hblock->header_block_len);
	}

	p = hblock->header_block + hblock->header_offset;
	net_write32(p, nlen);
	memcpy((p + 4), (u_int8_t *)name, nlen);
	hblock->header_offset += 4 + nlen;

	p = hblock->header_block + hblock->header_offset;
	net_write32(p, vlen);
	memcpy((p + 4), (u_int8_t *)value, vlen);
	hblock->header_offset += 4 + vlen;

	hblock->header_pairs++;
}

u_int8_t *
spdy_header_block_release(struct connection *c,
    struct spdy_header_block *hblock, u_int32_t *len)
{
	u_int8_t	*deflated;

	kore_debug("spdy_header_block_release(%p, %p)", hblock, len);

	net_write32(hblock->header_block, hblock->header_pairs);
	if (!spdy_zlib_deflate(c, hblock->header_block, hblock->header_offset,
	    &deflated, len)) {
		kore_mem_free(hblock->header_block);
		kore_mem_free(hblock);
		return (NULL);
	}

	kore_mem_free(hblock->header_block);
	kore_mem_free(hblock);

	return (deflated);
}

int
spdy_stream_get_header(struct spdy_header_block *s, char *header, char **out)
{
	char			*cmp;
	u_int8_t		*p, *end;
	u_int32_t		i, nlen, vlen;

	kore_debug("spdy_stream_get_header(%p, %s) <%d>", s, header,
	    s->header_pairs);

	p = s->header_block + 4;
	end = s->header_block + s->header_block_len;

	if (p >= end) {
		kore_debug("p >= end when looking for headers");
		return (KORE_RESULT_ERROR);
	}

	for (i = 0; i < s->header_pairs; i++) {
		nlen = net_read32(p);
		if ((p + nlen + 4) > end) {
			kore_debug("nlen out of bounds on %d (%d)", i, nlen);
			return (KORE_RESULT_ERROR);
		}

		vlen = net_read32(p + nlen + 4);
		if ((p + nlen + vlen + 8) > end) {
			kore_debug("vlen out of bounds on %d (%d)", i, vlen);
			return (KORE_RESULT_ERROR);
		}

		cmp = (char *)(p + 4);
		if (!strncasecmp(cmp, header, nlen)) {
			kore_debug("found %s header", header);

			cmp = (char *)(p + nlen + 8);
			*out = (char *)kore_malloc(vlen + 1);
			kore_strlcpy(*out, cmp, vlen + 1);
			return (KORE_RESULT_OK);
		}

		kore_debug("pair name %d bytes, value %d bytes", nlen, vlen);

		p += nlen + vlen + 8;
	}

	return (KORE_RESULT_ERROR);
}

int
spdy_frame_data_done(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;
	struct spdy_stream	*s = (struct spdy_stream *)nb->extra;

	spdy_update_wsize(c, s, nb->len);
	return (KORE_RESULT_OK);
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

	kore_debug("spdy_ctrl_frame_syn_stream()");
	kore_debug("stream_id: %d", syn.stream_id);
	kore_debug("length   : %d", ctrl.length);

	/* XXX need to send protocol error. */
	if ((syn.stream_id % 2) == 0 || syn.stream_id == 0) {
		kore_debug("client sent incorrect id for SPDY_SYN_STREAM (%d)",
		    syn.stream_id);
		return (KORE_RESULT_ERROR);
	}

	/* XXX need to send protocol error. */
	if (syn.stream_id < c->client_stream_id) {
		kore_debug("client sent incorrect id SPDY_SYN_STREAM (%d < %d)",
		    syn.stream_id, c->client_stream_id);
		return (KORE_RESULT_ERROR);
	}

	if ((s = spdy_stream_lookup(c, syn.stream_id)) != NULL) {
		kore_debug("duplicate SPDY_SYN_STREAM (%d)", syn.stream_id);
		return (KORE_RESULT_ERROR);
	}

	s = (struct spdy_stream *)kore_malloc(sizeof(*s));
	s->prio = syn.prio;
	s->flags = ctrl.flags;
	s->wsize = c->wsize_initial;
	s->stream_id = syn.stream_id;
	s->hblock = spdy_header_block_create(SPDY_HBLOCK_DELAYED_ALLOC);

	src = (nb->buf + SPDY_FRAME_SIZE + SPDY_SYNFRAME_SIZE);
	kore_debug("compressed headers are %d bytes long", ctrl.length - 10);
	if (!spdy_zlib_inflate(c, src, (ctrl.length - SPDY_SYNFRAME_SIZE),
	    &(s->hblock->header_block), &(s->hblock->header_block_len))) {
		kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
		kore_mem_free(s);
		return (KORE_RESULT_ERROR);
	}

	s->hblock->header_pairs = net_read32(s->hblock->header_block);
	kore_debug("got %d headers", s->hblock->header_pairs);

	path = NULL;
	host = NULL;
	method = NULL;

#define GET_HEADER(n, r)				\
	if (!spdy_stream_get_header(s->hblock, n, r)) {	\
		kore_mem_free(s->hblock->header_block);		\
		kore_mem_free(s->hblock);			\
		kore_mem_free(s);				\
		kore_debug("no such header: %s", n);	\
		if (path != NULL)			\
			kore_mem_free(path);			\
		if (host != NULL)			\
			kore_mem_free(host);			\
		if (method != NULL)			\
			kore_mem_free(method);			\
		return (KORE_RESULT_ERROR);		\
	}

	GET_HEADER(":path", &path);
	GET_HEADER(":method", &method);
	GET_HEADER(":host", &host);

	if (!http_request_new(c, s, host, method, path,
	    (struct http_request **)&(s->httpreq))) {
		kore_mem_free(path);
		kore_mem_free(method);
		kore_mem_free(host);
		kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
		kore_mem_free(s);
		return (KORE_RESULT_ERROR);
	}

	kore_mem_free(path);
	kore_mem_free(method);
	kore_mem_free(host);

	c->client_stream_id = s->stream_id;
	TAILQ_INSERT_TAIL(&(c->spdy_streams), s, list);
	kore_debug("SPDY_SYN_STREAM: %d:%d:%d", s->stream_id,
	    s->flags, s->prio);

	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_settings(struct netbuf *nb)
{
	u_int8_t		*buf, flags;
	u_int32_t		ecount, i, id, val;
	struct connection	*c = (struct connection *)nb->owner;

	ecount = net_read32(nb->buf + SPDY_FRAME_SIZE);
	kore_debug("SPDY_SETTINGS: %d settings present", ecount);

	buf = nb->buf + SPDY_FRAME_SIZE + 4;
	for (i = 0; i < ecount; i++) {
		flags = *(u_int8_t *)buf;
		id = net_read32(buf) & 0xffffff;
		val = net_read32(buf + 4);

		switch (id) {
		case SETTINGS_INITIAL_WINDOW_SIZE:
			c->wsize_initial = val;
			break;
		default:
			kore_debug("no handling for setting %d:%d (%d)",
			    id, val, flags);
			break;
		}

		buf += 8;
	}

	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_ping(struct netbuf *nb)
{
	u_int32_t		id;
	struct connection	*c = (struct connection *)nb->owner;

	id = ntohl(*(u_int32_t *)(nb->buf + SPDY_FRAME_SIZE));
	kore_debug("SPDY_PING: %d", id);

	/* XXX todo - check if we sent the ping. */
	if ((id % 2) == 0) {
		kore_debug("received malformed client PING (%d)", id);
		return (KORE_RESULT_ERROR);
	}

	spdy_frame_send(c, SPDY_CTRL_FRAME_PING, 0, 4, NULL, id);
	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_window(struct netbuf *nb)
{
	struct spdy_stream	*s;
	u_int32_t		stream_id, window_size;
	struct connection	*c = (struct connection *)nb->owner;

	stream_id = net_read32(nb->buf + SPDY_FRAME_SIZE);
	window_size = net_read32(nb->buf + SPDY_FRAME_SIZE + 4);

	if ((s = spdy_stream_lookup(c, stream_id)) == NULL) {
		kore_debug("received WINDOW_UPDATE for nonexistant stream");
		kore_debug("stream_id: %d", stream_id);
		return (KORE_RESULT_ERROR);
	}

	if (s->flags & SPDY_STREAM_WILLCLOSE) {
		kore_debug("received WINDOW_UPDATE for FIN stream");
		return (KORE_RESULT_ERROR);
	}

	kore_debug("SPDY_WINDOW_UPDATE: %d:%d", stream_id, window_size);
	s->wsize += window_size;
	if (s->wsize > 0) {
		c->flags &= ~CONN_WRITE_BLOCK;
		c->flags |= CONN_WRITE_POSSIBLE;
		kore_connection_stop_idletimer(c);

		kore_debug("can now send again (%d wsize)", s->wsize);
		return (net_send_flush(c));
	}

	return (KORE_RESULT_OK);
}

static int
spdy_data_frame_recv(struct netbuf *nb)
{
	struct spdy_stream		*s;
	struct http_request		*req;
	struct spdy_data_frame		data;
	struct connection		*c = (struct connection *)nb->owner;

	data.stream_id = net_read32(nb->buf) & ~(1 << 31);
	data.flags = *(u_int8_t *)(nb->buf + 4);
	data.length = net_read32(nb->buf + 4) & 0xffffff;
	kore_debug("SPDY_SESSION_DATA: %d:%d:%d", data.stream_id,
	    data.flags, data.length);

	if ((s = spdy_stream_lookup(c, data.stream_id)) == NULL) {
		kore_debug("session data for incorrect stream");
		return (KORE_RESULT_OK);
	}

	req = (struct http_request *)s->httpreq;
	if (req->method != HTTP_METHOD_POST) {
		kore_debug("data frame for non post received");
		return (KORE_RESULT_ERROR);
	}

	if (req->post_data == NULL)
		req->post_data = kore_buf_create(data.length);
	kore_buf_append(req->post_data, (nb->buf + SPDY_FRAME_SIZE),
	    data.length);

	if (data.flags & FLAG_FIN) {
		s->flags |= FLAG_FIN;
		req->flags |= HTTP_REQUEST_COMPLETE;
	}

	return (KORE_RESULT_OK);
}

static void
spdy_stream_close(struct connection *c, struct spdy_stream *s)
{
	kore_debug("spdy_stream_close(%p, %p) <%d>", c, s, s->stream_id);

	TAILQ_REMOVE(&(c->spdy_streams), s, list);
	if (s->hblock != NULL) {
		if (s->hblock->header_block != NULL)
			kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
	}

	kore_mem_free(s);
}

static int
spdy_frame_send_done(struct netbuf *nb)
{
	u_int8_t		flags;
	struct connection	*c = (struct connection *)nb->owner;
	struct spdy_stream	*s = (struct spdy_stream *)nb->extra;

	flags = *(u_int8_t *)(nb->buf + 4);
	if ((flags & FLAG_FIN) && (s->flags & FLAG_FIN))
		spdy_stream_close(c, s);

	return (KORE_RESULT_OK);
}

static void
spdy_update_wsize(struct connection *c, struct spdy_stream *s, u_int32_t len)
{
	s->wsize -= len;
	kore_debug("spdy_update_wsize(): stream %d, window size %d",
	    s->stream_id, s->wsize);

	if (s->wsize <= 0) {
		kore_debug("window size <= 0 for stream %d", s->stream_id);
		c->flags &= ~CONN_WRITE_POSSIBLE;
		c->flags |= CONN_WRITE_BLOCK;
		kore_connection_start_idletimer(c);
	}
}

static int
spdy_zlib_inflate(struct connection *c, u_int8_t *src, size_t len,
    u_int8_t **dst, u_int32_t *olen)
{
	size_t			have;
	int			r, ret;
	u_char			inflate_buffer[SPDY_ZLIB_CHUNK];

	kore_debug("spdy_zlib_inflate(%p, %p, %d)", c, src, len);

	if (c->inflate_started == 0) {
		c->z_inflate.avail_in = 0;
		c->z_inflate.next_in = Z_NULL;
		c->z_inflate.zalloc = Z_NULL;
		c->z_inflate.zfree = Z_NULL;
		if ((r = inflateInit(&(c->z_inflate))) != Z_OK) {
			kore_debug("inflateInit() failed: %d", r);
			return (KORE_RESULT_ERROR);
		}

		c->inflate_started = 1;
	}

	*olen = 0;
	*dst = NULL;

	ret = -1;
	c->z_inflate.avail_in = len;
	c->z_inflate.next_in = src;
	while (ret == -1) {
		c->z_inflate.avail_out = SPDY_ZLIB_CHUNK;
		c->z_inflate.next_out = inflate_buffer;

		r = inflate(&(c->z_inflate), Z_SYNC_FLUSH);
		switch (r) {
		case Z_NEED_DICT:
			r = inflateSetDictionary(&(c->z_inflate),
			    SPDY_dictionary_txt, SPDY_ZLIB_DICT_SIZE);
			if (r != Z_OK) {
				inflateEnd(&(c->z_inflate));
				kore_debug("inflateSetDictionary(): %d", r);
					return (KORE_RESULT_ERROR);
			}

			continue;
		case Z_BUF_ERROR:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			ret = KORE_RESULT_ERROR;
			kore_debug("inflate(): %d", r);
			break;
		case Z_OK:
			have = SPDY_ZLIB_CHUNK - c->z_inflate.avail_out;
			*olen += have;
			*dst = (u_int8_t *)kore_realloc(*dst, *olen);
			memcpy((*dst) + (*olen - have), inflate_buffer, have);

			if (c->z_inflate.avail_in != 0 ||
			    c->z_inflate.avail_out == 0)
				break;
			/* FALLTHROUGH */
		case Z_STREAM_END:
			ret = KORE_RESULT_OK;
			break;
		}
	}

	return (ret);
}

static int
spdy_zlib_deflate(struct connection *c, u_int8_t *src, size_t len,
    u_int8_t **dst, u_int32_t *olen)
{
	size_t			have;
	int			r, ret;
	u_char			deflate_buffer[SPDY_ZLIB_CHUNK];

	kore_debug("spdy_zlib_deflate(%p, %p, %d)", c, src, len);

	if (c->deflate_started == 0) {
		c->z_deflate.avail_in = 0;
		c->z_deflate.next_in = Z_NULL;
		c->z_deflate.zalloc = Z_NULL;
		c->z_deflate.zfree = Z_NULL;
		if ((r = deflateInit(&(c->z_deflate), -1)) != Z_OK) {
			kore_debug("deflateInit() failed: %d", r);
			return (KORE_RESULT_ERROR);
		}

		r = deflateSetDictionary(&(c->z_deflate), SPDY_dictionary_txt,
		    SPDY_ZLIB_DICT_SIZE);
		if (r != Z_OK) {
			deflateEnd(&(c->z_deflate));
			kore_debug("delfateSetDictionary(): %d", r);
			return (KORE_RESULT_ERROR);
		}

		c->deflate_started = 1;
	}

	*olen = 0;
	*dst = NULL;

	ret = -1;
	c->z_deflate.avail_in = len;
	c->z_deflate.next_in = src;
	while (ret == -1) {
		c->z_deflate.avail_out = SPDY_ZLIB_CHUNK;
		c->z_deflate.next_out = deflate_buffer;

		r = deflate(&(c->z_deflate), Z_SYNC_FLUSH);
		switch (r) {
		case Z_BUF_ERROR:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			ret = KORE_RESULT_ERROR;
			kore_debug("deflate(): %d", r);
			break;
		case Z_OK:
			have = SPDY_ZLIB_CHUNK - c->z_deflate.avail_out;
			*olen += have;
			*dst = (u_int8_t *)kore_realloc(*dst, *olen);
			memcpy((*dst) + (*olen - have), deflate_buffer, have);

			if (c->z_deflate.avail_in == 0 &&
			    c->z_deflate.avail_out != 0)
				ret = KORE_RESULT_OK;
			break;
		}
	}

	return (ret);
}
