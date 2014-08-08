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

#include <limits.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

#define SPDY_KEEP_NETBUFS		0
#define SPDY_REMOVE_NETBUFS		1

static int		spdy_ctrl_frame_syn_stream(struct netbuf *);
static int		spdy_ctrl_frame_rst_stream(struct netbuf *);
static int		spdy_ctrl_frame_settings(struct netbuf *);
static int		spdy_ctrl_frame_ping(struct netbuf *);
static int		spdy_ctrl_frame_window(struct netbuf *);
static int		spdy_ctrl_frame_goaway(struct netbuf *);
static int		spdy_data_frame_recv(struct netbuf *);

static void		spdy_block_write(struct connection *);
static void		spdy_enable_write(struct connection *);

static void		spdy_stream_close(struct connection *,
			    struct spdy_stream *, int);
static int		spdy_zlib_inflate(struct connection *, u_int8_t *,
			    size_t, u_int8_t **, u_int32_t *);
static int		spdy_zlib_deflate(struct connection *, u_int8_t *,
			    size_t, u_int8_t **, u_int32_t *);

u_int64_t		spdy_idle_time = 120000;
u_int32_t		spdy_recv_wsize = 65536;

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
		ctrl.version = net_read16(nb->buf) & 0x7fff;
		ctrl.type = net_read16(nb->buf + 2);
		ctrl.flags = *(u_int8_t *)(nb->buf + 4);
		ctrl.length = net_read32(nb->buf + 4) & 0xffffff;

		kore_debug("received control frame %d", ctrl.type);

		if ((int)ctrl.length < 0) {
			spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
			return (KORE_RESULT_OK);
		}

		if (ctrl.version != 3) {
			kore_debug("protocol mismatch (recv version %u)",
			    ctrl.version);

			spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
			return (KORE_RESULT_OK);
		}

		switch (ctrl.type) {
		case SPDY_CTRL_FRAME_SYN_STREAM:
			cb = spdy_ctrl_frame_syn_stream;
			break;
		case SPDY_CTRL_FRAME_RST_STREAM:
			cb = spdy_ctrl_frame_rst_stream;
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
		case SPDY_CTRL_FRAME_GOAWAY:
			cb = spdy_ctrl_frame_goaway;
			break;
		default:
			cb = NULL;
			break;
		}

		if (cb != NULL) {
			r = net_recv_expand(c, nb, ctrl.length, cb);
		} else {
			kore_debug("no callback for type %u", ctrl.type);
			r = KORE_RESULT_OK;
		}
	} else {
		data.stream_id = net_read32(nb->buf) & ~(1 << 31);
		if ((s = spdy_stream_lookup(c, data.stream_id)) == NULL) {
			if (!(c->flags & SPDY_CONN_GOAWAY)) {
				kore_debug("recv dataframe for bad stream: %u",
				    data.stream_id);
				r = KORE_RESULT_ERROR;
			} else {
				r = KORE_RESULT_OK;
			}
		} else if (s->flags & FLAG_FIN) {
			kore_debug("received data frame but FLAG_FIN was set");
			r = KORE_RESULT_ERROR;
		} else {
			data.flags = *(u_int8_t *)(nb->buf + 4);
			data.length = net_read32(nb->buf + 4) & 0xffffff;
			if ((int)data.length < 0) {
				r = KORE_RESULT_ERROR;
			} else {
				r = net_recv_expand(c, nb, data.length,
				    spdy_data_frame_recv);
			}
		}
	}

	if (r == KORE_RESULT_OK) {
		net_recv_queue(c, SPDY_FRAME_SIZE, 0, NULL, spdy_frame_recv);
	} else {
		r = KORE_RESULT_OK;
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
	}

	return (r);
}

int
spdy_dataframe_begin(struct connection *c)
{
	struct spdy_stream	*s = c->snb->stream;

	if (s->frame_size != 0 || s->send_size == 0) {
		fatal("spdy_dataframe_begin(): s:%u fz:%d - sz:%d",
		    s->stream_id, s->frame_size, s->send_size);
	}

	if ((int)s->send_wsize <= 0 || (int)c->spdy_send_wsize <= 0) {
		kore_debug("no space for new dataframe right now");
		spdy_block_write(c);
		return (KORE_RESULT_ERROR);
	}

	s->frame_size = MIN(NETBUF_SEND_PAYLOAD_MAX, s->send_size);

	kore_debug("spdy_dataframe_begin(): %u: fz:%d wz:%d cwz:%d",
	    s->stream_id, s->frame_size, s->send_size, c->spdy_send_wsize);

	s->flags &= ~SPDY_DATAFRAME_PRELUDE;
	spdy_frame_send(c, SPDY_DATA_FRAME, 0, s->frame_size, s, 0);

	return (KORE_RESULT_OK);
}

void
spdy_frame_send(struct connection *c, u_int16_t type, u_int8_t flags,
    u_int32_t len, struct spdy_stream *s, u_int32_t misc)
{
	u_int8_t		nb[16];
	u_int32_t		length;

	kore_debug("spdy_frame_send(%p, %u, %u, %u, %p, %u)",
	    c, type, flags, len, s, misc);

	switch (type) {
	case SPDY_CTRL_FRAME_SYN_REPLY:
	case SPDY_CTRL_FRAME_WINDOW:
	case SPDY_DATA_FRAME:
		if (s == NULL)
			fatal("spdy_frame_send(): stream is NULL for %d", type);
		break;
	}

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
	case SPDY_CTRL_FRAME_GOAWAY:
		net_write16(&nb[0], 3);
		nb[0] |= (1 << 7);
		net_write16(&nb[2], type);
		net_write32(&nb[4], len);
		nb[4] = flags;
		length = 8;
		break;
	case SPDY_CTRL_FRAME_WINDOW:
		net_write16(&nb[0], 3);
		nb[0] |= (1 << 7);
		net_write16(&nb[2], type);
		net_write32(&nb[4], len);
		nb[4] = flags;
		net_write32(&nb[8], s->stream_id);
		net_write32(&nb[12], misc);
		length = 16;
		break;
	case SPDY_DATA_FRAME:
		net_write32(&nb[0], s->stream_id);
		nb[0] &= ~(1 << 7);
		net_write32(&nb[4], len);
		nb[4] = flags;
		length = 8;
		break;
	}

	if (type == SPDY_DATA_FRAME && !(flags & FLAG_FIN)) {
		net_send_queue(c, nb, length, NULL, NETBUF_BEFORE_CHAIN);
	} else {
		net_send_queue(c, nb, length, NULL, NETBUF_LAST_CHAIN);
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

	hblock = kore_malloc(sizeof(*hblock));
	if (delayed_alloc == SPDY_HBLOCK_NORMAL) {
		hblock->header_block = kore_malloc(128);
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
	u_int32_t		nlen, vlen, tlen;

	kore_debug("spdy_header_block_add(%p, %s, %s)", hblock, name, value);

	nlen = strlen(name);
	vlen = strlen(value);

	tlen = nlen + 4 + vlen + 4;
	if ((tlen + hblock->header_offset) > hblock->header_block_len) {
		hblock->header_block_len += nlen + vlen + 128;
		hblock->header_block = kore_realloc(hblock->header_block,
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
spdy_stream_get_header(struct spdy_header_block *s,
    const char *header, char **out)
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
		if ((int)nlen < 0 || (p + nlen + 4) > end) {
			kore_debug("nlen out of bounds on %u (%u)", i, nlen);
			return (KORE_RESULT_ERROR);
		}

		vlen = net_read32(p + nlen + 4);
		if ((int)vlen < 0 || (p + nlen + vlen + 8) > end) {
			kore_debug("vlen out of bounds on %u (%u)", i, vlen);
			return (KORE_RESULT_ERROR);
		}

		cmp = (char *)(p + 4);
		if (!strncasecmp(cmp, header, nlen)) {
			cmp = (char *)(p + nlen + 8);
			*out = kore_malloc(vlen + 1);
			kore_strlcpy(*out, cmp, vlen + 1);
			return (KORE_RESULT_OK);
		}

		p += nlen + vlen + 8;
	}

	return (KORE_RESULT_ERROR);
}

void
spdy_session_teardown(struct connection *c, u_int8_t err)
{
	u_int8_t	d[8];

	kore_debug("spdy_session_teardown(%p, %u)", c, err);

	net_write32((u_int8_t *)&d[0], c->client_stream_id);
	net_write32((u_int8_t *)&d[4], err);

	spdy_frame_send(c, SPDY_CTRL_FRAME_GOAWAY, 0, 8, NULL, 0);
	net_send_queue(c, d, sizeof(d), NULL, NETBUF_LAST_CHAIN);

	c->flags &= ~CONN_READ_POSSIBLE;
	c->flags |= CONN_READ_BLOCK;

	net_send_flush(c);
	kore_connection_disconnect(c);
}

void
spdy_update_wsize(struct connection *c, struct spdy_stream *s, u_int32_t len)
{
	s->send_size -= len;
	s->frame_size -= len;
	s->send_wsize -= len;
	c->spdy_send_wsize -= len;

	kore_debug("spdy_update_wsize(): s:%u fz:%d sz:%d wz:%d cwz:%d",
	    s->stream_id, s->frame_size, s->send_size,
	    s->send_wsize, c->spdy_send_wsize);

	if (s->frame_size == 0 && s->send_size > 0) {
		kore_debug("spdy_update_wsize(): starting new data frame");
		s->flags |= SPDY_DATAFRAME_PRELUDE;
	}

	if (s->send_size == 0) {
		if (!(s->flags & SPDY_KORE_FIN)) {
			s->flags |= SPDY_KORE_FIN;
			kore_debug("sending final frame %u", s->stream_id);
			spdy_frame_send(c, SPDY_DATA_FRAME, FLAG_FIN, 0, s, 0);
			return;
		}

		if (s->flags & (SPDY_KORE_FIN | FLAG_FIN)) {
			spdy_stream_close(c, s, SPDY_KEEP_NETBUFS);
			return;
		}

		kore_debug("%u remains half open\n", s->stream_id);
	}

	if ((int)s->send_wsize <= 0) {
		kore_debug("flow control kicked in for STREAM %p:%p", s, c);
		s->flags |= SPDY_STREAM_BLOCKING;
	}

	if ((int)c->spdy_send_wsize <= 0) {
		kore_debug("flow control kicked in for CONNECTION %p", c);
		spdy_block_write(c);
	}
}

static int
spdy_ctrl_frame_syn_stream(struct netbuf *nb)
{
	struct spdy_stream		*s;
	struct spdy_syn_stream		syn;
	struct spdy_ctrl_frame		ctrl;
	u_int8_t			*src;
	char				*host, *method, *path, *version;
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
	kore_debug("stream_id: %u", syn.stream_id);
	kore_debug("length   : %u", ctrl.length);

	if (c->spdy_send_wsize > 0 && (c->flags & CONN_WRITE_BLOCK))
		spdy_enable_write(c);

	if ((int)ctrl.length < 0) {
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	if ((syn.stream_id % 2) == 0 || syn.stream_id == 0) {
		kore_debug("client sent incorrect id for SPDY_SYN_STREAM (%u)",
		    syn.stream_id);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	if (syn.stream_id < c->client_stream_id) {
		kore_debug("client sent incorrect id SPDY_SYN_STREAM (%u < %u)",
		    syn.stream_id, c->client_stream_id);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	if ((s = spdy_stream_lookup(c, syn.stream_id)) != NULL) {
		kore_debug("duplicate SPDY_SYN_STREAM (%u)", syn.stream_id);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	s = kore_malloc(sizeof(*s));
	s->send_size = 0;
	s->frame_size = 0;
	s->httpreq = NULL;
	s->prio = syn.prio;
	s->flags = ctrl.flags;
	s->recv_wsize = spdy_recv_wsize;
	s->send_wsize = c->wsize_initial;
	s->stream_id = syn.stream_id;
	s->hblock = spdy_header_block_create(SPDY_HBLOCK_DELAYED_ALLOC);

	src = (nb->buf + SPDY_FRAME_SIZE + SPDY_SYNFRAME_SIZE);
	kore_debug("compressed headers are %u bytes long", ctrl.length - 10);
	if (!spdy_zlib_inflate(c, src, (ctrl.length - SPDY_SYNFRAME_SIZE),
	    &(s->hblock->header_block), &(s->hblock->header_block_len))) {
		kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
		kore_mem_free(s);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_INTERNAL);
		return (KORE_RESULT_OK);
	}

	s->hblock->header_pairs = net_read32(s->hblock->header_block);
	if ((int)s->hblock->header_pairs < 0) {
		kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
		kore_mem_free(s);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	kore_debug("got %u headers", s->hblock->header_pairs);

	path = NULL;
	host = NULL;
	method = NULL;
	version = NULL;

#define GET_HEADER(n, r)					\
	if (!spdy_stream_get_header(s->hblock, n, r)) {		\
		kore_mem_free(s->hblock->header_block);		\
		kore_mem_free(s->hblock);			\
		kore_mem_free(s);				\
		kore_debug("no such header: %s", n);		\
		if (path != NULL)				\
			kore_mem_free(path);			\
		if (host != NULL)				\
			kore_mem_free(host);			\
		if (method != NULL)				\
			kore_mem_free(method);			\
		if (version != NULL)				\
			kore_mem_free(version);			\
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);	\
		return (KORE_RESULT_OK);			\
	}

	GET_HEADER(":path", &path);
	GET_HEADER(":method", &method);
	GET_HEADER(":host", &host);
	GET_HEADER(":version", &version);

	c->client_stream_id = s->stream_id;
	TAILQ_INSERT_TAIL(&(c->spdy_streams), s, list);

	/*
	 * We don't care so much for what http_request_new() tells us here,
	 * we just have to clean up after passing our stuff to it.
	 *
	 * In case of early errors (414, 500, ...) a net_send_flush() will
	 * clear out this stream properly via spdy_stream_close().
	 */
	(void)http_request_new(c, s, host, method, path, version,
	    (struct http_request **)&(s->httpreq));

	kore_mem_free(path);
	kore_mem_free(method);
	kore_mem_free(host);
	kore_mem_free(version);

	kore_debug("SPDY_SYN_STREAM: %u:%u:%u", s->stream_id,
	    s->flags, s->prio);

	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_rst_stream(struct netbuf *nb)
{
	struct spdy_stream	*s;
	u_int32_t		stream_id;
	struct connection	*c = (struct connection *)nb->owner;

	stream_id = net_read32(nb->buf + SPDY_FRAME_SIZE);
	if ((stream_id % 2) == 0) {
		kore_debug("received RST for non-client stream %u", stream_id);
		return (KORE_RESULT_ERROR);
	}

	if ((s = spdy_stream_lookup(c, stream_id)) == NULL) {
		kore_debug("received RST for unknown stream %u", stream_id);
		return (KORE_RESULT_ERROR);
	}

	spdy_stream_close(c, s, SPDY_REMOVE_NETBUFS);

	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_settings(struct netbuf *nb)
{
	struct spdy_stream	*s;
	u_int8_t		*buf;
	u_int32_t		ecount, i, id, val, length, diff;
	struct connection	*c = (struct connection *)nb->owner;

	ecount = net_read32(nb->buf + SPDY_FRAME_SIZE);
	length = net_read32(nb->buf + 4) & 0xffffff;
	if ((int)ecount < 0 || (int)length < 0) {
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	kore_debug("SPDY_SETTINGS: %u settings present", ecount);

	if (length != ((ecount * 8) + 4)) {
		kore_debug("ecount is not correct (%u != %u)", length,
		    (ecount * 8) + 4);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	buf = nb->buf + SPDY_FRAME_SIZE + 4;
	for (i = 0; i < ecount; i++) {
		id = net_read32(buf) & 0xffffff;
		val = net_read32(buf + 4);

		if ((int)val < 0) {
			buf += 8;
			continue;
		}

		switch (id) {
		case SETTINGS_INITIAL_WINDOW_SIZE:
			diff = val - c->wsize_initial;
			c->wsize_initial = val;
			TAILQ_FOREACH(s, &(c->spdy_streams), list)
				s->send_wsize += diff;
			kore_debug("updated wsize with %d", diff);
			break;
		default:
			kore_debug("no handling for setting %u:%u", id, val);
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
	kore_debug("SPDY_PING: %u", id);

	/* XXX todo - check if we sent the ping. */
	if ((id % 2) == 0) {
		kore_debug("received malformed client PING (%u)", id);
		spdy_session_teardown(c, SPDY_SESSION_ERROR_PROTOCOL);
		return (KORE_RESULT_OK);
	}

	spdy_frame_send(c, SPDY_CTRL_FRAME_PING, 0, 4, NULL, id);
	return (KORE_RESULT_OK);
}

static int
spdy_ctrl_frame_window(struct netbuf *nb)
{
	int			r;
	struct spdy_stream	*s;
	u_int32_t		stream_id, window_size;
	struct connection	*c = (struct connection *)nb->owner;

	stream_id = net_read32(nb->buf + SPDY_FRAME_SIZE);
	window_size = net_read32(nb->buf + SPDY_FRAME_SIZE + 4);

	r = KORE_RESULT_OK;
	if ((s = spdy_stream_lookup(c, stream_id)) != NULL) {
		s->send_wsize += window_size;
		if (c->flags & CONN_WRITE_BLOCK && s->send_wsize > 0) {
			s->flags &= ~SPDY_STREAM_BLOCKING;
			kore_debug("stream %u no longer blocket", s->stream_id);
		}
	} else {
		c->spdy_send_wsize += window_size;
		if (c->flags & CONN_WRITE_BLOCK && c->spdy_send_wsize > 0) {
			spdy_enable_write(c);
			r = net_send_flush(c);
		}
	}

	kore_debug("window_update: %u for %u", window_size, stream_id);
	kore_debug("c->spdy_send_wsize = %u", c->spdy_send_wsize);

	return (r);
}

static int
spdy_ctrl_frame_goaway(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;

	kore_debug("spdy_ctrl_frame_goaway(%p)", c);

	c->flags |= SPDY_CONN_GOAWAY;
	kore_connection_disconnect(c);

	return (KORE_RESULT_OK);
}

static int
spdy_data_frame_recv(struct netbuf *nb)
{
	struct spdy_stream		*s;
	int				err;
	struct http_request		*req;
	struct spdy_data_frame		data;
	char				*content;
	struct connection		*c = (struct connection *)nb->owner;

	data.stream_id = net_read32(nb->buf) & ~(1 << 31);
	data.flags = *(u_int8_t *)(nb->buf + 4);
	data.length = net_read32(nb->buf + 4) & 0xffffff;
	kore_debug("SPDY_SESSION_DATA: %u:%u:%u", data.stream_id,
	    data.flags, data.length);

	if ((int)data.length < 0)
		return (KORE_RESULT_ERROR);

	if ((s = spdy_stream_lookup(c, data.stream_id)) == NULL) {
		kore_debug("session data for non-existant stream");
		/* stream error */
		return (KORE_RESULT_ERROR);
	}

	req = (struct http_request *)s->httpreq;
	if (req == NULL || req->method != HTTP_METHOD_POST) {
		kore_debug("data frame for non post received");
		/* stream error */
		return (KORE_RESULT_ERROR);
	}

	if (req->post_data == NULL) {
		if (!spdy_stream_get_header(s->hblock,
		    "content-length", &content)) {
			kore_debug("no content-length found for post");
			return (KORE_RESULT_ERROR);
		}

		s->post_size = kore_strtonum(content, 10, 0, LLONG_MAX, &err);
		if (err == KORE_RESULT_ERROR) {
			kore_debug("bad content-length: %s", content);
			kore_mem_free(content);
			return (KORE_RESULT_ERROR);
		}

		kore_mem_free(content);

		if (s->post_size == 0) {
			req->flags |= HTTP_REQUEST_COMPLETE;
			return (KORE_RESULT_OK);
		}

		if (s->post_size > http_postbody_max) {
			kore_log(LOG_NOTICE, "POST data too large (%ld > %ld)",
			    s->post_size, http_postbody_max);
			return (KORE_RESULT_ERROR);
		}

		req->post_data = kore_buf_create(s->post_size);
	}

	if ((req->post_data->offset + data.length) > s->post_size) {
		kore_debug("POST would grow too large");
		return (KORE_RESULT_ERROR);
	}

	kore_buf_append(req->post_data, (nb->buf + SPDY_FRAME_SIZE),
	    data.length);

	if (data.flags & FLAG_FIN) {
		if (req->post_data->offset != s->post_size) {
			kore_debug("FLAG_FIN before all POST data received");
			return (KORE_RESULT_ERROR);
		}

		s->post_size = 0;
		s->flags |= FLAG_FIN;
		req->flags |= HTTP_REQUEST_COMPLETE;
	}

	s->recv_wsize -= data.length;
	if (s->recv_wsize < (spdy_recv_wsize / 2)) {
		spdy_frame_send(c, SPDY_CTRL_FRAME_WINDOW,
		    0, 8, s, spdy_recv_wsize - s->recv_wsize);

		s->recv_wsize += (spdy_recv_wsize - s->recv_wsize);
	}

	return (KORE_RESULT_OK);
}

static void
spdy_stream_close(struct connection *c, struct spdy_stream *s, int rb)
{
	struct http_request		*req;
	struct netbuf			*nb, *nt;

	kore_debug("spdy_stream_close(%p, %p) <%d>", c, s, s->stream_id);

	if (rb) {
		for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = nt) {
			nt = TAILQ_NEXT(nb, list);
			if (nb->stream == s) {
				kore_debug("spdy_stream_close: killing %p", nb);
				net_remove_netbuf(&(c->send_queue), nb);
			}
		}
	}

	TAILQ_REMOVE(&(c->spdy_streams), s, list);
	if (s->hblock != NULL) {
		if (s->hblock->header_block != NULL)
			kore_mem_free(s->hblock->header_block);
		kore_mem_free(s->hblock);
	}

	if (s->httpreq != NULL) {
		req = s->httpreq;
		req->stream = NULL;
		req->flags |= HTTP_REQUEST_DELETE;
	}

	kore_mem_free(s);
}

static void
spdy_block_write(struct connection *c)
{
	kore_debug("spdy_block_write(%p)", c);

	c->flags |= CONN_WRITE_BLOCK;
	c->flags &= ~CONN_WRITE_POSSIBLE;
}

static void
spdy_enable_write(struct connection *c)
{
	kore_debug("spdy_enable_write(%p)", c);

	c->flags &= ~CONN_WRITE_BLOCK;
	c->flags |= CONN_WRITE_POSSIBLE;
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
			*dst = kore_realloc(*dst, *olen);
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
			kore_debug("deflateSetDictionary(): %d", r);
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
			*dst = kore_realloc(*dst, *olen);
			memcpy((*dst) + (*olen - have), deflate_buffer, have);

			if (c->z_deflate.avail_in == 0 &&
			    c->z_deflate.avail_out != 0)
				ret = KORE_RESULT_OK;
			break;
		}
	}

	return (ret);
}
