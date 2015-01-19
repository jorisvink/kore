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

#include <sys/param.h>

#include <limits.h>

#include "kore.h"
#include "http.h"

#define WEBSOCKET_FRAME_HDR		2
#define WEBSOCKET_MASK_LEN		4
#define WEBSOCKET_FRAME_MAXLEN		16384
#define WEBSOCKET_PAYLOAD_SINGLE	125
#define WEBSOCKET_PAYLOAD_EXTEND_1	126
#define WEBSOCKET_PAYLOAD_EXTEND_2	127
#define WEBSOCKET_OPCODE_MASK		0x0f
#define WEBSOCKET_FRAME_LENGTH(x)	((x) & ~(1 << 7))
#define WEBSOCKET_HAS_MASK(x)		((x) & (1 << 7))
#define WEBSOCKET_HAS_FINFLAG(x)	((x) & (1 << 7))
#define WEBSOCKET_RSV(x, i)		((x) & (1 << (7 - i)))

#define WEBSOCKET_SERVER_RESPONSE	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct websocket_data {
	u_int8_t		op;
	void			*data;
	size_t			len;
};

u_int64_t	kore_websocket_timeout = 120000;
u_int64_t	kore_websocket_maxframe = 16384;

static int	websocket_recv_frame(struct netbuf *);
static int	websocket_recv_opcode(struct netbuf *);
static void	websocket_disconnect(struct connection *);
static void	websocket_send_single(struct connection *, void *);
void		websocket_send(struct connection *, u_int8_t, void *, size_t);

void
kore_websocket_handshake(struct http_request *req, struct kore_wscbs *wscbs)
{
	SHA_CTX			sctx;
	struct kore_buf		*buf;
	char			*key, *base64, *version;
	u_int8_t		digest[SHA_DIGEST_LENGTH];

	if (!http_request_header(req, "sec-websocket-key", &key)) {
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

	if (!http_request_header(req, "sec-websocket-version", &version)) {
		http_response_header(req, "sec-websocket-version", "13");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

	if (strcmp(version, "13")) {
		kore_mem_free(version);
		http_response_header(req, "sec-websocket-version", "13");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

	kore_mem_free(version);

	buf = kore_buf_create(128);
	kore_buf_appendf(buf, "%s%s", key, WEBSOCKET_SERVER_RESPONSE);
	kore_mem_free(key);

	(void)SHA1_Init(&sctx);
	(void)SHA1_Update(&sctx, buf->data, buf->offset);
	(void)SHA1_Final(digest, &sctx);

	kore_buf_free(buf);

	if (!kore_base64_encode(digest, sizeof(digest), &base64)) {
		kore_debug("failed to base64 encode digest");
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return;
	}

	http_response_header(req, "upgrade", "websocket");
	http_response_header(req, "connection", "upgrade");
	http_response_header(req, "sec-websocket-accept", base64);
	kore_mem_free(base64);

	kore_debug("%p: new websocket connection", req->owner);

	http_response(req, HTTP_STATUS_SWITCHING_PROTOCOLS, NULL, 0);
	net_recv_reset(req->owner, WEBSOCKET_FRAME_HDR, websocket_recv_opcode);

	req->owner->disconnect = websocket_disconnect;
	req->owner->rnb->flags &= ~NETBUF_CALL_CB_ALWAYS;
	req->owner->proto = CONN_PROTO_WEBSOCKET;

	req->owner->wscbs = wscbs;
	req->owner->idle_timer.start = kore_time_ms();
	req->owner->idle_timer.length = kore_websocket_timeout;

	if (wscbs->connect != NULL)
		wscbs->connect(req->owner);
}

void
kore_websocket_send(struct connection *c, u_int8_t op, void *data, size_t len)
{
	u_int8_t		len_1;
	u_int16_t		len16;
	u_int64_t		len64;
	struct kore_buf		*frame;

	if (c->proto != CONN_PROTO_WEBSOCKET)
		fatal("kore_websocket_send(): to non websocket connection");

	kore_debug("%p: sending %ld bytes", c, len);

	if (len > WEBSOCKET_PAYLOAD_SINGLE) {
		if (len < USHRT_MAX)
			len_1 = WEBSOCKET_PAYLOAD_EXTEND_1;
		else
			len_1 = WEBSOCKET_PAYLOAD_EXTEND_2;
	} else {
		len_1 = len;
	}

	frame = kore_buf_create(len);

	op |= (1 << 7);
	kore_buf_append(frame, &op, sizeof(op));

	len_1 &= ~(1 << 7);
	kore_buf_append(frame, &len_1, sizeof(len_1));

	if (len_1 != len) {
		switch (len_1) {
		case WEBSOCKET_PAYLOAD_EXTEND_1:
			net_write16((u_int8_t *)&len16, len);
			kore_buf_append(frame, &len16, sizeof(len16));
			break;
		case WEBSOCKET_PAYLOAD_EXTEND_2:
			net_write64((u_int8_t *)&len64, len);
			kore_buf_append(frame, &len64, sizeof(len64));
			break;
		}
	}

	kore_buf_append(frame, data, len);
	net_send_queue(c, frame->data, frame->offset, NULL, NETBUF_LAST_CHAIN);
	kore_buf_free(frame);
}

void
kore_websocket_broadcast(struct connection *c, u_int8_t op, void *data,
    size_t len, int scope)
{
	struct websocket_data	arg;

	arg.op = op;
	arg.len = len;
	arg.data = data;
	kore_worker_websocket_broadcast(c, websocket_send_single, &arg);

	if (scope == WEBSOCKET_BROADCAST_GLOBAL)
		fatal("kore_websocket_broadcast: no global scope yet");
}

static void
websocket_send_single(struct connection *c, void *args)
{
	struct websocket_data	*arg = args;

	kore_websocket_send(c, arg->op, arg->data, arg->len);
	net_send_flush(c);
}

static int
websocket_recv_opcode(struct netbuf *nb)
{
	u_int8_t		op, len;
	struct connection	*c = nb->owner;

	if (!WEBSOCKET_HAS_MASK(nb->buf[1])) {
		kore_debug("%p: frame did not have a mask set", c);
		return (KORE_RESULT_ERROR);
	}

	if (WEBSOCKET_RSV(nb->buf[0], 1) || WEBSOCKET_RSV(nb->buf[0], 2) ||
	    WEBSOCKET_RSV(nb->buf[0], 2)) {
		kore_debug("%p: RSV bits are not zero", c);
		return (KORE_RESULT_ERROR);
	}

	len = WEBSOCKET_FRAME_LENGTH(nb->buf[1]);

	op = nb->buf[0] & WEBSOCKET_OPCODE_MASK;
	switch (op) {
	case WEBSOCKET_OP_CONT:
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
		break;
	case WEBSOCKET_OP_CLOSE:
	case WEBSOCKET_OP_PING:
	case WEBSOCKET_OP_PONG:
		if (len > WEBSOCKET_PAYLOAD_SINGLE ||
		    !WEBSOCKET_HAS_FINFLAG(nb->buf[0])) {
			kore_debug("%p: large or fragmented control frame", c);
			return (KORE_RESULT_ERROR);
		}
		break;
	default:
		kore_debug("%p: bad websocket op %d", c, op);
		return (KORE_RESULT_ERROR);
	}

	switch (len) {
	case WEBSOCKET_PAYLOAD_EXTEND_1:
		len += sizeof(u_int16_t);
		break;
	case WEBSOCKET_PAYLOAD_EXTEND_2:
		len += sizeof(u_int64_t);
		break;
	}

	len += WEBSOCKET_MASK_LEN;
	net_recv_expand(c, len, NULL, websocket_recv_frame);

	return (KORE_RESULT_OK);
}

static int
websocket_recv_frame(struct netbuf *nb)
{
	struct connection	*c;
	int			ret;
	struct kore_wscbs	*wscbs;
	u_int64_t		len, i, total;
	u_int8_t		op, moff, extra;

	c = nb->owner;
	wscbs = c->wscbs;

	op = nb->buf[0] & WEBSOCKET_OPCODE_MASK;
	len = WEBSOCKET_FRAME_LENGTH(nb->buf[1]);

	switch (len) {
	case WEBSOCKET_PAYLOAD_EXTEND_1:
		moff = 4;
		extra = sizeof(u_int16_t);
		len = net_read16(&nb->buf[2]);
		break;
	case WEBSOCKET_PAYLOAD_EXTEND_2:
		moff = 10;
		extra = sizeof(u_int64_t);
		len = net_read64(&nb->buf[2]);
		break;
	default:
		extra = 0;
		moff = 2;
		break;
	}

	if (len > kore_websocket_maxframe) {
		kore_debug("%p: frame too big", c);
		return (KORE_RESULT_ERROR);
	}

	extra += WEBSOCKET_FRAME_HDR;
	total = len + extra + WEBSOCKET_MASK_LEN;
	if (total > nb->b_len) {
		total -= nb->b_len;
		net_recv_expand(c, total, NULL, websocket_recv_frame);
		return (KORE_RESULT_OK);
	}

	if (total != nb->b_len)
		return (KORE_RESULT_ERROR);

	for (i = 0; i < len; i++)
		nb->buf[moff + 4 + i] ^= nb->buf[moff + (i % 4)];

	ret = KORE_RESULT_OK;
	switch (op) {
	case WEBSOCKET_OP_CONT:
	case WEBSOCKET_OP_PONG:
		ret = KORE_RESULT_ERROR;
		kore_log(LOG_ERR, "%p: we do not support op 0x%02x yet", c, op);
		break;
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
		if (wscbs->message != NULL)
			wscbs->message(c, op, &nb->buf[moff + 4], len);
		break;
	case WEBSOCKET_OP_CLOSE:
		kore_connection_disconnect(c);
		break;
	case WEBSOCKET_OP_PING:
		kore_websocket_send(c, WEBSOCKET_OP_PONG,
		    &nb->buf[moff + 4], len);
		break;
	default:
		kore_debug("%p: bad websocket op %d", c, op);
		return (KORE_RESULT_ERROR);
	}

	net_recv_reset(c, WEBSOCKET_FRAME_HDR, websocket_recv_opcode);
	return (ret);
}

static void
websocket_disconnect(struct connection *c)
{
	struct kore_wscbs	*wscbs = c->wscbs;

	if (wscbs->disconnect != NULL)
		wscbs->disconnect(c);
}
