/*
 * Copyright (c) 2016 Joris Vink <joris@coders.se>
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

#include <sys/socket.h>

#include <signal.h>

#include "kore.h"
#include "http.h"

struct msg_type {
	u_int8_t		id;
	void			(*cb)(struct kore_msg *, const void *);
	TAILQ_ENTRY(msg_type)	list;
};

TAILQ_HEAD(, msg_type)		msg_types;

static struct msg_type	*msg_type_lookup(u_int8_t);
static int		msg_recv_packet(struct netbuf *);
static int		msg_recv_data(struct netbuf *);
static void		msg_disconnected_parent(struct connection *);
static void		msg_disconnected_worker(struct connection *);
static void		msg_type_shutdown(struct kore_msg *msg, const void *data);

#if !defined(KORE_NO_HTTP)
static void		msg_type_accesslog(struct kore_msg *, const void *);
static void		msg_type_websocket(struct kore_msg *, const void *);
#endif

void
kore_msg_init(void)
{
	TAILQ_INIT(&msg_types);
}

void
kore_msg_parent_init(void)
{
	u_int8_t		i;
	struct kore_worker	*kw;

	for (i = 0; i < worker_count; i++) {
		kw = kore_worker_data(i);
		kore_msg_parent_add(kw);
	}

	kore_msg_register(KORE_MSG_SHUTDOWN, msg_type_shutdown);

#if !defined(KORE_NO_HTTP)
	kore_msg_register(KORE_MSG_ACCESSLOG, msg_type_accesslog);
#endif
}

void
kore_msg_parent_add(struct kore_worker *kw)
{
	kw->msg[0] = kore_connection_new(NULL);
	kw->msg[0]->fd = kw->pipe[0];
	kw->msg[0]->read = net_read;
	kw->msg[0]->write = net_write;
	kw->msg[0]->proto = CONN_PROTO_MSG;
	kw->msg[0]->state = CONN_STATE_ESTABLISHED;
	kw->msg[0]->hdlr_extra = &kw->id;
	kw->msg[0]->disconnect = msg_disconnected_worker;
	kw->msg[0]->handle = kore_connection_handle;

	TAILQ_INSERT_TAIL(&connections, kw->msg[0], list);
	kore_platform_event_all(kw->msg[0]->fd, kw->msg[0]);

	net_recv_queue(kw->msg[0], sizeof(struct kore_msg), 0, msg_recv_packet);
}

void
kore_msg_parent_remove(struct kore_worker *kw)
{
	kore_connection_disconnect(kw->msg[0]);
	kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	(void)close(kw->pipe[1]);
}

void
kore_msg_worker_init(void)
{
#if !defined(KORE_NO_HTTP)
	kore_msg_register(KORE_MSG_WEBSOCKET, msg_type_websocket);
#endif

	worker->msg[1] = kore_connection_new(NULL);
	worker->msg[1]->fd = worker->pipe[1];
	worker->msg[1]->read = net_read;
	worker->msg[1]->write = net_write;
	worker->msg[1]->proto = CONN_PROTO_MSG;
	worker->msg[1]->state = CONN_STATE_ESTABLISHED;
	worker->msg[1]->disconnect = msg_disconnected_parent;
	worker->msg[1]->handle = kore_connection_handle;

	TAILQ_INSERT_TAIL(&connections, worker->msg[1], list);
	kore_platform_event_all(worker->msg[1]->fd, worker->msg[1]);

	net_recv_queue(worker->msg[1],
	    sizeof(struct kore_msg), 0, msg_recv_packet);
}

int
kore_msg_register(u_int8_t id, void (*cb)(struct kore_msg *, const void *))
{
	struct msg_type		*type;

	if ((type = msg_type_lookup(id)) != NULL)
		return (KORE_RESULT_ERROR);

	type = kore_malloc(sizeof(*type));
	type->id = id;
	type->cb = cb;
	TAILQ_INSERT_TAIL(&msg_types, type, list);

	return (KORE_RESULT_OK);
}

void
kore_msg_send(u_int16_t dst, u_int8_t id, const void *data, u_int32_t len)
{
	struct kore_msg		m;

	m.id = id;
	m.dst = dst;
	m.length = len;
	m.src = worker->id;

	net_send_queue(worker->msg[1], &m, sizeof(m));
	if (data != NULL && len > 0)
		net_send_queue(worker->msg[1], data, len);

	net_send_flush(worker->msg[1]);
}

static int
msg_recv_packet(struct netbuf *nb)
{
	struct kore_msg		*msg = (struct kore_msg *)nb->buf;

	if (msg->length > 0) {
		net_recv_expand(nb->owner, msg->length, msg_recv_data);
		return (KORE_RESULT_OK);
	}

	return (msg_recv_data(nb));
}

static int
msg_recv_data(struct netbuf *nb)
{
	struct connection	*c;
	struct msg_type		*type;
	u_int16_t		destination;
	struct kore_msg		*msg = (struct kore_msg *)nb->buf;

	if ((type = msg_type_lookup(msg->id)) != NULL) {
		if (worker == NULL && msg->dst != KORE_MSG_PARENT)
			fatal("received parent msg for non parent dst");
		if (worker != NULL && msg->dst != worker->id)
			fatal("received message for incorrect worker");

		if (msg->length > 0)
			type->cb(msg, nb->buf + sizeof(*msg));
		else
			type->cb(msg, NULL);
	}

	if (worker == NULL && type == NULL) {
		destination = msg->dst;
		TAILQ_FOREACH(c, &connections, list) {
			if (c == nb->owner)
				continue;
			if (c->proto != CONN_PROTO_MSG || c->hdlr_extra == NULL)
				continue;

			if (destination != KORE_MSG_WORKER_ALL &&
			    *(u_int8_t *)c->hdlr_extra != destination)
				continue;

			/* This allows the worker to receive the correct id. */
			msg->dst = *(u_int8_t *)c->hdlr_extra;

			net_send_queue(c, nb->buf, nb->s_off);
			net_send_flush(c);
		}
	}

	net_recv_reset(nb->owner, sizeof(struct kore_msg), msg_recv_packet);
	return (KORE_RESULT_OK);
}

static void
msg_disconnected_parent(struct connection *c)
{
	kore_log(LOG_ERR, "parent gone, shutting down");
	if (kill(worker->pid, SIGQUIT) == -1)
		kore_log(LOG_ERR, "failed to send SIGQUIT: %s", errno_s);
}

static void
msg_disconnected_worker(struct connection *c)
{
	c->hdlr_extra = NULL;
}

static void
msg_type_shutdown(struct kore_msg *msg, const void *data)
{
	kore_log(LOG_NOTICE, "worker requested shutdown");
	kore_signal(SIGQUIT);
}

#if !defined(KORE_NO_HTTP)
static void
msg_type_accesslog(struct kore_msg *msg, const void *data)
{
	if (kore_accesslog_write(data, msg->length) == -1)
		kore_log(LOG_WARNING, "failed to write to accesslog");
}

static void
msg_type_websocket(struct kore_msg *msg, const void *data)
{
	struct connection	*c;

	TAILQ_FOREACH(c, &connections, list) {
		if (c->proto == CONN_PROTO_WEBSOCKET) {
			net_send_queue(c, data, msg->length);
			net_send_flush(c);
		}
	}
}
#endif

static struct msg_type *
msg_type_lookup(u_int8_t id)
{
	struct msg_type		*type;

	TAILQ_FOREACH(type, &msg_types, list) {
		if (type->id == id)
			return (type);
	}

	return (NULL);
}
