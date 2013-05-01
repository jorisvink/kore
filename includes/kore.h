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

#ifndef __H_KORE_H
#define __H_KORE_H

#define KORE_RESULT_ERROR	0
#define KORE_RESULT_OK		1

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)
#define kore_log(fmt, ...)	\
	kore_log_internal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define NETBUF_RECV		0
#define NETBUF_SEND		1

struct netbuf {
	u_int8_t		*buf;
	u_int32_t		offset;
	u_int32_t		len;
	u_int8_t		type;
	u_int8_t		retain;

	void			*owner;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

struct listener {
	int			fd;
	struct sockaddr_in	sin;
};

#define CONN_STATE_UNKNOWN	0
#define CONN_STATE_SSL_SHAKE	1
#define CONN_STATE_ESTABLISHED	2

#define CONN_PROTO_UNKNOWN	0
#define CONN_PROTO_SPDY		1
#define CONN_PROTO_HTTP		2

struct connection {
	int			fd;
	int			state;
	int			proto;
	struct sockaddr_in	sin;
	void			*owner;
	SSL			*ssl;

	TAILQ_HEAD(, netbuf)	send_queue;
	TAILQ_HEAD(, netbuf)	recv_queue;

	u_int32_t		client_stream_id;
	TAILQ_HEAD(, spdy_stream)	spdy_streams;
};

void		*kore_malloc(size_t);
void		*kore_calloc(size_t, size_t);
void		*kore_realloc(void *, size_t);
char		*kore_strdup(const char *);
void		kore_strlcpy(char *, const char *, size_t);
void		kore_server_disconnect(struct connection *);

void		fatal(const char *, ...);
void		kore_log_internal(char *, int, const char *, ...);

u_int16_t	net_read16(u_int8_t *);
u_int32_t	net_read32(u_int8_t *);
void		net_write16(u_int8_t *, u_int16_t);
void		net_write32(u_int8_t *, u_int32_t);
int		net_recv(struct connection *);
int		net_send(struct connection *);
int		net_recv_queue(struct connection *, size_t,
		    int (*cb)(struct netbuf *));
int		net_recv_expand(struct connection *c, struct netbuf *, size_t,
		    int (*cb)(struct netbuf *));
int		net_send_queue(struct connection *, u_int8_t *, size_t,
		    int (*cb)(struct netbuf *));

int		spdy_frame_recv(struct netbuf *);
int		spdy_frame_send(struct connection *, u_int16_t,
		    u_int8_t, u_int32_t, u_int32_t, u_int8_t *);
struct spdy_stream	*spdy_stream_lookup(struct connection *, u_int32_t);

#endif /* !__H_KORE_H */
