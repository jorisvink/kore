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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/event.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/err.h"
#include "openssl/ssl.h"

#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define KQUEUE_EVENT_COUNT	100
#define NETBUF_RECV_MAX		8192

#define HTTP_REQUEST_FMT	\
	"GET %s?host=%s&port=%s HTTP/1.1\r\nHost: %s\r\n\r\n"

struct netbuf {
	u_int8_t		*data;
	u_int32_t		offset;
	u_int32_t		length;

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_list, netbuf);

#define PEER_CAN_READ		0x01
#define PEER_CAN_WRITE		0x02

struct peer {
	int			fd;
	int			family;
	int			flags;

	char			*name;
	char			*host;
	char			*port;

	int			(*write)(struct peer *);
	int			(*read)(struct peer *, struct peer *);

	SSL			*ssl;
	SSL_CTX			*ssl_ctx;
	void			*connection;
	struct peer		*opposite;

	struct netbuf		*recv_buf;
	struct netbuf_list	write_queue;
};

#define CONNECTION_WILL_DISCONNECT	0x01

struct connection {
	int			flags;
	struct peer		local;
	struct peer		remote;
	TAILQ_ENTRY(connection)	list;
};

TAILQ_HEAD(, connection)		clients;
TAILQ_HEAD(, connection)		disconnects;

void		usage(void);
void		fatal(const char *, ...);

int		ktunnel_peer_handle(struct peer *);
void		ktunnel_peer_cleanup(struct peer *);
void		ktunnel_connection_close(struct connection *);
void		ktunnel_connection_cleanup(struct connection *);

void		ktunnel_event_schedule(int, int, int, void *);

void		ktunnel_set_nonblock(int);
int		ktunnel_write_local(struct peer *);
int		ktunnel_write_remote(struct peer *);
int		ktunnel_read_local(struct peer *, struct peer *);
int		ktunnel_read_remote(struct peer *, struct peer *);

void		ktunnel_accept(struct peer *);
void		ktunnel_bind(struct peer *, struct addrinfo *);
void		ktunnel_connect(struct peer *, struct addrinfo *);
void		ktunnel_peer_init(struct peer *, const char *,
		    void (*cb)(struct peer *, struct addrinfo *));

void		ktunnel_netbuf_create(struct netbuf **, struct netbuf_list *,
		    u_int8_t *, u_int32_t);

int		kfd = - 1;
u_int32_t	nchanges = 0;
struct kevent	*events = NULL;
struct kevent	*changelist = NULL;
char		*target_host = NULL;
char		*target_port = NULL;
char		*remote_name = NULL;
char		*http_hostname = NULL;
char		*http_path = "/connect";

void
usage(void)
{
	fprintf(stderr,
	    "Usage: ktunnel-client [-h host] [-p path] "
	    "local:port remote:port target:port\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	int			n, i, ch;
	struct connection	*c, *cnext;
	struct peer		lpeer, *peer;

	while ((ch = getopt(argc, argv, "h:p:")) != -1) {
		switch (ch) {
		case 'h':
			http_hostname = optarg;
			break;
		case 'p':
			http_path = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 3)
		usage();

	TAILQ_INIT(&clients);
	TAILQ_INIT(&disconnects);

	if ((kfd = kqueue()) == -1)
		fatal("kqueue(): %s", errno_s);

	nchanges = 0;
	events = calloc(KQUEUE_EVENT_COUNT, sizeof(struct kevent));
	changelist = calloc(KQUEUE_EVENT_COUNT, sizeof(struct kevent));
	if (events == NULL || changelist == NULL)
		fatal("calloc(): %s", errno_s);

	memset(&lpeer, 0, sizeof(lpeer));
	ktunnel_peer_init(&lpeer, argv[0], ktunnel_bind);
	ktunnel_event_schedule(lpeer.fd, EVFILT_READ, EV_ADD, &lpeer);

	remote_name = argv[1];
	target_host = argv[2];

	if ((target_port = strchr(target_host, ':')) == NULL)
		fatal("Target host does not contain a port");
	*(target_port)++ = '\0';

	if (http_hostname == NULL)
		http_hostname = target_host;

	for (;;) {
		n = kevent(kfd, changelist, nchanges,
		    events, KQUEUE_EVENT_COUNT, NULL);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			fatal("kevent(): %s", errno_s);
		}

		nchanges = 0;
		for (i = 0; i < n; i++) {
			if (events[i].udata == NULL)
				fatal("events[%d].udata == NULL", i);

			peer = (struct peer *)events[i].udata;

			if (events[i].flags & EV_EOF ||
			    events[i].flags & EV_ERROR) {
				if (peer->fd == lpeer.fd)
					fatal("error on listening socket");

				ktunnel_connection_close(peer->connection);
				continue;
			}

			if (peer->fd == lpeer.fd) {
				ktunnel_accept(peer);
				continue;
			}

			if (events[i].filter == EVFILT_READ)
				peer->flags |= PEER_CAN_READ;
			if (events[i].filter == EVFILT_WRITE)
				peer->flags |= PEER_CAN_WRITE;

			if (ktunnel_peer_handle(peer) == -1) {
				ktunnel_connection_close(peer->connection);
			} else {
				if (!TAILQ_EMPTY(&peer->write_queue)) {
					ktunnel_event_schedule(peer->fd,
					    EVFILT_WRITE,
					    EV_ADD | EV_ONESHOT, peer);
				}
			}
		}

		for (c = TAILQ_FIRST(&disconnects); c != NULL; c = cnext) {
			cnext = TAILQ_NEXT(c, list);
			TAILQ_REMOVE(&disconnects, c, list);
			ktunnel_connection_cleanup(c);
		}
	}

	return (0);
}

void
ktunnel_peer_init(struct peer *peer, const char *name, void (*cb)(struct peer *,
    struct addrinfo *))
{
	int			r;
	struct addrinfo		*ai, *results;

	if ((peer->name = strdup(name)) == NULL)
		fatal("strdup() messed up");

	peer->host = peer->name;
	if ((peer->port = strchr(peer->host, ':')) == NULL)
		fatal("No port section in given local host '%s'", peer->name);
	*(peer->port)++ = '\0';

	r = getaddrinfo(peer->host, peer->port, NULL, &results);
	if (r != 0)
		fatal("%s: %s", name, gai_strerror(r));

	for (ai = results; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_socktype != SOCK_STREAM)
			continue;
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		cb(peer, ai);
		peer->family = ai->ai_family;

		break;
	}

	freeaddrinfo(results);
}

void
ktunnel_accept(struct peer *peer)
{
	int			fd;
	struct connection	*c;
	struct sockaddr_in	sin4;
	struct sockaddr_in6	sin6;
	struct sockaddr		*sin;
	socklen_t		slen;

	sin = NULL;

	switch (peer->family) {
	case AF_INET:
		sin = (struct sockaddr *)&sin4;
		slen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		sin = (struct sockaddr *)&sin6;
		slen = sizeof(struct sockaddr_in6);
		break;
	default:
		fatal("Unknown peer family %d", peer->family);
		/* NOTREACHED */
	}

	if ((fd = accept(peer->fd, sin, &slen)) == -1)
		fatal("accept(): %s", errno_s);

	if ((c = malloc(sizeof(*c))) == NULL)
		fatal("malloc(): %s", errno_s);

	memset(c, 0, sizeof(*c));
	c->local.fd = fd;
	TAILQ_INIT(&c->local.write_queue);

	ktunnel_event_schedule(c->local.fd, EVFILT_READ, EV_ADD, &c->local);
	ktunnel_event_schedule(c->local.fd, EVFILT_WRITE,
	    EV_ADD | EV_ONESHOT, &c->local);

	c->local.connection = c;
	c->local.opposite = &c->remote;
	c->local.read = ktunnel_read_local;
	c->local.write = ktunnel_write_local;

	c->remote.connection = c;
	c->remote.opposite = &c->local;
	c->remote.read = ktunnel_read_remote;
	c->remote.write = ktunnel_write_remote;

	ktunnel_peer_init(&c->remote, remote_name, ktunnel_connect);
	ktunnel_netbuf_create(&c->local.recv_buf,
	    NULL, NULL, NETBUF_RECV_MAX);

	ktunnel_set_nonblock(c->local.fd);
	ktunnel_set_nonblock(c->remote.fd);

	TAILQ_INSERT_TAIL(&clients, c, list);

	printf("new connection %p (%p<->%p)\n", c, &c->local, &c->remote);
}

void
ktunnel_bind(struct peer *peer, struct addrinfo *ai)
{
	if ((peer->fd = socket(ai->ai_family, ai->ai_socktype, 0)) == -1)
		fatal("socket(): %s", errno_s);

	if (bind(peer->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		fatal("Cannot bind to %s:%s: %s",
		    peer->host, peer->port, errno_s);
	}

	if (listen(peer->fd, 10) == -1)
		fatal("Cannot listen on socket: %s", errno_s);

	TAILQ_INIT(&peer->write_queue);
	ktunnel_netbuf_create(&peer->recv_buf, NULL, NULL, NETBUF_RECV_MAX);
}

void
ktunnel_connect(struct peer *peer, struct addrinfo *ai)
{
	int		l;
	char		*req;

	if ((peer->fd = socket(ai->ai_family, ai->ai_socktype, 0)) == -1)
		fatal("socket(): %s", errno_s);

	if (connect(peer->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		fatal("Cannot connect to %s:%s: %s",
		    peer->host, peer->port, errno_s);
	}

	TAILQ_INIT(&peer->write_queue);
	ktunnel_netbuf_create(&peer->recv_buf, NULL, NULL, NETBUF_RECV_MAX);

	/*
	 * XXX
	 * - Add our client certs
	 * - Verify server cert properly
	 * - ...
	 */
	SSL_library_init();
	SSL_load_error_strings();

	if ((peer->ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL)
		fatal("SSL_CTX_new(): %s", ssl_errno_s);

	SSL_CTX_set_mode(peer->ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_options(peer->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(peer->ssl_ctx, SSL_OP_NO_SSLv3);
	SSL_CTX_set_options(peer->ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_set_options(peer->ssl_ctx, SSL_OP_NO_TLSv1_1);

	if ((peer->ssl = SSL_new(peer->ssl_ctx)) == NULL)
		fatal("SSL_new(): %s", ssl_errno_s);
	if (!SSL_set_fd(peer->ssl, peer->fd))
		fatal("SSL_set_fd(): %s", ssl_errno_s);
	if (!SSL_connect(peer->ssl)) {
		fatal("Could not establish an SSL connection to %s: %s",
		    peer->host, ssl_errno_s);
	}

	/* Send custom HTTP command. */
	l = asprintf(&req, HTTP_REQUEST_FMT, http_path,
	    target_host, target_port, http_hostname);
	if (l == -1)
		fatal("asprintf(): %s", errno_s);

	if (SSL_write(peer->ssl, req, l) != l) {
		fatal("Failed to talk to %s:%s: %s",
		    peer->host, peer->port, ssl_errno_s);
	}

	free(req);

	ktunnel_event_schedule(peer->fd, EVFILT_READ, EV_ADD, peer);
	ktunnel_event_schedule(peer->fd, EVFILT_WRITE,
	    EV_ADD | EV_ONESHOT, peer);

	printf("Connected over SSL to %s:%s\n", peer->host, peer->port);
}

int
ktunnel_peer_handle(struct peer *peer)
{
	int		r;

	printf("handling peer %p (%d)\n", peer, peer->flags);

	if (peer->flags & PEER_CAN_READ) {
		printf("\treading\n");
		r = peer->read(peer, peer->opposite);
	}

	if (peer->flags & PEER_CAN_WRITE) {
		printf("\twriting\n");
		r = peer->write(peer);
	}

	return (r);
}

void
ktunnel_connection_close(struct connection *c)
{
	printf("ktunnel_connection_close(%p)\n", c);

	if (!(c->flags & CONNECTION_WILL_DISCONNECT)) {
		c->flags |= CONNECTION_WILL_DISCONNECT;

		TAILQ_REMOVE(&clients, c, list);
		TAILQ_INSERT_TAIL(&disconnects, c, list);
	}
}

void
ktunnel_connection_cleanup(struct connection *c)
{
	ktunnel_peer_cleanup(&c->local);
	ktunnel_peer_cleanup(&c->remote);

	free(c);
}

void
ktunnel_peer_cleanup(struct peer *peer)
{
	struct netbuf		*nb, *next;

	printf("ktunnel_peer_cleanup(%p)\n", peer);

	close(peer->fd);

	if (peer->ssl != NULL)
		SSL_free(peer->ssl);
	if (peer->ssl_ctx != NULL)
		SSL_CTX_free(peer->ssl_ctx);

	for (nb = TAILQ_FIRST(&peer->write_queue); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&peer->write_queue, nb, list);

		free(nb->data);
		free(nb);
	}

	free(peer->recv_buf->data);
}

void
ktunnel_netbuf_create(struct netbuf **out, struct netbuf_list *head,
    u_int8_t *data, u_int32_t length)
{
	struct netbuf		*nb;

	if ((nb = malloc(sizeof(struct netbuf))) == NULL)
		fatal("malloc(): %s", errno_s);

	nb->offset = 0;
	nb->length = length;

	if ((nb->data = malloc(nb->length)) == NULL)
		fatal("malloc(): %s", errno_s);

	if (data != NULL)
		memcpy(nb->data, data, nb->length);

	if (head != NULL)
		TAILQ_INSERT_TAIL(head, nb, list);

	if (out != NULL)
		*out = nb;
}

void
ktunnel_event_schedule(int fd, int type, int flags, void *udata)
{
	if (nchanges >= KQUEUE_EVENT_COUNT)
		fatal("nchanges > KQUEUE_EVENT_COUNT");

	EV_SET(&changelist[nchanges], fd, type, flags, 0, 0, udata);
	nchanges++;
}

int
ktunnel_read_local(struct peer *in, struct peer *out)
{
	int		r;

	printf("ktunnel_read_local: %p\n", in);

	r = read(in->fd, in->recv_buf->data, in->recv_buf->length);
	if (r == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			printf("read error on local peer: %s\n", errno_s);
			return (-1);
		}

		return (0);
	}

	if (r == 0) {
		printf("local peer closed connection\n");
		return (-1);
	}

	printf("ktunnel_read_local: %p -- %d bytes --> %p\n", in, r, out);

	ktunnel_netbuf_create(NULL, &(out->write_queue), in->recv_buf->data, r);
	return (ktunnel_write_remote(out));
}

int
ktunnel_write_local(struct peer *peer)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&peer->write_queue)) {
		nb = TAILQ_FIRST(&peer->write_queue);

		printf("ktunnel_write_local: %p writing %d/%d\n", peer,
		    nb->offset, nb->length);

		r = write(peer->fd, (nb->data + nb->offset),
		    (nb->length - nb->offset));
		if (r == -1) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				peer->flags &= ~PEER_CAN_WRITE;
				return (0);
			default:
				printf("failed to write to local peer: %s\n",
				    errno_s);
				return (-1);
			}
		}

		nb->offset += r;
		printf("ktunnel_write_local: %p progress %d/%d\n", peer,
		    nb->offset, nb->length);

		if (nb->offset == nb->length) {
			TAILQ_REMOVE(&peer->write_queue, nb, list);
			free(nb->data);
			free(nb);
		}
	}

	return (0);
}

int
ktunnel_read_remote(struct peer *in, struct peer *out)
{
	int			r;

	r = SSL_read(in->ssl, in->recv_buf->data, in->recv_buf->length);
	if (r <= 0) {
		r = SSL_get_error(in->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			in->flags &= ~PEER_CAN_READ;
			return (0);
		default:
			printf("failed to read from remote peer: %d, %s\n",
			    r, ssl_errno_s);
			return (-1);
		}
	}

	ktunnel_netbuf_create(NULL, &(out->write_queue), in->recv_buf->data, r);
	return (ktunnel_write_local(out));
}

int
ktunnel_write_remote(struct peer *peer)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&peer->write_queue)) {
		nb = TAILQ_FIRST(&peer->write_queue);

		printf("ktunnel_write_remote: %p writing %d/%d bytes\n", peer,
		    nb->offset, nb->length);

		r = SSL_write(peer->ssl, (nb->data + nb->offset),
		    (nb->length - nb->offset));
		if (r <= 0) {
			r = SSL_get_error(peer->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				peer->flags &= ~PEER_CAN_WRITE;
				return (0);
			default:
				printf("failed to write to remote peer: %s\n",
				    ssl_errno_s);
				return (-1);
			}
		}

		nb->offset += r;
		printf("ktunnel_write_remote: %p progress %d/%d\n", peer,
		    nb->offset, nb->length);

		if (nb->offset == nb->length) {
			TAILQ_REMOVE(&peer->write_queue, nb, list);
			free(nb->data);
			free(nb);
		}
	}

	return (0);
}

void
ktunnel_set_nonblock(int fd)
{
	int		flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl(): get %s", errno_s);

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fnctl(): set %s", errno_s);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf("\n");

	exit(1);
}
