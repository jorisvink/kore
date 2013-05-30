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
#include <sys/epoll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pwd.h>
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <zlib.h>
#include <pthread.h>
#include <unistd.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

#define EPOLL_EVENTS	500

static int	efd = -1;
static SSL_CTX	*ssl_ctx = NULL;

volatile sig_atomic_t			sig_recv;
static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, kore_worker)	kore_workers;
static struct kore_worker		*last_worker = NULL;

int			server_port = 0;
char			*server_ip = NULL;
char			*chroot_path = NULL;
char			*runas_user = NULL;
u_int8_t		worker_count = 0;
pthread_mutex_t		disconnect_lock;

static void	kore_signal(int);
static void	kore_worker_init(void);
static void	*kore_worker_entry(void *);
static int	kore_socket_nonblock(int);
static int	kore_server_sslstart(void);
static void	kore_event(int, int, void *);
static int	kore_server_accept(struct listener *);
static int	kore_connection_handle(struct connection *, int);
static void	kore_server_final_disconnect(struct connection *);
static int	kore_server_bind(struct listener *, const char *, int);
static int	kore_ssl_npn_cb(SSL *, const u_char **, unsigned int *, void *);

int
main(int argc, char *argv[])
{
	struct passwd		*pw;
	struct listener		server;
	struct epoll_event	*events;
	int			n, i, *fd;
	struct connection	*c, *cnext;

	if (argc != 2)
		fatal("Usage: kore [config file]");

	kore_parse_config(argv[1]);
	if (!kore_module_loaded())
		fatal("no site module was loaded");

	if (server_ip == NULL || server_port == 0)
		fatal("missing a correct bind directive in configuration");
	if (chroot_path == NULL)
		fatal("missing a chroot path");
	if (runas_user == NULL)
		fatal("missing a username to run as");
	if ((pw = getpwnam(runas_user)) == NULL)
		fatal("user '%s' does not exist");

	if (!kore_server_bind(&server, server_ip, server_port))
		fatal("cannot bind to %s:%d", server_ip, server_port);
	if (!kore_server_sslstart())
		fatal("cannot initiate SSL");

	if ((efd = epoll_create(1000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	if (chroot(chroot_path) == -1)
		fatal("chroot(%s): %s", chroot_path, errno_s);
	if (chdir("/") == -1)
		fatal("chdir(/): %s", errno_s);
	if (setgroups(1, &pw->pw_gid) || setresgid(pw->pw_gid, pw->pw_gid,
	    pw->pw_gid) || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("unable to drop privileges");

	TAILQ_INIT(&disconnected);
	pthread_mutex_init(&disconnect_lock, NULL);

	kore_worker_init();

	sig_recv = 0;
	signal(SIGHUP, kore_signal);

	kore_event(server.fd, EPOLLIN, &server);
	events = kore_calloc(EPOLL_EVENTS, sizeof(struct epoll_event));
	for (;;) {
		if (sig_recv == SIGHUP) {
			kore_module_reload();
			sig_recv = 0;
		}

		n = epoll_wait(efd, events, EPOLL_EVENTS, 10);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			fatal("epoll_wait(): %s", errno_s);
		}

		if (n > 0)
			kore_log("main(): %d sockets available", n);

		for (i = 0; i < n; i++) {
			fd = (int *)events[i].data.ptr;

			if (events[i].events & EPOLLERR ||
			    events[i].events & EPOLLHUP) {
				if (*fd == server.fd)
					fatal("error on server socket");

				c = (struct connection *)events[i].data.ptr;
				if (pthread_mutex_trylock(&(c->lock))) {
					// Reschedule the client.
					kore_log("resched on error");
				} else {
					kore_server_disconnect(c);
					pthread_mutex_unlock(&(c->lock));
				}
				continue;
			}

			if (*fd == server.fd) {
				kore_server_accept(&server);
			} else {
				c = (struct connection *)events[i].data.ptr;
				if (pthread_mutex_trylock(&(c->lock))) {
					// Reschedule the client.
					kore_log("resched on normal");
				} else {
					if (!kore_connection_handle(c,
					    events[i].events))
						kore_server_disconnect(c);
					pthread_mutex_unlock(&(c->lock));
				}
			}
		}

		if (pthread_mutex_trylock(&disconnect_lock))
			continue;

		for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
			cnext = TAILQ_NEXT(c, list);
			TAILQ_REMOVE(&disconnected, c, list);
			kore_server_final_disconnect(c);
		}

		pthread_mutex_unlock(&disconnect_lock);
	}

	close(server.fd);
	return (0);
}

void
kore_server_disconnect(struct connection *c)
{
	if (c->state != CONN_STATE_DISCONNECTING) {
		kore_log("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;

		pthread_mutex_lock(&disconnect_lock);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
		pthread_mutex_unlock(&disconnect_lock);
	}
}

void
kore_worker_delegate(struct http_request *req)
{
	struct kore_worker		*kw;

	if (last_worker != NULL) {
		kw = TAILQ_NEXT(last_worker, list);
		if (kw == NULL)
			kw = TAILQ_FIRST(&kore_workers);
	} else {
		kw = TAILQ_FIRST(&kore_workers);
	}

	last_worker = kw;

	pthread_mutex_lock(&(kw->lock));
	kore_log("assigning request %p to worker %d:%d", req, kw->id, kw->load);
	kw->load++;
	TAILQ_INSERT_TAIL(&(kw->requests), req, list);
	pthread_mutex_unlock(&(kw->lock));
	pthread_cond_signal(&(kw->cond));
}

static int
kore_server_sslstart(void)
{
	kore_log("kore_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL) {
		kore_log("SSL_ctx_new(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, "cert/server.crt")) {
		kore_log("SSL_CTX_use_certificate_file(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, "cert/server.key",
	    SSL_FILETYPE_PEM)) {
		kore_log("SSL_CTX_use_PrivateKey_file(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, kore_ssl_npn_cb, NULL);

	return (KORE_RESULT_OK);
}

static int
kore_server_bind(struct listener *l, const char *ip, int port)
{
	kore_log("kore_server_bind(%p, %s, %d)", l, ip, port);

	if ((l->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		kore_log("socket(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_socket_nonblock(l->fd)) {
		close(l->fd);
		return (KORE_RESULT_ERROR);
	}

	memset(&(l->sin), 0, sizeof(l->sin));
	l->sin.sin_family = AF_INET;
	l->sin.sin_port = htons(port);
	l->sin.sin_addr.s_addr = inet_addr(ip);

	if (bind(l->fd, (struct sockaddr *)&(l->sin), sizeof(l->sin)) == -1) {
		close(l->fd);
		kore_log("bind(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (listen(l->fd, 50) == -1) {
		close(l->fd);
		kore_log("listen(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
kore_server_accept(struct listener *l)
{
	socklen_t		len;
	struct connection	*c;

	kore_log("kore_server_accept(%p)", l);

	len = sizeof(struct sockaddr_in);
	c = (struct connection *)kore_malloc(sizeof(*c));
	if ((c->fd = accept(l->fd, (struct sockaddr *)&(c->sin), &len)) == -1) {
		free(c);
		kore_log("accept(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_socket_nonblock(c->fd)) {
		close(c->fd);
		free(c);
		return (KORE_RESULT_ERROR);
	}

	c->owner = l;
	c->ssl = NULL;
	c->flags = 0;
	c->inflate_started = 0;
	c->deflate_started = 0;
	c->client_stream_id = 0;
	c->proto = CONN_PROTO_UNKNOWN;
	c->state = CONN_STATE_SSL_SHAKE;
	pthread_mutex_init(&(c->lock), NULL);

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	TAILQ_INIT(&(c->spdy_streams));;
	kore_event(c->fd, EPOLLIN | EPOLLOUT | EPOLLET, c);

	return (KORE_RESULT_OK);
}

static void
kore_server_final_disconnect(struct connection *c)
{
	struct netbuf		*nb, *next;
	struct spdy_stream	*s, *snext;

	if (pthread_mutex_trylock(&(c->lock))) {
		kore_log("delaying disconnection of %p", c);
		return;
	}

	kore_log("kore_server_final_disconnect(%p)", c);

	if (c->ssl != NULL) {
		if (SSL_shutdown(c->ssl) == 0) {
			pthread_mutex_unlock(&(c->lock));
			return;
		}

		SSL_free(c->ssl);
	}

	close(c->fd);
	if (c->inflate_started)
		inflateEnd(&(c->z_inflate));
	if (c->deflate_started)
		deflateEnd(&(c->z_deflate));

	for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);
		free(nb->buf);
		free(nb);
	}

	for (nb = TAILQ_FIRST(&(c->recv_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->recv_queue), nb, list);
		free(nb->buf);
		free(nb);
	}

	for (s = TAILQ_FIRST(&(c->spdy_streams)); s != NULL; s = snext) {
		snext = TAILQ_NEXT(s, list);
		TAILQ_REMOVE(&(c->spdy_streams), s, list);

		if (s->hblock != NULL) {
			if (s->hblock->header_block != NULL)
				free(s->hblock->header_block);
			free(s->hblock);
		}

		free(s);
	}

	pthread_mutex_destroy(&(c->lock));
	free(c);
}

static int
kore_connection_handle(struct connection *c, int flags)
{
	int			r;
	u_int32_t		len;
	const u_char		*data;

	kore_log("kore_connection_handle(%p, %d)", c, flags);

	if (flags & EPOLLIN)
		c->flags |= CONN_READ_POSSIBLE;
	if (flags & EPOLLOUT)
		c->flags |= CONN_WRITE_POSSIBLE;

	switch (c->state) {
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(ssl_ctx);
			if (c->ssl == NULL) {
				kore_log("SSL_new(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}

			SSL_set_fd(c->ssl, c->fd);
		}

		r = SSL_accept(c->ssl);
		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return (KORE_RESULT_OK);
			default:
				kore_log("SSL_accept(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}
		}

		r = SSL_get_verify_result(c->ssl);
		if (r != X509_V_OK) {
			kore_log("SSL_get_verify_result(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}

		SSL_get0_next_proto_negotiated(c->ssl, &data, &len);
		if (data) {
			if (!memcmp(data, "spdy/3", 6))
				kore_log("using SPDY/3");
			c->proto = CONN_PROTO_SPDY;
			net_recv_queue(c, SPDY_FRAME_SIZE, 0,
			    NULL, spdy_frame_recv);
		} else {
			kore_log("using HTTP/1.1");
			c->proto = CONN_PROTO_HTTP;
			net_recv_queue(c, HTTP_HEADER_MAX_LEN,
			    NETBUF_CALL_CB_ALWAYS, NULL,
			    http_header_recv);
		}

		c->state = CONN_STATE_ESTABLISHED;
		/* FALLTHROUGH */
	case CONN_STATE_ESTABLISHED:
		if (c->flags & CONN_READ_POSSIBLE) {
			if (!net_recv_flush(c))
				return (KORE_RESULT_ERROR);
		}

		if (c->flags & CONN_WRITE_POSSIBLE) {
			if (!net_send_flush(c))
				return (KORE_RESULT_ERROR);
		}
		break;
	case CONN_STATE_DISCONNECTING:
		break;
	default:
		kore_log("unknown state on %d (%d)", c->fd, c->state);
		break;
	}

	return (KORE_RESULT_OK);
}

static void
kore_worker_init(void)
{
	u_int8_t		i;
	struct kore_worker	*kw;

	kore_log("kore_worker_init(): starting %d workers", worker_count);

	TAILQ_INIT(&kore_workers);
	for (i = 0; i < worker_count; i++) {
		kw = (struct kore_worker *)kore_malloc(sizeof(*kw));
		kw->id = i;
		kw->load = 0;
		pthread_cond_init(&(kw->cond), NULL);
		pthread_mutex_init(&(kw->lock), NULL);
		TAILQ_INIT(&(kw->requests));
		TAILQ_INSERT_TAIL(&kore_workers, kw, list);

		if (pthread_create(&(kw->pctx), NULL, kore_worker_entry, kw))
			kore_log("failed to spawn worker: %s", errno_s);
	}

	if (i == 0)
		fatal("No workers spawned, check logs for errors.");
}

static void *
kore_worker_entry(void *arg)
{
	u_int8_t		retry;
	struct http_request	*req, *next;
	struct kore_worker	*kw = (struct kore_worker *)arg;
	int			r, (*hdlr)(struct http_request *);

	pthread_mutex_lock(&(kw->lock));
	for (;;) {
		if (retry == 0) {
			pthread_cond_wait(&(kw->cond), &(kw->lock));
			kore_log("worker %d woke up with %d reqs",
			    kw->id, kw->load);
		}

		retry = 0;
		for (req = TAILQ_FIRST(&(kw->requests)); req != NULL;
		    req = next) {
			next = TAILQ_NEXT(req, list);
			if (req->flags & HTTP_REQUEST_DELETE) {
				TAILQ_REMOVE(&(kw->requests), req, list);
				http_request_free(req);
				continue;
			}

			if (!(req->flags & HTTP_REQUEST_COMPLETE))
				continue;

			if (pthread_mutex_trylock(&(req->owner->lock))) {
				retry = 1;
				continue;
			}

			hdlr = kore_module_handler_find(req->host, req->path);
			if (hdlr == NULL)
				r = http_generic_404(req);
			else
				r = hdlr(req);

			if (r != KORE_RESULT_ERROR) {
				r = net_send_flush(req->owner);
				if (r == KORE_RESULT_ERROR ||
				    req->owner->proto == CONN_PROTO_HTTP)
					kore_server_disconnect(req->owner);
			} else {
				kore_server_disconnect(req->owner);
			}

			pthread_mutex_unlock(&(req->owner->lock));

			TAILQ_REMOVE(&(kw->requests), req, list);
			http_request_free(req);

			kw->load--;
		}
	}

	pthread_exit(NULL);
}

static int
kore_socket_nonblock(int fd)
{
	int		flags;

	kore_log("kore_socket_nonblock(%d)", fd);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		kore_log("fcntl(): F_GETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		kore_log("fcntl(): F_SETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
kore_ssl_npn_cb(SSL *ssl, const u_char **data, unsigned int *len, void *arg)
{
	kore_log("kore_ssl_npn_cb(): sending protocols");

	*data = (const unsigned char *)KORE_SSL_PROTO_STRING;
	*len = strlen(KORE_SSL_PROTO_STRING);

	return (SSL_TLSEXT_ERR_OK);
}

static void
kore_event(int fd, int flags, void *udata)
{
	struct epoll_event	evt;

	kore_log("kore_event(%d, %d, %p)", fd, flags, udata);

	evt.events = flags;
	evt.data.ptr = udata;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl() MOD: %s", errno_s);
		} else {
			fatal("epoll_ctl() ADD: %s", errno_s);
		}
	}
}

static void
kore_signal(int sig)
{
	sig_recv = sig;
}
