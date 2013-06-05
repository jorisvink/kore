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
#include <sys/prctl.h>
#include <sys/wait.h>

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
#include <sched.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <zlib.h>
#include <unistd.h>

#include "spdy.h"
#include "kore.h"
#include "http.h"

#define EPOLL_EVENTS	500

static int	efd = -1;
static SSL_CTX	*ssl_ctx = NULL;

volatile sig_atomic_t			sig_recv;
static struct listener			server;
static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		worker_clients;
static TAILQ_HEAD(, kore_worker)	kore_workers;
static struct passwd			*pw = NULL;
static u_int16_t			workerid = 0;
static u_int16_t			cpu_count = 1;

pid_t			mypid = -1;
int			server_port = 0;
u_int8_t		worker_count = 0;
char			*server_ip = NULL;
char			*chroot_path = NULL;
char			*runas_user = NULL;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;

static void	kore_signal(int);
static void	kore_worker_wait(int);
static void	kore_worker_init(void);
static void	kore_write_mypid(void);
static int	kore_socket_nonblock(int);
static int	kore_server_sslstart(void);
static void	kore_event(int, int, void *);
static void	kore_worker_spawn(u_int16_t);
static int	kore_server_accept(struct listener *);
static void	kore_worker_entry(struct kore_worker *);
static void	kore_worker_setcpu(struct kore_worker *);
static int	kore_connection_handle(struct connection *, int);
static void	kore_server_final_disconnect(struct connection *);
static int	kore_server_bind(struct listener *, const char *, int);
static int	kore_ssl_npn_cb(SSL *, const u_char **, unsigned int *, void *);

int
main(int argc, char *argv[])
{
	struct kore_worker	*kw, *next;

	kore_log_init();
	mypid = getpid();

	if (argc != 2)
		fatal("Usage: kore [config file]");
	if (getuid() != 0)
		fatal("kore must be started as root");

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
	if ((cpu_count = sysconf(_SC_NPROCESSORS_ONLN)) == -1) {
		kore_debug("could not get number of cpu's falling back to 1");
		cpu_count = 1;
	}

	if (!kore_server_bind(&server, server_ip, server_port))
		fatal("cannot bind to %s:%d", server_ip, server_port);
	if (daemon(1, 1) == -1)
		fatal("cannot daemon(): %s", errno_s);

	mypid = getpid();
	kore_write_mypid();

	kore_log(LOG_NOTICE, "kore is starting up");
	kore_worker_init();

	if (prctl(PR_SET_NAME, "kore [main]"))
		kore_debug("cannot set process title");

	sig_recv = 0;
	signal(SIGQUIT, kore_signal);
	signal(SIGHUP, kore_signal);

	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP) {
				TAILQ_FOREACH(kw, &kore_workers, list) {
					if (kill(kw->pid, SIGHUP) == -1) {
						kore_debug("kill(%d, HUP): %s",
						    kw->pid, errno_s);
					}
				}
			} else if (sig_recv == SIGQUIT) {
				break;
			}
			sig_recv = 0;
		}

		kore_worker_wait(0);
		sleep(1);
	}

	for (kw = TAILQ_FIRST(&kore_workers); kw != NULL; kw = next) {
		next = TAILQ_NEXT(kw, list);
		if (kill(kw->pid, SIGINT) == -1)
			kore_debug("kill(%d, SIGINT): %s", kw->pid, errno_s);
	}

	kore_log(LOG_NOTICE, "waiting for workers to drain and finish");
	while (!TAILQ_EMPTY(&kore_workers))
		kore_worker_wait(1);

	kore_log(LOG_NOTICE, "server shutting down");
	unlink(kore_pidfile);
	close(server.fd);

	return (0);
}

void
kore_server_disconnect(struct connection *c)
{
	if (c->state != CONN_STATE_DISCONNECTING) {
		kore_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;
		TAILQ_REMOVE(&worker_clients, c, list);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
	}
}

static int
kore_server_sslstart(void)
{
	kore_debug("kore_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL) {
		kore_debug("SSL_ctx_new(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, "cert/server.crt")) {
		kore_debug("SSL_CTX_use_certificate_file(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, "cert/server.key",
	    SSL_FILETYPE_PEM)) {
		kore_debug("SSL_CTX_use_PrivateKey_file(): %s", ssl_errno_s);
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
	int	on;

	kore_debug("kore_server_bind(%p, %s, %d)", l, ip, port);

	if ((l->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		kore_debug("socket(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_socket_nonblock(l->fd)) {
		close(l->fd);
		return (KORE_RESULT_ERROR);
	}

	on = 1;
	if (setsockopt(l->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
	    sizeof(on)) == -1) {
		kore_debug("setsockopt(): %s", errno_s);
		close(l->fd);
		return (KORE_RESULT_ERROR);
	}

	memset(&(l->sin), 0, sizeof(l->sin));
	l->sin.sin_family = AF_INET;
	l->sin.sin_port = htons(port);
	l->sin.sin_addr.s_addr = inet_addr(ip);

	if (bind(l->fd, (struct sockaddr *)&(l->sin), sizeof(l->sin)) == -1) {
		close(l->fd);
		kore_debug("bind(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (listen(l->fd, 50) == -1) {
		close(l->fd);
		kore_debug("listen(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
kore_server_accept(struct listener *l)
{
	socklen_t		len;
	struct connection	*c;

	kore_debug("kore_server_accept(%p)", l);

	len = sizeof(struct sockaddr_in);
	c = (struct connection *)kore_malloc(sizeof(*c));
	if ((c->fd = accept(l->fd, (struct sockaddr *)&(c->sin), &len)) == -1) {
		free(c);
		kore_debug("accept(): %s", errno_s);
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

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	TAILQ_INIT(&(c->spdy_streams));;
	TAILQ_INSERT_TAIL(&worker_clients, c, list);

	kore_event(c->fd, EPOLLIN | EPOLLOUT | EPOLLET, c);

	return (KORE_RESULT_OK);
}

static void
kore_server_final_disconnect(struct connection *c)
{
	struct netbuf		*nb, *next;
	struct spdy_stream	*s, *snext;

	kore_debug("kore_server_final_disconnect(%p)", c);

	if (c->ssl != NULL)
		SSL_free(c->ssl);

	TAILQ_REMOVE(&disconnected, c, list);
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

	free(c);
}

static int
kore_connection_handle(struct connection *c, int flags)
{
	int			r;
	u_int32_t		len;
	const u_char		*data;

	kore_debug("kore_connection_handle(%p, %d)", c, flags);

	if (flags & EPOLLIN)
		c->flags |= CONN_READ_POSSIBLE;
	if (flags & EPOLLOUT)
		c->flags |= CONN_WRITE_POSSIBLE;

	switch (c->state) {
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(ssl_ctx);
			if (c->ssl == NULL) {
				kore_debug("SSL_new(): %s", ssl_errno_s);
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
				kore_debug("SSL_accept(): %s", ssl_errno_s);
				return (KORE_RESULT_ERROR);
			}
		}

		r = SSL_get_verify_result(c->ssl);
		if (r != X509_V_OK) {
			kore_debug("SSL_get_verify_result(): %s", ssl_errno_s);
			return (KORE_RESULT_ERROR);
		}

		SSL_get0_next_proto_negotiated(c->ssl, &data, &len);
		if (data) {
			if (!memcmp(data, "spdy/3", 6))
				kore_debug("using SPDY/3");
			c->proto = CONN_PROTO_SPDY;
			net_recv_queue(c, SPDY_FRAME_SIZE, 0,
			    NULL, spdy_frame_recv);
		} else {
			kore_debug("using HTTP/1.1");
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
		kore_debug("unknown state on %d (%d)", c->fd, c->state);
		break;
	}

	return (KORE_RESULT_OK);
}

static void
kore_worker_init(void)
{
	u_int16_t		i, cpu;

	if (worker_count == 0)
		fatal("no workers specified");

	kore_debug("kore_worker_init(): system has %d cpu's", cpu_count);
	kore_debug("kore_worker_init(): starting %d workers", worker_count);
	if (worker_count > cpu_count)
		kore_debug("kore_worker_init(): more workers then cpu's");

	cpu = 0;
	TAILQ_INIT(&kore_workers);
	for (i = 0; i < worker_count; i++) {
		kore_worker_spawn(cpu++);
		if (cpu == cpu_count)
			cpu = 0;
	}
}

static void
kore_worker_spawn(u_int16_t cpu)
{
	struct kore_worker	*kw;

	kw = (struct kore_worker *)kore_malloc(sizeof(*kw));
	kw->id = workerid++;
	kw->cpu = cpu;
	kw->pid = fork();
	if (kw->pid == -1)
		fatal("could not spawn worker child: %s", errno_s);

	if (kw->pid == 0) {
		kw->pid = getpid();
		kore_worker_entry(kw);
		/* NOTREACHED */
	}

	TAILQ_INSERT_TAIL(&kore_workers, kw, list);
}

static void
kore_worker_wait(int final)
{
	int			r;
	siginfo_t		info;
	struct kore_worker	k, *kw, *next;

	memset(&info, 0, sizeof(info));
	if (final)
		r = waitid(P_ALL, 0, &info, WEXITED);
	else
		r = waitid(P_ALL, 0, &info, WEXITED | WNOHANG);
	if (r == -1) {
		kore_debug("waitid(): %s", errno_s);
		return;
	}

	if (info.si_pid == 0)
		return;

	for (kw = TAILQ_FIRST(&kore_workers); kw != NULL; kw = next) {
		next = TAILQ_NEXT(kw, list);
		if (kw->pid != info.si_pid)
			continue;

		k = *kw;
		TAILQ_REMOVE(&kore_workers, kw, list);
		kore_log(LOG_NOTICE, "worker %d (%d)-> status %d (%d)",
		    kw->id, info.si_pid, info.si_status, info.si_code);
		free(kw);

		if (final)
			continue;

		if (info.si_code == CLD_EXITED ||
		    info.si_code == CLD_KILLED ||
		    info.si_code == CLD_DUMPED) {
			kore_log(LOG_NOTICE,
			    "worker %d (pid: %d) gone, respawning new one",
			    k.id, k.pid);
			kore_worker_spawn(k.cpu);
		}
	}
}

static void
kore_worker_setcpu(struct kore_worker *kw)
{
	cpu_set_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
		kore_debug("kore_worker_setcpu(): %s", errno_s);
	} else {
		kore_debug("kore_worker_setcpu(): worker %d on cpu %d",
		    kw->id, kw->cpu);
	}
}

static void
kore_worker_entry(struct kore_worker *kw)
{
	char			buf[16];
	struct epoll_event	*events;
	struct connection	*c, *cnext;
	struct kore_worker	*k, *next;
	int			n, i, *fd, quit;

	snprintf(buf, sizeof(buf), "kore [wrk %d]", kw->id);
	if (prctl(PR_SET_NAME, buf) == -1)
		kore_debug("cannot set process title");

	if (chroot(chroot_path) == -1)
		fatal("cannot chroot(): %s", errno_s);
	if (chdir("/") == -1)
		fatal("cannot chdir(): %s", errno_s);
	if (setgroups(1, &pw->pw_gid) || setresgid(pw->pw_gid, pw->pw_gid,
	    pw->pw_gid) || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("unable to drop privileges");

	kore_worker_setcpu(kw);

	for (k = TAILQ_FIRST(&kore_workers); k != NULL; k = next) {
		next = TAILQ_NEXT(k, list);
		TAILQ_REMOVE(&kore_workers, k, list);
		free(k);
	}

	mypid = kw->pid;

	if (!kore_server_sslstart())
		fatal("cannot initiate SSL");
	if ((efd = epoll_create(1000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);

	http_init();
	TAILQ_INIT(&disconnected);
	TAILQ_INIT(&worker_clients);

	quit = 0;
	kore_event(server.fd, EPOLLIN, &server);
	events = kore_calloc(EPOLL_EVENTS, sizeof(struct epoll_event));

	kore_log(LOG_NOTICE, "worker %d going to work (CPU: %d)",
	    kw->id, kw->cpu);
	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP)
				kore_module_reload();
			else if (sig_recv == SIGQUIT)
				quit = 1;
			sig_recv = 0;
		}

		n = epoll_wait(efd, events, EPOLL_EVENTS, 100);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			fatal("epoll_wait(): %s", errno_s);
		}

		if (n > 0)
			kore_debug("main(): %d sockets available", n);

		for (i = 0; i < n; i++) {
			fd = (int *)events[i].data.ptr;

			if (events[i].events & EPOLLERR ||
			    events[i].events & EPOLLHUP) {
				if (*fd == server.fd)
					fatal("error on server socket");

				c = (struct connection *)events[i].data.ptr;
				kore_server_disconnect(c);
				continue;
			}

			if (*fd == server.fd) {
				if (!quit)
					kore_server_accept(&server);
			} else {
				c = (struct connection *)events[i].data.ptr;
				if (!kore_connection_handle(c,
				    events[i].events))
					kore_server_disconnect(c);
			}
		}

		http_process();

		for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
			cnext = TAILQ_NEXT(c, list);
			kore_server_final_disconnect(c);
		}

		if (quit && http_request_count == 0)
			break;
	}

	for (c = TAILQ_FIRST(&worker_clients); c != NULL; c = cnext) {
		cnext = TAILQ_NEXT(c, list);
		net_send_flush(c);
		kore_server_final_disconnect(c);
	}

	for (c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext) {
		cnext = TAILQ_NEXT(c, list);
		net_send_flush(c);
		kore_server_final_disconnect(c);
	}

	kore_debug("worker %d shutting down", kw->id);
	exit(0);
}

static int
kore_socket_nonblock(int fd)
{
	int		flags;

	kore_debug("kore_socket_nonblock(%d)", fd);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		kore_debug("fcntl(): F_GETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		kore_debug("fcntl(): F_SETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
kore_ssl_npn_cb(SSL *ssl, const u_char **data, unsigned int *len, void *arg)
{
	kore_debug("kore_ssl_npn_cb(): sending protocols");

	*data = (const unsigned char *)KORE_SSL_PROTO_STRING;
	*len = strlen(KORE_SSL_PROTO_STRING);

	return (SSL_TLSEXT_ERR_OK);
}

static void
kore_event(int fd, int flags, void *udata)
{
	struct epoll_event	evt;

	kore_debug("kore_event(%d, %d, %p)", fd, flags, udata);

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
kore_write_mypid(void)
{
	FILE		*fp;

	if ((fp = fopen(kore_pidfile, "w+")) == NULL) {
		kore_debug("kore_write_mypid(): fopen() %s", errno_s);
	} else {
		fprintf(fp, "%d\n", mypid);
		fclose(fp);
	}
}

static void
kore_signal(int sig)
{
	sig_recv = sig;
}
