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

volatile sig_atomic_t			sig_recv;
static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		worker_clients;
static struct passwd			*pw = NULL;
static u_int16_t			workerid = 0;

struct listener		server;
pid_t			mypid = -1;
u_int16_t		cpu_count = 1;
struct kore_worker_h	kore_workers;
struct kore_worker	*worker = NULL;
int			kore_debug = 0;
int			server_port = 0;
u_int8_t		worker_count = 0;
char			*server_ip = NULL;
char			*runas_user = NULL;
char			*chroot_path = NULL;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;

static void	usage(void);
static void	kore_signal(int);
static void	kore_write_mypid(void);
static int	kore_socket_nonblock(int);
static void	kore_server_sslstart(void);
static void	kore_server_final_disconnect(struct connection *);
static int	kore_server_bind(struct listener *, const char *, int);

static void
usage(void)
{
	fprintf(stderr, "Usage: kore [-c config] [-d]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int			ch;
	struct kore_worker	*kw, *next;
	char			*config_file;

	if (getuid() != 0)
		fatal("kore must be started as root");

	kore_debug = 0;
	config_file = NULL;
	while ((ch = getopt(argc, argv, "c:d")) != -1) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			kore_debug = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (config_file == NULL)
		fatal("please specify a configuration file to use (-c)");

	mypid = getpid();

	kore_domain_init();
	kore_server_sslstart();

	kore_parse_config(config_file);
	if (!kore_module_loaded())
		fatal("no site module was loaded");

	if (server_ip == NULL || server_port == 0)
		fatal("missing a correct bind directive in configuration");
	if (chroot_path == NULL)
		fatal("missing a chroot path");
	if (runas_user == NULL)
		fatal("missing a username to run as");
	if ((pw = getpwnam(runas_user)) == NULL)
		fatal("user '%s' does not exist", runas_user);

	kore_log_init();
	kore_platform_init();
	kore_accesslog_init();

	if (!kore_server_bind(&server, server_ip, server_port))
		fatal("cannot bind to %s:%d", server_ip, server_port);
	if (daemon(1, 1) == -1)
		fatal("cannot daemon(): %s", errno_s);

	mypid = getpid();
	kore_write_mypid();

	kore_log(LOG_NOTICE, "kore is starting up");
	kore_worker_init();
	kore_set_proctitle("kore [parent]");

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);

	free(server_ip);
	free(runas_user);

	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP) {
				kore_module_reload();
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

		if (!kore_accesslog_wait())
			break;
		kore_worker_wait(0);
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

int
kore_server_accept(struct listener *l, struct connection **out)
{
	socklen_t		len;
	struct connection	*c;

	kore_debug("kore_server_accept(%p)", l);

	*out = NULL;
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
	TAILQ_INIT(&(c->spdy_streams));
	TAILQ_INSERT_TAIL(&worker_clients, c, list);

	*out = c;
	return (KORE_RESULT_OK);
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

int
kore_connection_handle(struct connection *c)
{
	int			r;
	u_int32_t		len;
	const u_char		*data;

	kore_debug("kore_connection_handle(%p)", c);

	switch (c->state) {
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(primary_dom->ssl_ctx);
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

void
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

void
kore_worker_entry(struct kore_worker *kw)
{
	int			quit;
	char			buf[16];
	struct connection	*c, *cnext;
	struct kore_worker	*k, *next;

	worker = kw;

	if (chroot(chroot_path) == -1)
		fatal("cannot chroot(): %s", errno_s);
	if (chdir("/") == -1)
		fatal("cannot chdir(): %s", errno_s);
	if (setgroups(1, &pw->pw_gid) || setresgid(pw->pw_gid, pw->pw_gid,
	    pw->pw_gid) || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("unable to drop privileges");

	snprintf(buf, sizeof(buf), "kore [wrk %d]", kw->id);
	kore_set_proctitle(buf);
	kore_worker_setcpu(kw);

	for (k = TAILQ_FIRST(&kore_workers); k != NULL; k = next) {
		next = TAILQ_NEXT(k, list);
		TAILQ_REMOVE(&kore_workers, k, list);
		free(k);
	}

	mypid = kw->pid;

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);
	signal(SIGPIPE, SIG_IGN);

	http_init();
	TAILQ_INIT(&disconnected);
	TAILQ_INIT(&worker_clients);

	quit = 0;
	kore_event_init();
	kore_accesslog_worker_init();

	kore_log(LOG_NOTICE, "worker %d started (cpu#%d)", kw->id, kw->cpu);
	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP)
				kore_module_reload();
			else if (sig_recv == SIGQUIT)
				quit = 1;
			sig_recv = 0;
		}

		kore_event_wait(quit);
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

int
kore_ssl_npn_cb(SSL *ssl, const u_char **data, unsigned int *len, void *arg)
{
	kore_debug("kore_ssl_npn_cb(): sending protocols");

	*data = (const unsigned char *)KORE_SSL_PROTO_STRING;
	*len = strlen(KORE_SSL_PROTO_STRING);

	return (SSL_TLSEXT_ERR_OK);
}

int
kore_ssl_sni_cb(SSL *ssl, int *ad, void *arg)
{
	struct kore_domain	*dom;
	const char		*sname;

	sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	kore_debug("kore_ssl_sni_cb(): received host %s", sname);

	if (sname != NULL && (dom = kore_domain_lookup(sname)) != NULL) {
		kore_debug("kore_ssl_sni_cb(): Using %s CTX", sname);
		SSL_set_SSL_CTX(ssl, dom->ssl_ctx);
		return (SSL_TLSEXT_ERR_OK);
	}

	return (SSL_TLSEXT_ERR_NOACK);
}

static void
kore_server_sslstart(void)
{
	kore_debug("kore_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
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
