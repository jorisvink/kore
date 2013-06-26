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

struct listener		server;
struct passwd		*pw = NULL;
pid_t			kore_pid = -1;
u_int16_t		cpu_count = 1;
int			kore_debug = 0;
int			server_port = 0;
u_int8_t		worker_count = 0;
char			*server_ip = NULL;
char			*runas_user = NULL;
char			*chroot_path = NULL;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;

static void	usage(void);
static void	kore_server_start(void);
static void	kore_write_kore_pid(void);
static void	kore_server_sslstart(void);
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

	if (getuid() != 0)
		fatal("kore must be started as root");

	kore_debug = 0;
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

	kore_pid = getpid();
	kore_domain_init();
	kore_server_sslstart();

	kore_parse_config();
	kore_log_init();
	kore_platform_init();
	kore_accesslog_init();

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);

	kore_server_start();

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
		kore_platform_worker_wait(0);
	}

	for (kw = TAILQ_FIRST(&kore_workers); kw != NULL; kw = next) {
		next = TAILQ_NEXT(kw, list);
		if (kill(kw->pid, SIGINT) == -1)
			kore_debug("kill(%d, SIGINT): %s", kw->pid, errno_s);
	}

	kore_log(LOG_NOTICE, "waiting for workers to drain and finish");
	while (!TAILQ_EMPTY(&kore_workers))
		kore_platform_worker_wait(1);

	kore_log(LOG_NOTICE, "server shutting down");
	unlink(kore_pidfile);
	close(server.fd);

	return (0);
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

void
kore_signal(int sig)
{
	sig_recv = sig;
}

static void
kore_server_sslstart(void)
{
	kore_debug("kore_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
}

static void
kore_server_start(void)
{
	if (!kore_server_bind(&server, server_ip, server_port))
		fatal("cannot bind to %s:%d", server_ip, server_port);
	if (daemon(1, 1) == -1)
		fatal("cannot daemon(): %s", errno_s);

	kore_pid = getpid();
	kore_write_kore_pid();

	kore_log(LOG_NOTICE, "kore is starting up");
	kore_platform_proctitle("kore [parent]");

	kore_worker_init();

	free(server_ip);
	free(runas_user);
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
kore_write_kore_pid(void)
{
	FILE		*fp;

	if ((fp = fopen(kore_pidfile, "w+")) == NULL) {
		kore_debug("kore_write_kore_pid(): fopen() %s", errno_s);
	} else {
		fprintf(fp, "%d\n", kore_pid);
		fclose(fp);
	}
}
