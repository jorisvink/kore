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

#include <sys/socket.h>

#include <netdb.h>
#include <signal.h>

#include "kore.h"

volatile sig_atomic_t			sig_recv;

struct listener_head	listeners;
u_int8_t		nlisteners;
struct passwd		*pw = NULL;
pid_t			kore_pid = -1;
u_int16_t		cpu_count = 1;
int			kore_debug = 0;
int			skip_chroot = 0;
u_int8_t		worker_count = 0;
char			*runas_user = NULL;
char			*chroot_path = NULL;
int			kore_cb_worker = -1;
u_int64_t		kore_cb_interval = 0;
void			(*kore_cb)(void) = NULL;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;
char			*kore_ssl_cipher_list = KORE_DEFAULT_CIPHER_LIST;

static void	usage(void);
static void	kore_server_start(void);
static void	kore_write_kore_pid(void);
static void	kore_server_sslstart(void);

static void
usage(void)
{
	fprintf(stderr, "Usage: kore [-c config] [-dn]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int			ch;
	struct listener		*l;

	while ((ch = getopt(argc, argv, "c:dn")) != -1) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
#if defined(KORE_DEBUG)
			kore_debug = 1;
#else
			printf("kore not compiled with debug support\n");
#endif
			break;
		case 'n':
			skip_chroot = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	kore_pid = getpid();

	nlisteners = 0;
	LIST_INIT(&listeners);

	kore_log_init();
	kore_mem_init();
	kore_auth_init();
	kore_domain_init();
	kore_module_init();
	kore_validator_init();
	kore_server_sslstart();
	kore_parse_config();

	kore_platform_init();
	kore_accesslog_init();

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);

	kore_server_start();

	kore_log(LOG_NOTICE, "server shutting down");
	kore_worker_shutdown();
	unlink(kore_pidfile);

	LIST_FOREACH(l, &listeners, list)
		close(l->fd);

	kore_log(LOG_NOTICE, "goodbye");
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

		if (dom->cafile != NULL) {
			SSL_set_verify(ssl, SSL_VERIFY_PEER |
			    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		} else {
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
		}

		return (SSL_TLSEXT_ERR_OK);
	}

	return (SSL_TLSEXT_ERR_NOACK);
}

int
kore_server_bind(const char *ip, const char *port)
{
	struct listener		*l;
	int			on, r;
	struct addrinfo		*results;

	kore_debug("kore_server_bind(%s, %s)", ip, port);

	r = getaddrinfo(ip, port, NULL, &results);
	if (r != 0)
		fatal("getaddrinfo(%s): %s", ip, gai_strerror(r));

	l = kore_malloc(sizeof(struct listener));
	l->type = KORE_TYPE_LISTENER;
	l->addrtype = results->ai_family;

	if (l->addrtype != AF_INET && l->addrtype != AF_INET6)
		fatal("getaddrinfo(): unknown address family %d", l->addrtype);

	if ((l->fd = socket(results->ai_family, SOCK_STREAM, 0)) == -1) {
		kore_mem_free(l);
		freeaddrinfo(results);
		kore_debug("socket(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_connection_nonblock(l->fd)) {
		kore_mem_free(l);
		freeaddrinfo(results);
		return (KORE_RESULT_ERROR);
	}

	on = 1;
	if (setsockopt(l->fd, SOL_SOCKET,
	    SO_REUSEADDR, (const char *)&on, sizeof(on)) == -1) {
		close(l->fd);
		kore_mem_free(l);
		freeaddrinfo(results);
		kore_debug("setsockopt(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (bind(l->fd, results->ai_addr, results->ai_addrlen) == -1) {
		close(l->fd);
		kore_mem_free(l);
		freeaddrinfo(results);
		kore_debug("bind(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	freeaddrinfo(results);

	if (listen(l->fd, 5000) == -1) {
		close(l->fd);
		kore_mem_free(l);
		kore_debug("listen(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	nlisteners++;
	LIST_INSERT_HEAD(&listeners, l, list);

	return (KORE_RESULT_OK);
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
	u_int64_t	now, last_cb_run;

	kore_mem_free(runas_user);

	if (daemon(1, 1) == -1)
		fatal("cannot daemon(): %s", errno_s);

	kore_pid = getpid();
	kore_write_kore_pid();

	kore_log(LOG_NOTICE, "kore is starting up");
	kore_platform_proctitle("kore [parent]");
	kore_worker_init();

	now = kore_time_ms();
	last_cb_run = now;

	for (;;) {
		if (sig_recv != 0) {
			if (sig_recv == SIGHUP || sig_recv == SIGQUIT) {
				kore_worker_dispatch_signal(sig_recv);
				if (sig_recv == SIGHUP)
					kore_module_reload();
				if (sig_recv == SIGQUIT)
					break;
			}
			sig_recv = 0;
		}

		if (!kore_accesslog_wait())
			break;

		if (kore_cb != NULL && kore_cb_worker == -1) {
			now = kore_time_ms();
			if ((now - last_cb_run) >= kore_cb_interval) {
				kore_cb();
				last_cb_run = now;
			}
		}

		kore_worker_wait(0);
	}
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
