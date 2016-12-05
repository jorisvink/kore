/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/resource.h>

#include <stdio.h>
#include <netdb.h>
#include <signal.h>

#include "kore.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

volatile sig_atomic_t			sig_recv;

struct listener_head	listeners;
u_int8_t		nlisteners;
pid_t			kore_pid = -1;
u_int16_t		cpu_count = 1;
int			foreground = 0;
int			kore_debug = 0;
u_int8_t		worker_count = 0;
int			skip_chroot = 0;
char			*chroot_path = NULL;
int			skip_runas = 0;
char			*runas_user = NULL;
u_int32_t		kore_socket_backlog = 5000;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;
char			*kore_tls_cipher_list = KORE_DEFAULT_CIPHER_LIST;

extern char		*__progname;

static void	usage(void);
static void	version(void);
static void	kore_server_start(void);
static void	kore_write_kore_pid(void);
static void	kore_server_sslstart(void);

static void
usage(void)
{
#if !defined(KORE_SINGLE_BINARY)
	fprintf(stderr, "Usage: kore [options | command]\n");
#else
	fprintf(stderr, "Usage: %s [options]\n", __progname);
#endif
	fprintf(stderr, "\n");
	fprintf(stderr, "Available options:\n");
#if !defined(KORE_SINGLE_BINARY)
	fprintf(stderr, "\t-c\tconfiguration to use\n");
#endif
#if defined(KORE_DEBUG)
	fprintf(stderr, "\t-d\trun with debug on\n");
#endif
	fprintf(stderr, "\t-f\tstart in foreground\n");
	fprintf(stderr, "\t-h\tthis help text\n");
	fprintf(stderr, "\t-n\tdo not chroot\n");
	fprintf(stderr, "\t-r\tdo not drop privileges\n");
	fprintf(stderr, "\t-v\tdisplay kore build information\n");

#if !defined(KORE_SINGLE_BINARY)
	kore_cli_usage(0);
#else
	fprintf(stderr, "\nbuilt with https://kore.io\n");
	exit(1);
#endif
}

static void
version(void)
{
	printf("%d.%d.%d-%s ", KORE_VERSION_MAJOR, KORE_VERSION_MINOR,
	    KORE_VERSION_PATCH, KORE_VERSION_STATE);
#if defined(KORE_NO_TLS)
	printf("no-tls ");
#endif
#if defined(KORE_NO_HTTP)
	printf("no-http ");
#endif
#if defined(KORE_USE_PGSQL)
	printf("pgsql ");
#endif
#if defined(KORE_USE_TASKS)
	printf("tasks ");
#endif
#if defined(KORE_DEBUG)
	printf("debug ");
#endif
#if defined(KORE_SINGLE_BINARY)
	printf("single ");
#endif
	printf("\n");

	exit(0);
}

int
main(int argc, char *argv[])
{
	int		ch, flags;

	flags = 0;

#if !defined(KORE_SINGLE_BINARY)
	while ((ch = getopt(argc, argv, "c:dfhnrv")) != -1) {
#else
	while ((ch = getopt(argc, argv, "dfhnrv")) != -1) {
#endif
		flags++;
		switch (ch) {
#if !defined(KORE_SINGLE_BINARY)
		case 'c':
			config_file = optarg;
			break;
#endif
#if defined(KORE_DEBUG)
		case 'd':
			kore_debug = 1;
			break;
#endif
		case 'f':
			foreground = 1;
			break;
		case 'h':
			usage();
			break;
		case 'n':
			skip_chroot = 1;
			break;
		case 'r':
			skip_runas = 1;
			break;
		case 'v':
			version();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	kore_mem_init();

#if !defined(KORE_SINGLE_BINARY)
	if (argc > 0) {
		if (flags)
			fatal("You cannot specify kore flags and a command");
		return (kore_cli_main(argc, argv));
	}
#endif

	kore_pid = getpid();
	nlisteners = 0;
	LIST_INIT(&listeners);

	kore_log_init();
#if !defined(KORE_NO_HTTP)
	kore_auth_init();
	kore_validator_init();
#endif
	kore_domain_init();
	kore_module_init();
	kore_server_sslstart();

#if !defined(KORE_SINGLE_BINARY)
	if (config_file == NULL)
		usage();
#else
	kore_module_load(NULL, NULL);
#endif

	kore_parse_config();
	kore_platform_init();

#if !defined(KORE_NO_HTTP)
	kore_accesslog_init();
	if (http_body_disk_offload > 0) {
		if (mkdir(http_body_disk_path, 0700) == -1 && errno != EEXIST) {
			printf("can't create http_body_disk_path '%s': %s\n",
			    http_body_disk_path, errno_s);
			return (KORE_RESULT_ERROR);
		}
	}
#endif

	sig_recv = 0;
	signal(SIGHUP, kore_signal);
	signal(SIGQUIT, kore_signal);
	signal(SIGTERM, kore_signal);

	if (foreground)
		signal(SIGINT, kore_signal);
	else
		signal(SIGINT, SIG_IGN);

	kore_server_start();

	kore_log(LOG_NOTICE, "server shutting down");
	kore_worker_shutdown();

	if (!foreground)
		unlink(kore_pidfile);

	kore_listener_cleanup();
	kore_log(LOG_NOTICE, "goodbye");

	return (0);
}

#if !defined(KORE_NO_TLS)
int
kore_tls_sni_cb(SSL *ssl, int *ad, void *arg)
{
	struct kore_domain	*dom;
	const char		*sname;

	sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	kore_debug("kore_tls_sni_cb(): received host %s", sname);

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

void
kore_tls_info_callback(const SSL *ssl, int flags, int ret)
{
	struct connection	*c;

	if (flags & SSL_CB_HANDSHAKE_START) {
		if ((c = SSL_get_app_data(ssl)) == NULL)
			fatal("no SSL_get_app_data");
		c->tls_reneg++;
	}
}
#endif

int
kore_server_bind(const char *ip, const char *port, const char *ccb)
{
	struct listener		*l;
	int			on, r;
	struct addrinfo		hints, *results;

	kore_debug("kore_server_bind(%s, %s)", ip, port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	r = getaddrinfo(ip, port, &hints, &results);
	if (r != 0)
		fatal("getaddrinfo(%s): %s", ip, gai_strerror(r));

	l = kore_malloc(sizeof(struct listener));
	l->type = KORE_TYPE_LISTENER;
	l->addrtype = results->ai_family;

	if (l->addrtype != AF_INET && l->addrtype != AF_INET6)
		fatal("getaddrinfo(): unknown address family %d", l->addrtype);

	if ((l->fd = socket(results->ai_family, SOCK_STREAM, 0)) == -1) {
		kore_free(l);
		freeaddrinfo(results);
		kore_debug("socket(): %s", errno_s);
		printf("failed to create socket: %s\n", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_connection_nonblock(l->fd, 1)) {
		kore_free(l);
		freeaddrinfo(results);
		printf("failed to make socket non blocking: %s\n", errno_s);
		return (KORE_RESULT_ERROR);
	}

	on = 1;
	if (setsockopt(l->fd, SOL_SOCKET,
	    SO_REUSEADDR, (const char *)&on, sizeof(on)) == -1) {
		close(l->fd);
		kore_free(l);
		freeaddrinfo(results);
		kore_debug("setsockopt(): %s", errno_s);
		printf("failed to set SO_REUSEADDR: %s\n", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (bind(l->fd, results->ai_addr, results->ai_addrlen) == -1) {
		close(l->fd);
		kore_free(l);
		freeaddrinfo(results);
		kore_debug("bind(): %s", errno_s);
		printf("failed to bind to %s port %s: %s\n", ip, port, errno_s);
		return (KORE_RESULT_ERROR);
	}

	freeaddrinfo(results);

	if (listen(l->fd, kore_socket_backlog) == -1) {
		close(l->fd);
		kore_free(l);
		kore_debug("listen(): %s", errno_s);
		printf("failed to listen on socket: %s\n", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (ccb != NULL) {
		*(void **)&(l->connect) = kore_module_getsym(ccb);
		if (l->connect == NULL) {
			printf("no such callback: '%s'\n", ccb);
			close(l->fd);
			kore_free(l);
			return (KORE_RESULT_ERROR);
		}
	} else {
		l->connect = NULL;
	}

	nlisteners++;
	LIST_INSERT_HEAD(&listeners, l, list);

	if (foreground) {
#if !defined(KORE_NO_TLS)
		kore_log(LOG_NOTICE, "running on https://%s:%s", ip, port);
#else
		kore_log(LOG_NOTICE, "running on http://%s:%s", ip, port);
#endif
	}

	return (KORE_RESULT_OK);
}

void
kore_listener_cleanup(void)
{
	struct listener		*l;

	while (!LIST_EMPTY(&listeners)) {
		l = LIST_FIRST(&listeners);
		LIST_REMOVE(l, list);
		close(l->fd);
		kore_free(l);
	}
}

void
kore_signal(int sig)
{
	sig_recv = sig;
}

static void
kore_server_sslstart(void)
{
#if !defined(KORE_NO_TLS)
	kore_debug("kore_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
#endif
}

static void
kore_server_start(void)
{
	u_int32_t	tmp;
	int		quit;
#if defined(KORE_SINGLE_BINARY)
	void		(*preload)(void);
#endif

	if (foreground == 0 && daemon(1, 1) == -1)
		fatal("cannot daemon(): %s", errno_s);

	kore_pid = getpid();
	if (!foreground)
		kore_write_kore_pid();

	kore_log(LOG_NOTICE, "%s is starting up", __progname);
#if defined(KORE_USE_PGSQL)
	kore_log(LOG_NOTICE, "pgsql built-in enabled");
#endif
#if defined(KORE_USE_TASKS)
	kore_log(LOG_NOTICE, "tasks built-in enabled");
#endif
#if defined(KORE_USE_JSONRPC)
	kore_log(LOG_NOTICE, "jsonrpc built-in enabled");
#endif
#if defined(KORE_SINGLE_BINARY)
	*(void **)&(preload) = kore_module_getsym("kore_preload");
	if (preload != NULL)
		preload();
#endif

	kore_platform_proctitle("kore [parent]");
	kore_msg_init();
	kore_worker_init();

	/* Set worker_max_connections for kore_connection_init(). */
	tmp = worker_max_connections;
	worker_max_connections = worker_count;

	net_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_parent_init();

	quit = 0;
	worker_max_connections = tmp;
	while (quit != 1) {
		if (sig_recv != 0) {
			switch (sig_recv) {
			case SIGHUP:
#if !defined(KORE_SINGLE_BINARY)
				kore_worker_dispatch_signal(sig_recv);
				kore_module_reload(0);
#endif
				break;
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				quit = 1;
				kore_worker_dispatch_signal(sig_recv);
				continue;
			default:
				kore_log(LOG_NOTICE,
				    "no action taken for signal %d", sig_recv);
				break;
			}

			sig_recv = 0;
		}

		kore_worker_wait(0);
		kore_platform_event_wait(100);
		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	}

	kore_platform_event_cleanup();
	kore_connection_cleanup();
	kore_domain_cleanup();
	net_cleanup();
}

static void
kore_write_kore_pid(void)
{
	FILE		*fp;

	if ((fp = fopen(kore_pidfile, "w+")) == NULL) {
		printf("warning: couldn't write pid to %s (%s)\n",
		    kore_pidfile, errno_s);
	} else {
		fprintf(fp, "%d\n", kore_pid);
		fclose(fp);
	}
}
