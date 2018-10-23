/*
 * Copyright (c) 2013-2018 Joris Vink <joris@coders.se>
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
#include <sys/un.h>

#include <sys/socket.h>
#include <sys/resource.h>

#include <stdio.h>
#include <netdb.h>
#include <signal.h>

#include "kore.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

volatile sig_atomic_t	sig_recv;
struct listener_head	listeners;
u_int8_t		nlisteners;
pid_t			kore_pid = -1;
u_int16_t		cpu_count = 1;
int			foreground = 0;
int			kore_debug = 0;
int			skip_runas = 0;
int			skip_chroot = 0;
u_int8_t		worker_count = 0;
char			*kore_root_path = NULL;
char			*kore_runas_user = NULL;
u_int32_t		kore_socket_backlog = 5000;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;
char			*kore_tls_cipher_list = KORE_DEFAULT_CIPHER_LIST;

extern char		*__progname;

static void	usage(void);
static void	version(void);
static void	kore_write_kore_pid(void);
static void	kore_server_sslstart(void);
static void	kore_server_start(int, char *[]);

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", __progname);

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
	fprintf(stderr, "\t-v\tdisplay %s build information\n", __progname);

#if !defined(KORE_SINGLE_BINARY)
	fprintf(stderr, "\nFind more information on https://kore.io\n");
#else
	fprintf(stderr, "\nBuilt using https://kore.io\n");
#endif

	exit(1);
}

static void
version(void)
{
	printf("%s ", kore_version);
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
#if defined(KORE_USE_PYTHON)
	printf("python ");
#endif
	printf("\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	struct kore_runtime_call	*rcall;
	int				ch, flags;

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
	if (argc > 0)
		fatal("did you mean to run `kodev' instead?");
#endif

	kore_pid = getpid();
	nlisteners = 0;
	LIST_INIT(&listeners);

	kore_log_init();
#if defined(KORE_USE_PYTHON)
	kore_python_init();
#endif
#if !defined(KORE_NO_HTTP)
	http_parent_init();
	kore_auth_init();
	kore_validator_init();
	kore_filemap_init();
#endif
	kore_domain_init();
	kore_module_init();
	kore_server_sslstart();

#if !defined(KORE_SINGLE_BINARY)
	if (config_file == NULL)
		usage();
#endif
	kore_module_load(NULL, NULL, KORE_MODULE_NATIVE);
	kore_parse_config();

#if defined(KORE_SINGLE_BINARY)
	rcall = kore_runtime_getcall("kore_parent_configure");
	if (rcall != NULL) {
		kore_runtime_configure(rcall, argc, argv);
		kore_free(rcall);
	}
#endif

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

	kore_signal_setup();
	kore_server_start(argc, argv);

	kore_log(LOG_NOTICE, "server shutting down");
	kore_worker_shutdown();

	rcall = kore_runtime_getcall("kore_parent_teardown");
	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}

	if (unlink(kore_pidfile) == -1 && errno != ENOENT)
		kore_log(LOG_NOTICE, "failed to remove pidfile (%s)", errno_s);

	kore_listener_cleanup();
	kore_log(LOG_NOTICE, "goodbye");

#if defined(KORE_USE_PYTHON)
	kore_python_cleanup();
#endif

	kore_mem_cleanup();

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
		if (dom->ssl_ctx == NULL) {
			kore_log(LOG_NOTICE,
			    "TLS configuration for %s not complete",
			    dom->domain);
			return (SSL_TLSEXT_ERR_NOACK);
		}

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
	int			r;
	struct listener		*l;
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

	if ((l = kore_listener_alloc(results->ai_family, ccb)) == NULL) {
		freeaddrinfo(results);
		return (KORE_RESULT_ERROR);
	}

	if (bind(l->fd, results->ai_addr, results->ai_addrlen) == -1) {
		kore_listener_free(l);
		freeaddrinfo(results);
		kore_log(LOG_ERR, "bind(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	freeaddrinfo(results);

	if (listen(l->fd, kore_socket_backlog) == -1) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "listen(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (foreground) {
#if !defined(KORE_NO_TLS)
		kore_log(LOG_NOTICE, "running on https://%s:%s", ip, port);
#else
		kore_log(LOG_NOTICE, "running on http://%s:%s", ip, port);
#endif
	}

	return (KORE_RESULT_OK);
}

int
kore_server_bind_unix(const char *path, const char *ccb)
{
	struct listener		*l;
	int			len;
	struct sockaddr_un	sun;
	socklen_t		socklen;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
	if (len == -1 || (size_t)len >= sizeof(sun.sun_path)) {
		kore_log(LOG_ERR, "unix socket path '%s' too long", path);
		return (KORE_RESULT_ERROR);
	}

#if defined(__linux__)
	if (sun.sun_path[0] == '@')
		sun.sun_path[0] = '\0';
#endif

	socklen = sizeof(sun.sun_family) + len;

	if ((l = kore_listener_alloc(AF_UNIX, ccb)) == NULL)
		return (KORE_RESULT_ERROR);

	if (bind(l->fd, (struct sockaddr *)&sun, socklen) == -1) {
		kore_log(LOG_ERR, "bind: %s", errno_s);
		kore_listener_free(l);
		return (KORE_RESULT_ERROR);
	}

	if (listen(l->fd, kore_socket_backlog) == -1) {
		kore_log(LOG_ERR, "listen(): %s", errno_s);
		kore_listener_free(l);
		return (KORE_RESULT_ERROR);
	}

	if (foreground)
		kore_log(LOG_NOTICE, "running on %s", path);

	return (KORE_RESULT_OK);
}

struct listener *
kore_listener_alloc(int family, const char *ccb)
{
	struct listener		*l;

	switch (family) {
	case AF_INET:
	case AF_INET6:
	case AF_UNIX:
		break;
	default:
		fatal("unknown address family %d", family);
	}

	l = kore_calloc(1, sizeof(struct listener));

	nlisteners++;
	LIST_INSERT_HEAD(&listeners, l, list);

	l->fd = -1;
	l->family = family;

	l->evt.type = KORE_TYPE_LISTENER;
	l->evt.handle = kore_listener_accept;

	if ((l->fd = socket(family, SOCK_STREAM, 0)) == -1) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "socket(): %s", errno_s);
		return (NULL);
	}

	if (!kore_connection_nonblock(l->fd, family != AF_UNIX)) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "kore_connection_nonblock(): %s", errno_s);
		return (NULL);
	}

	if (!kore_sockopt(l->fd, SOL_SOCKET, SO_REUSEADDR)) {
		kore_listener_free(l);
		return (NULL);
	}

	if (ccb != NULL) {
		if ((l->connect = kore_runtime_getcall(ccb)) == NULL) {
			kore_log(LOG_ERR, "no such callback: '%s'", ccb);
			kore_listener_free(l);
			return (NULL);
		}
	} else {
		l->connect = NULL;
	}

	return (l);
}

void
kore_listener_free(struct listener *l)
{
	LIST_REMOVE(l, list);

	if (l->fd != -1)
		close(l->fd);

	kore_free(l);
}

void
kore_listener_accept(void *arg, int error)
{
	struct connection	*c;
	struct listener		*l = arg;
	u_int32_t		accepted;

	if (error)
		fatal("error on listening socket");

	if (!(l->evt.flags & KORE_EVENT_READ))
		return;

	accepted = 0;

	while (worker_active_connections < worker_max_connections) {
		if (worker_accept_threshold != 0 &&
		    accepted >= worker_accept_threshold) {
			kore_worker_make_busy();
			break;
		}

		if (!kore_connection_accept(l, &c))
			break;

		if (c == NULL)
			break;

		accepted++;
		kore_platform_event_all(c->fd, c);
	}
}

int
kore_sockopt(int fd, int what, int opt)
{
	int		on;

	on = 1;
	if (setsockopt(fd, what, opt, (const char *)&on, sizeof(on)) == -1) {
		kore_log(LOG_ERR, "setsockopt(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

void
kore_signal_setup(void)
{
	struct sigaction	sa;

	sig_recv = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = kore_signal;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(SIGHUP, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);

	if (foreground) {
		if (sigaction(SIGINT, &sa, NULL) == -1)
			fatal("sigaction: %s", errno_s);
	} else {
		(void)signal(SIGINT, SIG_IGN);
	}

	(void)signal(SIGPIPE, SIG_IGN);
}

void
kore_listener_cleanup(void)
{
	struct listener		*l;

	while (!LIST_EMPTY(&listeners)) {
		l = LIST_FIRST(&listeners);
		kore_listener_free(l);
	}
}

void
kore_signal(int sig)
{
	sig_recv = sig;
}

void
kore_shutdown(void)
{
	if (worker != NULL) {
		kore_msg_send(KORE_MSG_PARENT, KORE_MSG_SHUTDOWN, NULL, 0);
		return;
	}

	fatal("kore_shutdown: called from parent");
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
kore_server_start(int argc, char *argv[])
{
	u_int32_t			tmp;
	int				quit;
	struct kore_runtime_call	*rcall;

	if (foreground == 0) {
		if (daemon(1, 0) == -1)
			fatal("cannot daemon(): %s", errno_s);
#if defined(KORE_SINGLE_BINARY)
		rcall = kore_runtime_getcall("kore_parent_daemonized");
		if (rcall != NULL) {
			kore_runtime_execute(rcall);
			kore_free(rcall);
		}
#endif
	}

	kore_pid = getpid();
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
#if defined(KORE_USE_PYTHON)
	kore_log(LOG_NOTICE, "python built-in enabled");
#endif
#if !defined(KORE_SINGLE_BINARY)
	rcall = kore_runtime_getcall("kore_parent_configure");
	if (rcall != NULL) {
		kore_runtime_configure(rcall, argc, argv);
		kore_free(rcall);
	}
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
				kore_worker_dispatch_signal(sig_recv);
				kore_module_reload(0);
				break;
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				quit = 1;
				kore_worker_dispatch_signal(sig_recv);
				continue;
			case SIGUSR1:
				kore_worker_dispatch_signal(sig_recv);
				break;
			default:
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
