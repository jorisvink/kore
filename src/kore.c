/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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

#include <libgen.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <signal.h>

#include "kore.h"
#include "hooks.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#if defined(KORE_USE_CURL)
#include "curl.h"
#endif

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

#if defined(KORE_USE_ACME)
#include "acme.h"
#endif

volatile sig_atomic_t	sig_recv;
struct kore_server_list	kore_servers;
u_int8_t		nlisteners;
int			kore_argc = 0;
pid_t			kore_pid = -1;
u_int16_t		cpu_count = 1;
int			kore_quiet = 0;
int			skip_runas = 0;
int			skip_chroot = 0;
u_int8_t		worker_count = 0;
char			**kore_argv = NULL;
int			kore_foreground = 0;
char			*kore_progname = NULL;
u_int32_t		kore_socket_backlog = 5000;
int			kore_quit = KORE_QUIT_NONE;
char			*kore_pidfile = KORE_PIDFILE_DEFAULT;

struct kore_privsep	worker_privsep;

extern char		**environ;
extern char		*__progname;
static size_t		proctitle_maxlen = 0;

static void	usage(void);
static void	version(void);

static void	kore_write_kore_pid(void);
static void	kore_proctitle_setup(void);
static void	kore_server_shutdown(void);
static void	kore_server_start(int, char *[]);
static void	kore_call_parent_configure(int, char **);

#if !defined(KORE_SINGLE_BINARY) && defined(KORE_USE_PYTHON)
static const char	*parent_config_hook = KORE_PYTHON_CONFIG_HOOK;
static const char	*parent_teardown_hook = KORE_PYTHON_TEARDOWN_HOOK;
#else
static const char	*parent_config_hook = KORE_CONFIG_HOOK;
static const char	*parent_teardown_hook = KORE_TEARDOWN_HOOK;
#if defined(KORE_SINGLE_BINARY)
static const char	*parent_daemonized_hook = KORE_DAEMONIZED_HOOK;
#endif
#endif

static void
usage(void)
{
#if defined(KORE_USE_PYTHON)
	printf("Usage: %s [options] [app | app.py]\n", __progname);
#else
	printf("Usage: %s [options]\n", __progname);
#endif

	printf("\n");
	printf("Available options:\n");
#if !defined(KORE_SINGLE_BINARY)
	printf("\t-c\tconfiguration to use\n");
#endif
#if defined(KORE_DEBUG)
	printf("\t-d\trun with debug on\n");
#endif
	printf("\t-f\tstart in foreground\n");
	printf("\t-h\tthis help text\n");
	printf("\t-n\tdo not chroot on any worker\n");
	printf("\t-q\tonly log errors\n");
	printf("\t-r\tdo not change user on any worker\n");
	printf("\t-v\tdisplay %s build information\n", __progname);

	printf("\nFind more information on https://kore.io\n");

	exit(1);
}

static void
version(void)
{
	printf("%s ", kore_version);
#if defined(KORE_NO_HTTP)
	printf("no-http ");
#endif
#if defined(KORE_USE_CURL)
	printf("curl-%s ", LIBCURL_VERSION);
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
#if defined(KORE_USE_PYTHON)
	printf("python-%s ", PY_VERSION);
#endif
#if defined(KORE_USE_ACME)
	printf("acme ");
#endif
	if (!kore_tls_supported())
		printf("notls ");
	printf("\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	struct kore_runtime_call	*rcall;
#if !defined(KORE_SINGLE_BINARY) && defined(KORE_USE_PYTHON)
	struct stat			st;
#endif

	kore_argc = argc;
	kore_argv = argv;

#if !defined(KORE_SINGLE_BINARY)
	kore_default_getopt(argc, argv);
#endif

	kore_mem_init();
	kore_msg_init();
	kore_log_init();

	kore_progname = kore_strdup(argv[0]);
	kore_proctitle_setup();

#if !defined(KORE_SINGLE_BINARY)
	argc -= optind;
	argv += optind;
#endif

#if !defined(KORE_SINGLE_BINARY) && defined(KORE_USE_PYTHON)
	if (argc > 0) {
		kore_pymodule = argv[0];
		argc--;
		argv++;
	} else {
		kore_pymodule = NULL;
	}

	if (kore_pymodule) {
		if (lstat(kore_pymodule, &st) == -1) {
			fatal("failed to stat '%s': %s",
			    kore_pymodule, errno_s);
		}

		if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
			fatal("%s: not a directory or file", kore_pymodule);
	}
#endif

	kore_pid = getpid();
	nlisteners = 0;
	LIST_INIT(&kore_servers);

	kore_platform_init();
#if !defined(KORE_NO_HTTP)
	http_parent_init();
#if defined(KORE_USE_CURL)
	kore_curl_sysinit();
#endif
#if defined(KORE_USE_PGSQL)
	kore_pgsql_sys_init();
#endif
	kore_auth_init();
	kore_validator_init();
	kore_filemap_init();
#endif
#if defined(KORE_USE_ACME)
	kore_acme_init();
#endif
	kore_domain_init();
	kore_module_init();
	kore_tls_init();

#if !defined(KORE_SINGLE_BINARY) && !defined(KORE_USE_PYTHON)
	if (config_file == NULL)
		usage();
#endif
	kore_module_load(NULL, NULL, KORE_MODULE_NATIVE);

#if defined(KORE_USE_PYTHON)
	kore_python_init();
#if !defined(KORE_SINGLE_BINARY)
	if (kore_pymodule) {
		kore_module_load(kore_pymodule, NULL, KORE_MODULE_PYTHON);
		if (S_ISDIR(st.st_mode) && chdir(kore_pymodule) == -1)
			fatal("chdir(%s): %s", kore_pymodule, errno_s);
	} else {
		/* swap back to non-python hooks. */
		parent_config_hook = KORE_CONFIG_HOOK;
		parent_teardown_hook = KORE_TEARDOWN_HOOK;
	}
#endif
#endif

#if defined(KORE_SINGLE_BINARY)
	kore_call_parent_configure(argc, argv);
#endif

#if defined(KORE_USE_PYTHON) && !defined(KORE_SINGLE_BINARY)
	if (kore_pymodule)
		kore_call_parent_configure(argc, argv);
#endif

	kore_parse_config();

#if !defined(KORE_SINGLE_BINARY)
	free(config_file);
#endif

#if !defined(KORE_NO_HTTP)
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
	kore_server_shutdown();

	rcall = kore_runtime_getcall(parent_teardown_hook);
	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}

	if (unlink(kore_pidfile) == -1 && errno != ENOENT)
		kore_log(LOG_NOTICE, "failed to remove pidfile (%s)", errno_s);

	kore_server_cleanup();

	if (!kore_quiet)
		kore_log(LOG_INFO, "goodbye");

#if defined(KORE_USE_PYTHON)
	kore_python_cleanup();
#endif

	kore_mem_cleanup();

	return (kore_quit);
}

void
kore_default_getopt(int argc, char **argv)
{
	int		ch;

#if !defined(KORE_SINGLE_BINARY)
	while ((ch = getopt(argc, argv, "c:fhnqrv")) != -1) {
#else
	while ((ch = getopt(argc, argv, "fhnqrv")) != -1) {
#endif
		switch (ch) {
#if !defined(KORE_SINGLE_BINARY)
		case 'c':
			free(config_file);
			if ((config_file = strdup(optarg)) == NULL)
				fatal("strdup");
			break;
#endif
		case 'f':
			kore_foreground = 1;
			break;
		case 'h':
			usage();
			break;
		case 'n':
			skip_chroot = 1;
			break;
		case 'q':
			kore_quiet = 1;
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
}

int
kore_server_bind(struct kore_server *srv, const char *ip, const char *port,
    const char *ccb)
{
	int			r;
	struct listener		*l;
	struct addrinfo		hints, *results;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	r = getaddrinfo(ip, port, &hints, &results);
	if (r != 0)
		fatal("getaddrinfo(%s): %s", ip, gai_strerror(r));

	l = kore_listener_create(srv);
	l->host = kore_strdup(ip);
	l->port = kore_strdup(port);

	if (!kore_listener_init(l, results->ai_family, ccb)) {
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

	return (KORE_RESULT_OK);
}

int
kore_server_bind_unix(struct kore_server *srv, const char *path,
    const char *ccb)
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
	socklen = sizeof(sun.sun_family) + len;
#else
	socklen = sizeof(sun);
#endif

	l = kore_listener_create(srv);
	l->host = kore_strdup(path);

	if (!kore_listener_init(l, AF_UNIX, ccb))
		return (KORE_RESULT_ERROR);

	if (sun.sun_path[0] != '\0') {
		if (unlink(sun.sun_path) == -1 && errno != ENOENT) {
			kore_log(LOG_ERR, "unlink: %s: %s",
			    sun.sun_path, errno_s);
			kore_listener_free(l);
			return (KORE_RESULT_ERROR);
		}
	}

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

	return (KORE_RESULT_OK);
}

struct kore_server *
kore_server_create(const char *name)
{
	struct kore_server	*srv;

	srv = kore_calloc(1, sizeof(struct kore_server));
	srv->name = kore_strdup(name);

	if (kore_tls_supported())
		srv->tls = 1;
	else
		srv->tls = 0;

	TAILQ_INIT(&srv->domains);
	LIST_INIT(&srv->listeners);

	LIST_INSERT_HEAD(&kore_servers, srv, list);

	return (srv);
}

void
kore_server_finalize(struct kore_server *srv)
{
	struct listener		*l;
	const char		*proto;

	if (kore_quiet)
		return;

	LIST_FOREACH(l, &srv->listeners, list) {
		if (srv->tls)
			proto = "https";
		else
			proto = "http";

		if (l->family == AF_UNIX) {
			kore_log(LOG_INFO, "%s serving %s on %s",
			    srv->name, proto, l->host);
		} else {
			kore_log(LOG_INFO, "%s serving %s on %s:%s",
			    srv->name, proto, l->host, l->port);
		}
	}
}

struct listener *
kore_listener_create(struct kore_server *server)
{
	struct listener		*l;

	l = kore_calloc(1, sizeof(struct listener));

	nlisteners++;
	LIST_INSERT_HEAD(&server->listeners, l, list);

	l->server = server;

	l->fd = -1;
	l->evt.type = KORE_TYPE_LISTENER;
	l->evt.handle = kore_listener_accept;

	return (l);
}

struct kore_server *
kore_server_lookup(const char *name)
{
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		if (!strcmp(srv->name, name))
			return (srv);
	}

	return (NULL);
}

int
kore_listener_init(struct listener *l, int family, const char *ccb)
{
	switch (family) {
	case AF_INET:
	case AF_INET6:
	case AF_UNIX:
		break;
	default:
		fatal("unknown address family %d", family);
	}

	l->family = family;

	if ((l->fd = socket(family, SOCK_STREAM, 0)) == -1) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "socket(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (fcntl(l->fd, F_SETFD, FD_CLOEXEC) == -1) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "fcntl(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_connection_nonblock(l->fd, family != AF_UNIX)) {
		kore_listener_free(l);
		kore_log(LOG_ERR, "kore_connection_nonblock(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_sockopt(l->fd, SOL_SOCKET, SO_REUSEADDR)) {
		kore_listener_free(l);
		return (KORE_RESULT_ERROR);
	}

	if (ccb != NULL) {
		if ((l->connect = kore_runtime_getcall(ccb)) == NULL) {
			kore_log(LOG_ERR, "no such callback: '%s'", ccb);
			kore_listener_free(l);
			return (KORE_RESULT_ERROR);
		}
	} else {
		l->connect = NULL;
	}

	return (KORE_RESULT_OK);
}

void
kore_server_free(struct kore_server *srv)
{
	struct listener		*l;
	struct kore_domain	*dom;

	LIST_REMOVE(srv, list);

	while ((dom = TAILQ_FIRST(&srv->domains)) != NULL)
		kore_domain_free(dom);

	while ((l = LIST_FIRST(&srv->listeners)) != NULL)
		kore_listener_free(l);

	kore_free(srv->name);
	kore_free(srv);
}

void
kore_listener_free(struct listener *l)
{
	int	rm;

	LIST_REMOVE(l, list);

	if (l->fd != -1)
		close(l->fd);

	rm = 0;

#if defined(__linux__)
	if (worker == NULL && l->family == AF_UNIX && l->host[0] != '@')
		rm++;
#else
	if (worker == NULL && l->family == AF_UNIX)
		rm++;
#endif
	if (rm) {
		if (unlink(l->host) == -1) {
			kore_log(LOG_NOTICE,
			    "failed to remove unix socket %s (%s)", l->host,
			    errno_s);
		}
	}

	kore_free(l->host);
	kore_free(l->port);

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
	kore_signal_trap(SIGHUP);
	kore_signal_trap(SIGQUIT);
	kore_signal_trap(SIGTERM);
	kore_signal_trap(SIGUSR1);
	kore_signal_trap(SIGCHLD);

	if (kore_foreground)
		kore_signal_trap(SIGINT);
	else
		(void)signal(SIGINT, SIG_IGN);

	(void)signal(SIGPIPE, SIG_IGN);
}

void
kore_signal_trap(int sig)
{
	struct sigaction	sa;

	sig_recv = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = kore_signal;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

void
kore_server_closeall(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list)
			l->fd = -1;
	}
}

void
kore_server_cleanup(void)
{
	struct kore_server	*srv;

	while ((srv = LIST_FIRST(&kore_servers)) != NULL)
		kore_server_free(srv);
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

void
kore_proctitle(const char *title)
{
	int	len;

	kore_argv[1] = NULL;

	len = snprintf(kore_argv[0], proctitle_maxlen, "%s %s",
	    basename(kore_progname), title);
	if (len == -1 || (size_t)len >= proctitle_maxlen)
		fatal("proctitle '%s' too large", title);

	memset(kore_argv[0] + len, 0, proctitle_maxlen - len);
}

static void
kore_proctitle_setup(void)
{
	int		i;
	char		*p;

	proctitle_maxlen = 0;

	for (i = 0; environ[i] != NULL; i++) {
		if ((p = strdup(environ[i])) == NULL)
			fatal("strdup");
		proctitle_maxlen += strlen(environ[i]) + 1;
		environ[i] = p;
	}

	for (i = 0; kore_argv[i] != NULL; i++)
		proctitle_maxlen += strlen(kore_argv[i]) + 1;
}

static void
kore_server_start(int argc, char *argv[])
{
	u_int32_t			tmp;
	struct kore_server		*srv;
	u_int64_t			netwait;
	int				last_sig;
#if !defined(KORE_NO_HTTP)
	int				alog;
	struct kore_domain		*dom;
#endif
#if defined(KORE_SINGLE_BINARY)
	struct kore_runtime_call	*rcall;
#endif

	if (!kore_quiet) {
		kore_log(LOG_INFO, "%s %s starting, built=%s",
		    __progname, kore_version, kore_build_date);
		kore_log(LOG_INFO, "built-ins: "
#if defined(__linux__)
		    "seccomp "
#endif
#if defined(KORE_USE_PGSQL)
		    "pgsql "
#endif
#if defined(KORE_USE_TASKS)
		    "tasks "
#endif
#if defined(KORE_USE_JSONRPC)
		    "jsonrpc "
#endif
#if defined(KORE_USE_PYTHON)
		    "python "
#endif
#if defined(KORE_USE_ACME)
		    "acme "
#endif
#if defined(KORE_USE_CURL)
		    "curl "
#endif
		);
	}

	if (kore_foreground == 0) {
		if (daemon(1, 0) == -1)
			fatal("cannot daemon(): %s", errno_s);
#if defined(KORE_SINGLE_BINARY)
		rcall = kore_runtime_getcall(parent_daemonized_hook);
		if (rcall != NULL) {
			kore_runtime_execute(rcall);
			kore_free(rcall);
		}
#endif
	}

	kore_pid = getpid();
	kore_write_kore_pid();

#if !defined(KORE_SINGLE_BINARY) && !defined(KORE_USE_PYTHON)
	kore_call_parent_configure(argc, argv);
#endif

#if defined(KORE_USE_PYTHON) && !defined(KORE_SINGLE_BINARY)
	if (kore_pymodule == NULL)
		kore_call_parent_configure(argc, argv);
#endif

#if defined(KORE_USE_PYTHON)
	kore_python_routes_resolve();
#endif

	/* Check if keymgr will be active. */
	if (kore_tls_supported()) {
		LIST_FOREACH(srv, &kore_servers, list) {
			if (srv->tls) {
				kore_keymgr_active = 1;
				break;
			}
		}
	} else {
		kore_keymgr_active = 0;
	}

	kore_platform_proctitle("[parent]");

	if (!kore_worker_init()) {
		kore_log(LOG_ERR, "last worker log lines:");
		kore_log(LOG_ERR, "=====================================");
		net_init();
		kore_connection_init();
		kore_platform_event_init();
		kore_msg_parent_init();
		kore_platform_event_wait(10);
		kore_worker_dispatch_signal(SIGQUIT);
		kore_log(LOG_ERR, "=====================================");
		return;
	}

	/* Set worker_max_connections for kore_connection_init(). */
	tmp = worker_max_connections;
	worker_max_connections = worker_count;

	net_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_parent_init();

	worker_max_connections = tmp;

	kore_timer_init();

#if !defined(KORE_NO_HTTP)
	alog = 0;

	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			if (dom->accesslog != -1)
				alog = 1;
		}
	}

	if (alog) {
		kore_timer_add(kore_accesslog_run, 100, NULL, 0);
		kore_log(LOG_INFO, "accesslog vacuum is enabled");
	}
#endif

#if defined(KORE_USE_PYTHON)
	kore_msg_unregister(KORE_PYTHON_SEND_OBJ);
#endif

	while (kore_quit == KORE_QUIT_NONE) {
		last_sig = sig_recv;

		if (last_sig != 0) {
			switch (last_sig) {
			case SIGHUP:
				kore_worker_dispatch_signal(last_sig);
				kore_module_reload(0);
				break;
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				kore_quit = KORE_QUIT_NORMAL;
				kore_worker_dispatch_signal(last_sig);
				continue;
			case SIGUSR1:
				kore_worker_dispatch_signal(last_sig);
				break;
			case SIGCHLD:
				kore_worker_reap();
				break;
			default:
				break;
			}

			if (sig_recv == last_sig)
				sig_recv = 0;
			else
				continue;
		}

		netwait = kore_timer_next_run(kore_time_ms());
		kore_platform_event_wait(netwait);
		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
		kore_timer_run(kore_time_ms());
		kore_worker_reap();
	}

	kore_worker_dispatch_signal(SIGQUIT);
}

static void
kore_server_shutdown(void)
{
	if (!kore_quiet)
		kore_log(LOG_INFO, "server shutting down");

	kore_worker_shutdown();

#if !defined(KORE_NO_HTTP)
	kore_accesslog_gather(NULL, kore_time_ms(), 1);
#endif

	kore_platform_event_cleanup();
	kore_connection_cleanup();
	kore_domain_cleanup();
	kore_tls_cleanup();
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

static void
kore_call_parent_configure(int argc, char **argv)
{
	struct kore_runtime_call	*rcall;

	rcall = kore_runtime_getcall(parent_config_hook);
	if (rcall != NULL) {
		kore_runtime_configure(rcall, argc, argv);
		kore_free(rcall);
	}
}
