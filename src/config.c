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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

#if defined(KORE_USE_CURL)
#include "curl.h"
#endif

#if defined(KORE_USE_ACME)
#include "acme.h"
#endif

#if defined(__linux__)
#include "seccomp.h"
#endif

/* XXX - This is becoming a clusterfuck. Fix it. */

static int	configure_load(char *);
static char	*configure_resolve_var(char *);
static void	configure_check_var(char **, const char *, const char *);

#if defined(KORE_SINGLE_BINARY)
static FILE		*config_file_write(void);
extern u_int8_t		asset_builtin_kore_conf[];
extern u_int32_t	asset_len_builtin_kore_conf;
#elif defined(KORE_USE_PYTHON)
static int		configure_file(char *);
#endif

#if defined(KORE_USE_ACME)
static int		configure_acme(char *);
static int		configure_acme_email(char *);
static int		configure_acme_provider(char *);
#endif

static int		configure_tls(char *);
static int		configure_server(char *);
static int		configure_include(char *);
static int		configure_bind(char *);
static int		configure_bind_unix(char *);
static int		configure_attach(char *);
static int		configure_domain(char *);
static int		configure_privsep(char *);
static int		configure_logfile(char *);
static int		configure_workers(char *);
static int		configure_pidfile(char *);
static int		configure_rlimit_nofiles(char *);
static int		configure_max_connections(char *);
static int		configure_accept_threshold(char *);
static int		configure_death_policy(char *);
static int		configure_set_affinity(char *);
static int		configure_socket_backlog(char *);
static int		configure_privsep_skip(char *);
static int		configure_privsep_root(char *);
static int		configure_privsep_runas(char *);

#if defined(KORE_USE_PLATFORM_PLEDGE)
static int		configure_add_pledge(char *);
#endif

static int		configure_rand_file(char *);
static int		configure_certfile(char *);
static int		configure_certkey(char *);
static int		configure_tls_version(char *);
static int		configure_tls_cipher(char *);
static int		configure_tls_dhparam(char *);
static int		configure_client_verify(char *);
static int		configure_client_verify_depth(char *);

#if !defined(KORE_NO_HTTP)
static int		configure_route(char *);
static int		configure_route_methods(char *);
static int		configure_route_handler(char *);
static int		configure_route_on_free(char *);
static int		configure_route_on_headers(char *);
static int		configure_route_authenticate(char *);
static int		configure_route_on_body_chunk(char *);
static int		configure_filemap(char *);
static int		configure_return(char *);
static int		configure_redirect(char *);
static int		configure_static_handler(char *);
static int		configure_dynamic_handler(char *);
static int		configure_accesslog(char *);
static int		configure_http_header_max(char *);
static int		configure_http_header_timeout(char *);
static int		configure_http_body_max(char *);
static int		configure_http_body_timeout(char *);
static int		configure_filemap_ext(char *);
static int		configure_filemap_index(char *);
static int		configure_http_media_type(char *);
static int		configure_http_hsts_enable(char *);
static int		configure_http_keepalive_time(char *);
static int		configure_http_request_ms(char *);
static int		configure_http_request_limit(char *);
static int		configure_http_body_disk_offload(char *);
static int		configure_http_body_disk_path(char *);
static int		configure_http_server_version(char *);
static int		configure_http_pretty_error(char *);
static int		configure_validator(char *);
static int		configure_validate(char *);
static int		configure_authentication(char *);
static int		configure_authentication_uri(char *);
static int		configure_authentication_type(char *);
static int		configure_authentication_value(char *);
static int		configure_authentication_validator(char *);
static int		configure_websocket_maxframe(char *);
static int		configure_websocket_timeout(char *);
#endif

#if defined(KORE_USE_PGSQL)
static int		configure_pgsql_conn_max(char *);
static int		configure_pgsql_queue_limit(char *);
#endif

#if defined(KORE_USE_TASKS)
static int		configure_task_threads(char *);
#endif

#if defined(KORE_USE_PYTHON)
static int		configure_deployment(char *);
static int		configure_python_path(char *);
static int		configure_python_import(char *);
#endif

#if defined(KORE_USE_CURL)
static int		configure_curl_timeout(char *);
static int		configure_curl_recv_max(char *);
#endif

#if defined(__linux__)
static int		configure_seccomp_tracing(char *);
#endif

static struct {
	const char		*name;
	int			(*configure)(char *);
} config_directives[] = {
	{ "tls",			configure_tls },
#if defined(KORE_USE_ACME)
	{ "acme",			configure_acme },
#endif
	{ "bind",			configure_bind },
	{ "load",			configure_load },
	{ "domain",			configure_domain },
	{ "privsep",			configure_privsep },
	{ "server",			configure_server },
	{ "attach",			configure_attach },
	{ "certkey",			configure_certkey },
	{ "certfile",			configure_certfile },
	{ "include",			configure_include },
	{ "unix",			configure_bind_unix },
	{ "skip",			configure_privsep_skip },
	{ "root",			configure_privsep_root },
	{ "runas",			configure_privsep_runas },
	{ "client_verify",		configure_client_verify },
	{ "client_verify_depth",	configure_client_verify_depth },
#if defined(KORE_USE_PYTHON)
	{ "python_path",		configure_python_path },
	{ "python_import",		configure_python_import },
#endif
#if !defined(KORE_NO_HTTP)
	{ "route",			configure_route },
	{ "handler",			configure_route_handler },
	{ "on_headers",			configure_route_on_headers },
	{ "on_body_chunk",		configure_route_on_body_chunk },
	{ "on_free",			configure_route_on_free },
	{ "methods",			configure_route_methods },
	{ "authenticate",		configure_route_authenticate },
	{ "filemap",			configure_filemap },
	{ "redirect",			configure_redirect },
	{ "return",			configure_return },
	{ "static",			configure_static_handler },
	{ "dynamic",			configure_dynamic_handler },
	{ "accesslog",			configure_accesslog },
	{ "validator",			configure_validator },
	{ "validate",			configure_validate },
	{ "authentication",		configure_authentication },
	{ "authentication_uri",		configure_authentication_uri },
	{ "authentication_type",	configure_authentication_type },
	{ "authentication_value",	configure_authentication_value },
	{ "authentication_validator",	configure_authentication_validator },
#endif
	{ NULL,				NULL },
};

static struct {
	const char		*name;
	int			(*configure)(char *);
} config_settings[] = {
	{ "logfile",			configure_logfile },
	{ "workers",			configure_workers },
	{ "worker_max_connections",	configure_max_connections },
	{ "worker_rlimit_nofiles",	configure_rlimit_nofiles },
	{ "worker_accept_threshold",	configure_accept_threshold },
	{ "worker_death_policy",	configure_death_policy },
	{ "worker_set_affinity",	configure_set_affinity },
	{ "pidfile",			configure_pidfile },
	{ "socket_backlog",		configure_socket_backlog },
	{ "tls_version",		configure_tls_version },
	{ "tls_cipher",			configure_tls_cipher },
	{ "tls_dhparam",		configure_tls_dhparam },
	{ "rand_file",			configure_rand_file },
#if defined(KORE_USE_ACME)
	{ "acme_email",			configure_acme_email },
	{ "acme_provider",		configure_acme_provider },
#endif
#if defined(KORE_USE_PLATFORM_PLEDGE)
	{ "pledge",			configure_add_pledge },
#endif
#if defined(__linux__)
	{ "seccomp_tracing",		configure_seccomp_tracing },
#endif
#if !defined(KORE_NO_HTTP)
	{ "filemap_ext",		configure_filemap_ext },
	{ "filemap_index",		configure_filemap_index },
	{ "http_media_type",		configure_http_media_type },
	{ "http_header_max",		configure_http_header_max },
	{ "http_header_timeout",	configure_http_header_timeout },
	{ "http_body_max",		configure_http_body_max },
	{ "http_body_timeout",		configure_http_body_timeout },
	{ "http_hsts_enable",		configure_http_hsts_enable },
	{ "http_keepalive_time",	configure_http_keepalive_time },
	{ "http_request_ms",		configure_http_request_ms },
	{ "http_request_limit",		configure_http_request_limit },
	{ "http_body_disk_offload",	configure_http_body_disk_offload },
	{ "http_body_disk_path",	configure_http_body_disk_path },
	{ "http_server_version",	configure_http_server_version },
	{ "http_pretty_error",		configure_http_pretty_error },
	{ "websocket_maxframe",		configure_websocket_maxframe },
	{ "websocket_timeout",		configure_websocket_timeout },
#endif
#if defined(KORE_USE_PYTHON)
	{ "deployment",			configure_deployment },
#endif
#if defined(KORE_USE_PGSQL)
	{ "pgsql_conn_max",		configure_pgsql_conn_max },
	{ "pgsql_queue_limit",		configure_pgsql_queue_limit },
#endif
#if defined(KORE_USE_TASKS)
	{ "task_threads",		configure_task_threads },
#endif
#if defined(KORE_USE_CURL)
	{ "curl_timeout",		configure_curl_timeout },
	{ "curl_recv_max",		configure_curl_recv_max },
#endif
#if !defined(KORE_SINGLE_BINARY) && defined(KORE_USE_PYTHON)
	{ "file",			configure_file },
#endif
	{ NULL,				NULL },
};

static int				finalized = 0;

#if !defined(KORE_SINGLE_BINARY)
char					*config_file = NULL;
#endif

#if !defined(KORE_NO_HTTP)
static struct kore_auth			*current_auth = NULL;
static struct kore_route		*current_route = NULL;
#endif

extern const char			*__progname;
static struct kore_domain		*current_domain = NULL;
static struct kore_server		*current_server = NULL;
static struct kore_privsep		*current_privsep = NULL;

void
kore_parse_config(void)
{
	FILE		*fp;
	struct passwd	*pwd;
	char		path[PATH_MAX];

	if (finalized)
		return;

	fp = NULL;

#if !defined(KORE_SINGLE_BINARY)
	if (config_file != NULL) {
		if ((fp = fopen(config_file, "r")) == NULL) {
			fatal("configuration given cannot be opened: %s",
			    config_file);
		}
	}
#else
	fp = config_file_write();
#endif

	if (fp != NULL) {
		kore_parse_config_file(fp);
		(void)fclose(fp);
	}

	kore_tls_dh_check();

	if (!kore_module_loaded())
		fatal("no application module was loaded");

	if (worker_privsep.root == NULL) {
		if (getcwd(path, sizeof(path)) == NULL)
			fatal("getcwd: %s", errno_s);
		worker_privsep.root = kore_strdup(path);

		if (!kore_quiet)
			kore_log(LOG_NOTICE, "privsep: no root path set");
	}

	if (worker_privsep.runas == NULL) {
		if ((pwd = getpwuid(getuid())) == NULL)
			fatal("getpwuid: %s", errno_s);

		worker_privsep.runas = kore_strdup(pwd->pw_name);
		if (!kore_quiet)
			kore_log(LOG_NOTICE, "privsep: no runas user set");

		endpwent();
	}

	configure_check_var(&keymgr_privsep.runas, worker_privsep.runas,
		"privsep: no keymgr runas set");
#if defined(KORE_USE_ACME)
	configure_check_var(&acme_privsep.runas, worker_privsep.runas,
		"privsep: no acme runas set");
#endif

	configure_check_var(&keymgr_privsep.root, worker_privsep.root,
		"privsep: no keymgr root set");
#if defined(KORE_USE_ACME)
	configure_check_var(&acme_privsep.root, worker_privsep.root,
		"privsep: no acme root set");
#endif

	if (skip_chroot) {
		worker_privsep.skip_chroot = 1;
		keymgr_privsep.skip_chroot = 1;
#if defined(KORE_USE_ACME)
		acme_privsep.skip_chroot = 1;
#endif
	}

	if (skip_runas) {
		worker_privsep.skip_runas = 1;
		keymgr_privsep.skip_runas = 1;
#if defined(KORE_USE_ACME)
		acme_privsep.skip_runas = 1;
#endif
	}

	if (skip_runas && !kore_quiet)
		kore_log(LOG_NOTICE, "privsep: skipping all runas options");

	if (skip_chroot && !kore_quiet)
		kore_log(LOG_NOTICE, "privsep: skipping all chroot options");

	finalized = 1;
}

void
kore_parse_config_file(FILE *fp)
{
	int		i, lineno;
	char		buf[BUFSIZ], *p, *t, *v;

	lineno = 1;
	while ((p = kore_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(p) == 0) {
			lineno++;
			continue;
		}

		if (!strcmp(p, "}") && current_privsep != NULL) {
			lineno++;
			current_privsep = NULL;
			continue;
		}

		if (!strcmp(p, "}") && current_server != NULL) {
			lineno++;
			kore_server_finalize(current_server);
			current_server = NULL;
			continue;
		}

#if !defined(KORE_NO_HTTP)
		if (!strcmp(p, "}") && current_route != NULL) {
			lineno++;
			current_route = NULL;
			continue;
		}

		if (!strcmp(p, "}") && current_auth != NULL) {
			if (current_auth->validator == NULL) {
				fatal("no authentication validator for %s",
				    current_auth->name);
			}

			lineno++;
			current_auth = NULL;
			continue;
		}
#endif

		if (!strcmp(p, "}") && current_domain != NULL) {
			if (current_domain->server == NULL) {
				fatal("domain '%s' not attached to server",
				    current_domain->domain);
			}

			if (current_domain->server->tls == 1) {
#if defined(KORE_USE_ACME)
				if (current_domain->acme) {
					lineno++;
					current_domain = NULL;
					continue;
				}
#endif
				if (current_domain->certfile == NULL ||
				    current_domain->certkey == NULL) {
					fatal("incomplete TLS setup for '%s'",
					    current_domain->domain);
				}
			}

			current_domain = NULL;
		}

		if (!strcmp(p, "}")) {
			lineno++;
			continue;
		}

		if ((t = strchr(p, ' ')) == NULL) {
			kore_log(LOG_NOTICE,
			    "ignoring \"%s\" on line %d", p, lineno++);
			continue;
		}

		*(t)++ = '\0';

		p = kore_text_trim(p, strlen(p));
		t = kore_text_trim(t, strlen(t));

		if (strlen(p) == 0 || strlen(t) == 0) {
			kore_log(LOG_NOTICE,
			    "ignoring \"%s\" on line %d", p, lineno++);
			continue;
		}

		for (i = 0; config_directives[i].name != NULL; i++) {
			if (!strcmp(config_directives[i].name, p)) {
				if ((v  = configure_resolve_var(t)) == NULL)
					fatal("variable %s does not exist", t);
				if (config_directives[i].configure(v))
					break;
				fatal("configuration error on line %d", lineno);
				/* NOTREACHED */
			}
		}

		if (config_directives[i].name != NULL) {
			lineno++;
			continue;
		}

		for (i = 0; config_settings[i].name != NULL; i++) {
			if (!strcmp(config_settings[i].name, p)) {
				if ((v  = configure_resolve_var(t)) == NULL)
					fatal("variable %s does not exist", t);
				if (config_settings[i].configure(v))
					break;
				fatal("configuration error on line %d", lineno);
				/* NOTREACHED */
			}
		}

		if (config_settings[i].name == NULL) {
			kore_log(LOG_NOTICE,
			    "ignoring \"%s\" on line %d", p, lineno);
		}

		lineno++;
	}
}

#if defined(KORE_USE_PYTHON)
int
kore_configure_setting(const char *name, char *value)
{
	int	i;

	if (finalized)
		return (KORE_RESULT_ERROR);

	for (i = 0; config_settings[i].name != NULL; i++) {
		if (!strcmp(config_settings[i].name, name)) {
			if (config_settings[i].configure(value))
				return (KORE_RESULT_OK);
			fatal("bad value '%s' for '%s'", value, name);
		}
	}

	kore_log(LOG_NOTICE, "ignoring unknown kore.config.%s setting", name);
	return (KORE_RESULT_OK);
}
#endif

static void
configure_check_var(char **var, const char *other, const char *logmsg)
{
	if (*var == NULL) {
		if (!kore_quiet)
			kore_log(LOG_NOTICE, "%s", logmsg);
		*var = kore_strdup(other);
	}
}

static char *
configure_resolve_var(char *var)
{
	char	*v;

	if (var[0] == '$') {
		if ((v = getenv(&var[1])) == NULL)
			return (NULL);
	} else {
		v = var;
	}

	return (v);
}

static int
configure_include(char *path)
{
	FILE		*fp;

	if ((fp = fopen(path, "r")) == NULL)
		fatal("failed to open include '%s'", path);

	kore_parse_config_file(fp);
	(void)fclose(fp);

	return (KORE_RESULT_OK);
}

static int
configure_server(char *options)
{
	struct kore_server	*srv;
	char			*argv[3];

	if (current_server != NULL) {
		kore_log(LOG_ERR, "nested server contexts are not allowed");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);

	if (argv[0] == NULL || argv[1] == NULL) {
		kore_log(LOG_ERR, "server context invalid");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[1], "{")) {
		kore_log(LOG_ERR, "server context not opened correctly");
		return (KORE_RESULT_ERROR);
	}

	if ((srv = kore_server_lookup(argv[0])) != NULL) {
		kore_log(LOG_ERR, "server with name '%s' exists", srv->name);
		return (KORE_RESULT_ERROR);
	}

	current_server = kore_server_create(argv[0]);

	return (KORE_RESULT_OK);
}

static int
configure_tls(char *yesno)
{
	if (!kore_tls_supported()) {
		current_server->tls = 0;

		if (!strcmp(yesno, "yes")) {
			kore_log(LOG_ERR, "TLS not supported in this build");
			return (KORE_RESULT_ERROR);
		}

		return (KORE_RESULT_OK);
	}

	if (current_server == NULL) {
		kore_log(LOG_ERR, "tls keyword not inside a server context");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(yesno, "no")) {
		current_server->tls = 0;
	} else if (!strcmp(yesno, "yes")) {
		current_server->tls = 1;
	} else {
		kore_log(LOG_ERR, "invalid '%s' for yes|no tls option", yesno);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

#if defined(KORE_USE_ACME)
static int
configure_acme(char *yesno)
{
	if (current_domain == NULL) {
		kore_log(LOG_ERR, "acme keyword not inside a domain context");
		return (KORE_RESULT_ERROR);
	}

	if (strchr(current_domain->domain, '*')) {
		kore_log(LOG_ERR,
		    "wildcards not supported due to lack of dns-01");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(yesno, "no")) {
		current_domain->acme = 0;
	} else if (!strcmp(yesno, "yes")) {
		current_domain->acme = 1;

		/* Override keyfile and certfile locations. */
		kore_free(current_domain->certkey);
		kore_free(current_domain->certfile);

		kore_acme_get_paths(current_domain->domain,
		    &current_domain->certkey, &current_domain->certfile);
		acme_domains++;
	} else {
		kore_log(LOG_ERR, "invalid '%s' for yes|no acme option", yesno);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_acme_email(char *email)
{
	kore_free(acme_email);
	acme_email = kore_strdup(email);

	return (KORE_RESULT_OK);
}

static int
configure_acme_provider(char *provider)
{
	kore_free(acme_provider);
	acme_provider = kore_strdup(provider);

	return (KORE_RESULT_OK);
}

#endif

static int
configure_bind(char *options)
{
	char		*argv[4];

	if (current_server == NULL) {
		kore_log(LOG_ERR, "bind keyword not inside a server context");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 4);
	if (argv[0] == NULL || argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	return (kore_server_bind(current_server, argv[0], argv[1], argv[2]));
}

static int
configure_bind_unix(char *options)
{
	char		*argv[3];

	if (current_server == NULL) {
		kore_log(LOG_ERR,
		    "bind_unix keyword not inside a server context");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[0] == NULL)
		return (KORE_RESULT_ERROR);

	return (kore_server_bind_unix(current_server, argv[0], argv[1]));
}

static int
configure_load(char *options)
{
	char		*argv[3];

	kore_split_string(options, " ", argv, 3);
	if (argv[0] == NULL)
		return (KORE_RESULT_ERROR);

	kore_module_load(argv[0], argv[1], KORE_MODULE_NATIVE);
	return (KORE_RESULT_OK);
}

#if defined(KORE_SINGLE_BINARY)
static FILE *
config_file_write(void)
{
	FILE		*fp;
	ssize_t		ret;
	int		fd, len;
	char		fpath[MAXPATHLEN];

	len = snprintf(fpath, sizeof(fpath), "%s/%s.XXXXXX", KORE_TMPDIR,
	    __progname);
	if (len == -1 || (size_t)len >= sizeof(fpath))
		fatal("failed to create temporary path");

	if ((fd = mkstemp(fpath)) == -1)
		fatal("mkstemp(%s): %s", fpath, errno_s);

	(void)unlink(fpath);

	for (;;) {
		ret = write(fd, asset_builtin_kore_conf,
		    asset_len_builtin_kore_conf);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("failed to write temporary config: %s", errno_s);
		}

		if ((size_t)ret != asset_len_builtin_kore_conf)
			fatal("failed to write temporary config");
		break;
	}

	if ((fp = fdopen(fd, "w+")) == NULL)
		fatal("fdopen(): %s", errno_s);

	rewind(fp);

	return (fp);
}
#elif defined(KORE_USE_PYTHON)
static int
configure_file(char *file)
{
	free(config_file);
	if ((config_file = strdup(file)) == NULL)
		fatal("strdup");

	return (KORE_RESULT_OK);
}
#endif

static int
configure_tls_version(char *version)
{
	int	ver;

	if (!strcmp(version, "1.3")) {
		ver = KORE_TLS_VERSION_1_3;
	} else if (!strcmp(version, "1.2")) {
		ver = KORE_TLS_VERSION_1_2;
	} else if (!strcmp(version, "both")) {
		ver = KORE_TLS_VERSION_BOTH;
	} else {
		kore_log(LOG_ERR,
		    "unknown value for tls_version: %s (use 1.3, 1.2, both)",
		    version);
		return (KORE_RESULT_ERROR);
	}

	kore_tls_version_set(ver);

	return (KORE_RESULT_OK);
}

static int
configure_tls_cipher(char *cipherlist)
{
	return (kore_tls_ciphersuite_set(cipherlist));
}

static int
configure_tls_dhparam(char *path)
{
	return (kore_tls_dh_load(path));
}

static int
configure_client_verify_depth(char *value)
{
	int	err, depth;

	if (current_domain == NULL) {
		kore_log(LOG_ERR,
		    "client_verify_depth keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	depth = kore_strtonum(value, 10, 0, INT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad client_verify_depth value: %s", value);
		return (KORE_RESULT_ERROR);
	}

	current_domain->x509_verify_depth = depth;

	return (KORE_RESULT_OK);
}

static int
configure_client_verify(char *options)
{
	char		*argv[3];

	if (current_domain == NULL) {
		kore_log(LOG_ERR,
		    "client_verify keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[0] == NULL) {
		kore_log(LOG_ERR, "client_verify is missing a parameter");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->cafile != NULL) {
		kore_log(LOG_ERR, "client_verify already set for '%s'",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->cafile = kore_strdup(argv[0]);
	if (argv[1] != NULL)
		current_domain->crlfile = kore_strdup(argv[1]);

	return (KORE_RESULT_OK);
}

static int
configure_rand_file(char *path)
{
	if (kore_rand_file != NULL)
		kore_free(kore_rand_file);

	kore_rand_file = kore_strdup(path);

	return (KORE_RESULT_OK);
}

static int
configure_certfile(char *path)
{
	if (current_domain == NULL) {
		kore_log(LOG_ERR,
		    "certfile keyword not specified in domain context");
		return (KORE_RESULT_ERROR);
	}

	kore_free(current_domain->certfile);
	current_domain->certfile = kore_strdup(path);
	return (KORE_RESULT_OK);
}

static int
configure_certkey(char *path)
{
	if (current_domain == NULL) {
		kore_log(LOG_ERR,
		    "certkey keyword not specified in domain context");
		return (KORE_RESULT_ERROR);
	}

	kore_free(current_domain->certkey);
	current_domain->certkey = kore_strdup(path);
	return (KORE_RESULT_OK);
}

static int
configure_privsep(char *options)
{
	char		*argv[3];

	if (current_privsep != NULL) {
		kore_log(LOG_ERR, "nested privsep contexts are not allowed");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);

	if (argv[0] == NULL || argv[1] == NULL) {
		kore_log(LOG_ERR, "invalid privsep context");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[1], "{")) {
		kore_log(LOG_ERR, "privsep context not opened correctly");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(argv[0], "worker")) {
		current_privsep = &worker_privsep;
	} else if (!strcmp(argv[0], "keymgr")) {
		current_privsep = &keymgr_privsep;
#if defined(KORE_USE_ACME)
	} else if (!strcmp(argv[0], "acme")) {
		current_privsep = &acme_privsep;
#endif
	} else {
		kore_log(LOG_ERR, "unknown privsep context: %s", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_privsep_runas(char *user)
{
	if (current_privsep == NULL) {
		kore_log(LOG_ERR, "runas keyword not in privsep context");
		return (KORE_RESULT_ERROR);
	}

	if (current_privsep->runas != NULL)
		kore_free(current_privsep->runas);

	current_privsep->runas = kore_strdup(user);

	return (KORE_RESULT_OK);
}

static int
configure_privsep_root(char *root)
{
	if (current_privsep == NULL) {
		kore_log(LOG_ERR, "root keyword not in privsep context");
		return (KORE_RESULT_ERROR);
	}

	if (current_privsep->root != NULL)
		kore_free(current_privsep->root);

	current_privsep->root = kore_strdup(root);

	return (KORE_RESULT_OK);
}

static int
configure_privsep_skip(char *option)
{
	if (current_privsep == NULL) {
		kore_log(LOG_ERR, "skip keyword not in privsep context");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(option, "chroot")) {
		current_privsep->skip_chroot = 1;
	} else {
		kore_log(LOG_ERR, "unknown skip option '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_domain(char *options)
{
	char		*argv[3];

	if (current_domain != NULL) {
		kore_log(LOG_ERR, "nested domain contexts are not allowed");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);

	if (argv[0] == NULL || argv[1] == NULL) {
		kore_log(LOG_ERR, "invalid domain context");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[1], "{")) {
		kore_log(LOG_ERR, "domain context not opened correctly");
		return (KORE_RESULT_ERROR);
	}

	if (strlen(argv[0]) >= KORE_DOMAINNAME_LEN - 1) {
		kore_log(LOG_ERR, "domain name '%s' too long", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	current_domain = kore_domain_new(argv[0]);

	return (KORE_RESULT_OK);
}

static int
configure_attach(char *name)
{
	struct kore_server	*srv;

	if (current_domain == NULL) {
		kore_log(LOG_ERR, "attach keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->server != NULL) {
		kore_log(LOG_ERR, "domain '%s' already attached to server",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	if ((srv = kore_server_lookup(name)) == NULL) {
		kore_log(LOG_ERR, "server '%s' does not exist", name);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_domain_attach(current_domain, srv)) {
		kore_log(LOG_ERR, "failed to attach '%s' to '%s'",
		    current_domain->domain, name);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

#if !defined(KORE_NO_HTTP)
static int
configure_static_handler(char *options)
{
	kore_log(LOG_NOTICE, "static keyword removed, use route instead");
	return (KORE_RESULT_ERROR);
}

static int
configure_dynamic_handler(char *options)
{
	kore_log(LOG_NOTICE, "dynamic keyword removed, use route instead");
	return (KORE_RESULT_ERROR);
}

static int
configure_route(char *options)
{
	struct kore_route	*rt;
	int			type;
	char			*argv[4];

	if (current_domain == NULL) {
		kore_log(LOG_ERR, "route keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	if (current_route != NULL) {
		kore_log(LOG_ERR, "nested route contexts not allowed");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 4);

	if (argv[1] == NULL || strcmp(argv[1], "{")) {
		kore_log(LOG_ERR, "invalid route context");
		return (KORE_RESULT_ERROR);
	}

	if (*argv[0] == '/')
		type = HANDLER_TYPE_STATIC;
	else
		type = HANDLER_TYPE_DYNAMIC;

	if ((rt = kore_route_create(current_domain, argv[0], type)) == NULL) {
		kore_log(LOG_ERR,
		    "failed to create route handler for '%s'", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	current_route = rt;

	return (KORE_RESULT_OK);
}

static int
configure_route_handler(char *name)
{
	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "handler keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	kore_route_callback(current_route, name);

	return (KORE_RESULT_OK);
}

static int
configure_route_on_headers(char *name)
{
	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "on_header keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	if ((current_route->on_headers = kore_runtime_getcall(name)) == NULL) {
		kore_log(LOG_ERR, "on_headers callback '%s' for '%s' not found",
		    name, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_route_on_body_chunk(char *name)
{
	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "on_body_chunk keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	current_route->on_body_chunk = kore_runtime_getcall(name);
	if (current_route->on_body_chunk == NULL) {
		kore_log(LOG_ERR,
		    "on_body_chunk callback '%s' for '%s' not found",
		    name, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_route_on_free(char *name)
{
	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "on_free keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	if ((current_route->on_free = kore_runtime_getcall(name)) == NULL) {
		kore_log(LOG_ERR, "on_free callback '%s' for '%s' not found",
		    name, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_route_authenticate(char *name)
{
	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "authenticate keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	current_route->auth = kore_auth_lookup(name);

	if (current_route->auth == NULL) {
		kore_log(LOG_ERR, "no such authentication '%s' for '%s' found",
		    name, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_route_methods(char *options)
{
	int			i, cnt;
	char			*argv[10];

	if (current_route == NULL) {
		kore_log(LOG_ERR,
		    "methods keyword not inside of route context");
		return (KORE_RESULT_ERROR);
	}

	cnt = kore_split_string(options, " ", argv, 10);
	if (cnt < 1) {
		kore_log(LOG_ERR,
		    "bad methods option '%s', missing methods", options);
		return (KORE_RESULT_ERROR);
	}

	current_route->methods = 0;

	for (i = 0; i < cnt; i++) {
		if (!strcasecmp(argv[i], "post")) {
			current_route->methods |= HTTP_METHOD_POST;
		} else if (!strcasecmp(argv[i], "get")) {
			current_route->methods |= HTTP_METHOD_GET;
		} else if (!strcasecmp(argv[i], "put")) {
			current_route->methods |= HTTP_METHOD_PUT;
		} else if (!strcasecmp(argv[i], "delete")) {
			current_route->methods |= HTTP_METHOD_DELETE;
		} else if (!strcasecmp(argv[i], "head")) {
			current_route->methods |= HTTP_METHOD_HEAD;
		} else if (!strcasecmp(argv[i], "patch")) {
			current_route->methods |= HTTP_METHOD_PATCH;
		} else {
			kore_log(LOG_ERR, "unknown method: %s in method for %s",
			    argv[i], current_route->path);
			return (KORE_RESULT_ERROR);
		}
	}

	return (KORE_RESULT_OK);
}

static int
configure_return(char *options)
{
	char		*argv[3];
	int		elm, status, err;

	if (current_domain == NULL) {
		kore_log(LOG_ERR, "return keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	elm = kore_split_string(options, " ", argv, 3);
	if (elm != 2) {
		kore_log(LOG_ERR, "missing parameters for return");
		return (KORE_RESULT_ERROR);
	}

	status = kore_strtonum(argv[1], 10, 400, 600, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "invalid status code on return (%s)", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	if (!http_redirect_add(current_domain, argv[0], status, NULL)) {
		kore_log(LOG_ERR, "invalid regex on return path");
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_redirect(char *options)
{
	char		*argv[4];
	int		elm, status, err;

	if (current_domain == NULL) {
		kore_log(LOG_ERR, "redirect keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	elm = kore_split_string(options, " ", argv, 4);
	if (elm != 3) {
		kore_log(LOG_ERR, "missing parameters for redirect");
		return (KORE_RESULT_ERROR);
	}

	status = kore_strtonum(argv[1], 10, 300, 399, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "invalid status code on redirect (%s)", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	if (!http_redirect_add(current_domain, argv[0], status, argv[2])) {
		kore_log(LOG_ERR, "invalid regex on redirect path");
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_filemap(char *options)
{
	char		*argv[4];

	if (current_domain == NULL) {
		kore_log(LOG_ERR, "filemap keyword not in domain context");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 4);

	if (argv[0] == NULL || argv[1] == NULL) {
		kore_log(LOG_ERR, "missing parameters for filemap");
		return (KORE_RESULT_ERROR);
	}

	if (kore_filemap_create(current_domain,
	    argv[1], argv[0], argv[2]) == NULL) {
		kore_log(LOG_ERR, "cannot create filemap for %s", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_accesslog(char *path)
{
	if (current_domain == NULL) {
		kore_log(LOG_ERR, "accesslog not specified in domain context");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->accesslog != -1) {
		kore_log(LOG_ERR, "domain '%s' already has an open accesslog",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->accesslog = open(path,
	    O_CREAT | O_APPEND | O_WRONLY,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (current_domain->accesslog == -1) {
		kore_log(LOG_ERR, "accesslog open(%s): %s", path, errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_filemap_ext(char *ext)
{
	kore_free(kore_filemap_ext);
	kore_filemap_ext = kore_strdup(ext);

	return (KORE_RESULT_OK);
}

static int
configure_filemap_index(char *index)
{
	kore_free(kore_filemap_index);
	kore_filemap_index = kore_strdup(index);

	return (KORE_RESULT_OK);
}

static int
configure_http_media_type(char *type)
{
	int		i;
	char		*extensions, *ext[10];

	extensions = strchr(type, ' ');
	if (extensions == NULL) {
		kore_log(LOG_ERR, "bad http_media_type value '%s'", type);
		return (KORE_RESULT_ERROR);
	}

	*(extensions)++ = '\0';

	kore_split_string(extensions, " \t", ext, 10);
	for (i = 0; ext[i] != NULL; i++) {
		if (!http_media_register(ext[i], type)) {
			kore_log(LOG_ERR,
			    "duplicate extension found '%s'", ext[i]);
			return (KORE_RESULT_ERROR);
		}
	}

	if (i == 0) {
		kore_log(LOG_ERR, "missing extensions in '%s'", type);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_header_max(char *option)
{
	int		err;

	http_header_max = kore_strtonum(option, 10, 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_header_max value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_header_timeout(char *option)
{
	int		err;

	http_header_timeout = kore_strtonum(option, 10, 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_header_timeout value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_body_max(char *option)
{
	int		err;

	http_body_max = kore_strtonum(option, 10, 0, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_body_max value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_body_timeout(char *option)
{
	int		err;

	http_body_timeout = kore_strtonum(option, 10, 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_body_timeout value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_body_disk_offload(char *option)
{
	int		err;

	http_body_disk_offload = kore_strtonum(option, 10, 0, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad http_body_disk_offload value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_body_disk_path(char *path)
{
	if (strcmp(http_body_disk_path, HTTP_BODY_DISK_PATH))
		kore_free(http_body_disk_path);

	http_body_disk_path = kore_strdup(path);
	return (KORE_RESULT_OK);
}

static int
configure_http_server_version(char *version)
{
	http_server_version(version);

	return (KORE_RESULT_OK);
}

static int
configure_http_pretty_error(char *yesno)
{
	if (!strcmp(yesno, "no")) {
		http_pretty_error = 0;
	} else if (!strcmp(yesno, "yes")) {
		http_pretty_error = 1;
	} else {
		kore_log(LOG_ERR,
		    "invalid '%s' for yes|no http_pretty_error option", yesno);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_hsts_enable(char *option)
{
	int		err;

	http_hsts_enable = kore_strtonum(option, 10, 0, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_hsts_enable value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_keepalive_time(char *option)
{
	int		err;

	http_keepalive_time = kore_strtonum(option, 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad http_keepalive_time value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_request_ms(char *option)
{
	int		err;

	http_request_ms = kore_strtonum(option, 10, 0, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_request_ms value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_request_limit(char *option)
{
	int		err;

	http_request_limit = kore_strtonum(option, 10, 0, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad http_request_limit value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_validator(char *name)
{
	u_int8_t	type;
	char		*tname, *value;

	if ((tname = strchr(name, ' ')) == NULL) {
		kore_log(LOG_ERR, "missing validator name");
		return (KORE_RESULT_ERROR);
	}

	*(tname)++ = '\0';
	tname = kore_text_trim(tname, strlen(tname));
	if ((value = strchr(tname, ' ')) == NULL) {
		kore_log(LOG_ERR, "missing validator value");
		return (KORE_RESULT_ERROR);
	}

	*(value)++ = '\0';
	value = kore_text_trim(value, strlen(value));

	if (!strcmp(tname, "regex")) {
		type = KORE_VALIDATOR_TYPE_REGEX;
	} else if (!strcmp(tname, "function")) {
		type = KORE_VALIDATOR_TYPE_FUNCTION;
	} else {
		kore_log(LOG_ERR,
		    "bad type '%s' for validator '%s'", tname, name);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_validator_add(name, type, value)) {
		kore_log(LOG_ERR, "bad validator specified for '%s'", name);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_validate(char *options)
{
	struct kore_validator		*val;
	struct kore_route_params	*param;
	char				*method, *argv[4];
	int				flags, http_method;

	if (kore_split_string(options, " ", argv, 4) != 3) {
		kore_log(LOG_ERR,
		    "validate keyword needs 3 args: method param validator");
		return (KORE_RESULT_ERROR);
	}

	flags = 0;

	if ((method = strchr(argv[0], ':')) != NULL) {
		*(method)++ = '\0';
		if (!strcasecmp(argv[0], "qs")) {
			flags = KORE_PARAMS_QUERY_STRING;
		} else {
			kore_log(LOG_ERR,
			    "unknown validate method prefix '%s' for '%s'",
			    argv[0], current_route->path);
			return (KORE_RESULT_ERROR);
		}
	} else {
		method = argv[0];
	}

	if ((val = kore_validator_lookup(argv[2])) == NULL) {
		kore_log(LOG_ERR, "unknown validator '%s'", argv[2]);
		return (KORE_RESULT_ERROR);
	}

	if (!strcasecmp(method, "post")) {
		http_method = HTTP_METHOD_POST;
	} else if (!strcasecmp(method, "get")) {
		http_method = HTTP_METHOD_GET;
		/* Let params get /foo {} imply qs:get automatically. */
		flags |= KORE_PARAMS_QUERY_STRING;
	} else if (!strcasecmp(method, "put")) {
		http_method = HTTP_METHOD_PUT;
	} else if (!strcasecmp(method, "delete")) {
		http_method = HTTP_METHOD_DELETE;
	} else if (!strcasecmp(method, "head")) {
		http_method = HTTP_METHOD_HEAD;
	} else if (!strcasecmp(method, "patch")) {
		http_method = HTTP_METHOD_PATCH;
	} else {
		kore_log(LOG_ERR, "unknown method: %s in validator for %s",
		    method, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	if (!(current_route->methods & http_method)) {
		kore_log(LOG_ERR, "method '%s' not enabled for route '%s'",
		    method, current_route->path);
		return (KORE_RESULT_ERROR);
	}

	param = kore_calloc(1, sizeof(*param));

	param->flags = flags;
	param->validator = val;
	param->method = http_method;
	param->name = kore_strdup(argv[1]);

	TAILQ_INSERT_TAIL(&current_route->params, param, list);

	return (KORE_RESULT_OK);
}

static int
configure_authentication(char *options)
{
	char		*argv[3];

	if (current_auth != NULL) {
		kore_log(LOG_ERR, "previous authentication block not closed");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[1] == NULL) {
		kore_log(LOG_ERR, "missing name for authentication block");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[1], "{")) {
		kore_log(LOG_ERR, "missing { for authentication block");
		return (KORE_RESULT_ERROR);
	}

	if (!kore_auth_new(argv[0]))
		return (KORE_RESULT_ERROR);

	current_auth = kore_auth_lookup(argv[0]);

	return (KORE_RESULT_OK);
}

static int
configure_authentication_type(char *option)
{
	if (current_auth == NULL) {
		kore_log(LOG_ERR,
		    "authentication_type keyword not in correct context");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(option, "cookie")) {
		current_auth->type = KORE_AUTH_TYPE_COOKIE;
	} else if (!strcmp(option, "header")) {
		current_auth->type = KORE_AUTH_TYPE_HEADER;
	} else if (!strcmp(option, "request")) {
		current_auth->type = KORE_AUTH_TYPE_REQUEST;
	} else {
		kore_log(LOG_ERR, "unknown authentication type '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_authentication_value(char *option)
{
	if (current_auth == NULL) {
		kore_log(LOG_ERR,
		    "authentication_value keyword not in correct context");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth->value != NULL)
		kore_free(current_auth->value);
	current_auth->value = kore_strdup(option);

	return (KORE_RESULT_OK);
}

static int
configure_authentication_validator(char *validator)
{
	struct kore_validator		*val;

	if (current_auth == NULL) {
		kore_log(LOG_ERR,
		    "authentication_validator not in correct context");
		return (KORE_RESULT_ERROR);
	}

	if ((val = kore_validator_lookup(validator)) == NULL) {
		kore_log(LOG_ERR,
		    "authentication validator '%s' not found", validator);
		return (KORE_RESULT_ERROR);
	}

	current_auth->validator = val;

	return (KORE_RESULT_OK);
}

static int
configure_authentication_uri(char *uri)
{
	if (current_auth == NULL) {
		kore_log(LOG_ERR,
		    "authentication_uri keyword not in correct context");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth->redirect != NULL)
		kore_free(current_auth->redirect);
	current_auth->redirect = kore_strdup(uri);

	return (KORE_RESULT_OK);
}

static int
configure_websocket_maxframe(char *option)
{
	int	err;

	kore_websocket_maxframe = kore_strtonum64(option, 1, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad kore_websocket_maxframe value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_websocket_timeout(char *option)
{
	int	err;

	kore_websocket_timeout = kore_strtonum64(option, 1, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad kore_websocket_timeout value '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	kore_websocket_timeout = kore_websocket_timeout * 1000;

	return (KORE_RESULT_OK);
}

#endif /* !KORE_NO_HTTP */

static int
configure_logfile(char *path)
{
	kore_log_file(path);
	return (KORE_RESULT_OK);
}

static int
configure_workers(char *option)
{
	int		err;

	worker_count = kore_strtonum(option, 10, 1, KORE_WORKER_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad value for worker '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_pidfile(char *path)
{
	if (strcmp(kore_pidfile, KORE_PIDFILE_DEFAULT))
		kore_free(kore_pidfile);
	kore_pidfile = kore_strdup(path);

	return (KORE_RESULT_OK);
}

static int
configure_max_connections(char *option)
{
	int		err;

	worker_max_connections = kore_strtonum(option, 10, 1, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad value for worker_max_connections '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_rlimit_nofiles(char *option)
{
	int		err;

	worker_rlimit_nofiles = kore_strtonum(option, 10, 1, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad value for worker_rlimit_nofiles '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_accept_threshold(char *option)
{
	int		err;

	worker_accept_threshold = kore_strtonum(option, 0, 1, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad value for worker_accept_threshold '%s'\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_death_policy(char *option)
{
	if (!strcmp(option, "restart")) {
		worker_policy = KORE_WORKER_POLICY_RESTART;
	} else if (!strcmp(option, "terminate")) {
		worker_policy = KORE_WORKER_POLICY_TERMINATE;
	} else {
		kore_log(LOG_ERR,
		    "bad value for worker_death_policy '%s'\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_set_affinity(char *option)
{
	int		err;

	worker_set_affinity = kore_strtonum(option, 10, 0, 1, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad value for worker_set_affinity '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_socket_backlog(char *option)
{
	int		err;

	kore_socket_backlog = kore_strtonum(option, 10, 0, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad socket_backlog value: '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

#if defined(KORE_USE_PGSQL)
static int
configure_pgsql_conn_max(char *option)
{
	int		err;

	pgsql_conn_max = kore_strtonum(option, 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad value for pgsql_conn_max '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_pgsql_queue_limit(char *option)
{
	int		err;

	pgsql_queue_limit = kore_strtonum(option, 10, 0, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR,
		    "bad value for pgsql_queue_limit '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
#endif

#if defined(KORE_USE_TASKS)
static int
configure_task_threads(char *option)
{
	int		err;

	kore_task_threads = kore_strtonum(option, 10, 0, UCHAR_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad value for task_threads: '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
#endif

#if defined(KORE_USE_PYTHON)
static int
configure_deployment(char *value)
{
	if (!strcmp(value, "docker")) {
		kore_foreground = 1;
		skip_runas = 0;
		skip_chroot = 0;
	} else if (!strcmp(value, "dev") || !strcmp(value, "development")) {
		kore_foreground = 1;
		skip_runas = 1;
		skip_chroot = 1;
	} else if (!strcmp(value, "production")) {
		kore_foreground = 0;
		skip_runas = 0;
		skip_chroot = 0;
	} else {
		kore_log(LOG_NOTICE,
		    "kore.config.deployment: bad value '%s'", value);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_python_path(char *path)
{
	kore_python_path(path);

	return (KORE_RESULT_OK);
}

static int
configure_python_import(char *module)
{
	char		*argv[3];

	kore_split_string(module, " ", argv, 3);
	if (argv[0] == NULL)
		return (KORE_RESULT_ERROR);

	kore_module_load(argv[0], argv[1], KORE_MODULE_PYTHON);
	return (KORE_RESULT_OK);
}
#endif

#if defined(KORE_USE_PLATFORM_PLEDGE)
static int
configure_add_pledge(char *pledge)
{
	kore_platform_add_pledge(pledge);

	return (KORE_RESULT_OK);
}
#endif

#if defined(KORE_USE_CURL)
static int
configure_curl_recv_max(char *option)
{
	int		err;

	kore_curl_recv_max = kore_strtonum64(option, 1, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad curl_recv_max value '%s'\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_curl_timeout(char *option)
{
	int		err;

	kore_curl_timeout = kore_strtonum(option, 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		kore_log(LOG_ERR, "bad kore_curl_timeout value: '%s'", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
#endif

#if defined(__linux__)
static int
configure_seccomp_tracing(char *opt)
{
	if (!strcmp(opt, "yes")) {
		kore_seccomp_tracing = 1;
	} else if (!strcmp(opt, "no")) {
		kore_seccomp_tracing = 0;
	} else {
		kore_log(LOG_ERR,
		    "bad seccomp_tracing value '%s' (expected yes|no)\n", opt);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
#endif
