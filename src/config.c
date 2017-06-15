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

#include <sys/param.h>
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

/* XXX - This is becoming a clusterfuck. Fix it. */

static int		configure_load(char *);

#if defined(KORE_SINGLE_BINARY)
static FILE		*config_file_write(void);
extern u_int8_t		asset_builtin_kore_conf[];
extern u_int32_t	asset_len_builtin_kore_conf;
#endif

static int		configure_include(char *);
static int		configure_bind(char *);
static int		configure_domain(char *);
static int		configure_chroot(char *);
static int		configure_runas(char *);
static int		configure_workers(char *);
static int		configure_pidfile(char *);
static int		configure_rlimit_nofiles(char *);
static int		configure_max_connections(char *);
static int		configure_accept_threshold(char *);
static int		configure_set_affinity(char *);
static int		configure_socket_backlog(char *);

#if !defined(KORE_NO_TLS)
static int		configure_rand_file(char *);
static int		configure_certfile(char *);
static int		configure_certkey(char *);
static int		configure_tls_version(char *);
static int		configure_tls_cipher(char *);
static int		configure_tls_dhparam(char *);
static int		configure_client_certificates(char *);
#endif

#if !defined(KORE_NO_HTTP)
static int		configure_handler(int, char *);
static int		configure_static_handler(char *);
static int		configure_dynamic_handler(char *);
static int		configure_accesslog(char *);
static int		configure_http_header_max(char *);
static int		configure_http_body_max(char *);
static int		configure_http_hsts_enable(char *);
static int		configure_http_keepalive_time(char *);
static int		configure_http_request_limit(char *);
static int		configure_http_body_disk_offload(char *);
static int		configure_http_body_disk_path(char *);
static int		configure_validator(char *);
static int		configure_params(char *);
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
#endif

#if defined(KORE_USE_TASKS)
static int		configure_task_threads(char *);
#endif

#if defined(KORE_USE_PYTHON)
static int		configure_python_import(char *);
#endif

static void		domain_tls_init(void);
static void		kore_parse_config_file(const char *);

static struct {
	const char		*name;
	int			(*configure)(char *);
} config_names[] = {
	{ "include",			configure_include },
	{ "bind",			configure_bind },
	{ "load",			configure_load },
#if defined(KORE_USE_PYTHON)
	{ "python_import",		configure_python_import },
#endif
	{ "domain",			configure_domain },
	{ "chroot",			configure_chroot },
	{ "runas",			configure_runas },
	{ "workers",			configure_workers },
	{ "worker_max_connections",	configure_max_connections },
	{ "worker_rlimit_nofiles",	configure_rlimit_nofiles },
	{ "worker_accept_threshold",	configure_accept_threshold },
	{ "worker_set_affinity",	configure_set_affinity },
	{ "pidfile",			configure_pidfile },
	{ "socket_backlog",		configure_socket_backlog },
#if !defined(KORE_NO_TLS)
	{ "tls_version",		configure_tls_version },
	{ "tls_cipher",			configure_tls_cipher },
	{ "tls_dhparam",		configure_tls_dhparam },
	{ "rand_file",			configure_rand_file },
	{ "certfile",			configure_certfile },
	{ "certkey",			configure_certkey },
	{ "client_certificates",	configure_client_certificates },
#endif
#if !defined(KORE_NO_HTTP)
	{ "static",			configure_static_handler },
	{ "dynamic",			configure_dynamic_handler },
	{ "accesslog",			configure_accesslog },
	{ "http_header_max",		configure_http_header_max },
	{ "http_body_max",		configure_http_body_max },
	{ "http_hsts_enable",		configure_http_hsts_enable },
	{ "http_keepalive_time",	configure_http_keepalive_time },
	{ "http_request_limit",		configure_http_request_limit },
	{ "http_body_disk_offload",	configure_http_body_disk_offload },
	{ "http_body_disk_path",	configure_http_body_disk_path },
	{ "validator",			configure_validator },
	{ "params",			configure_params },
	{ "validate",			configure_validate },
	{ "authentication",		configure_authentication },
	{ "authentication_uri",		configure_authentication_uri },
	{ "authentication_type",	configure_authentication_type },
	{ "authentication_value",	configure_authentication_value },
	{ "authentication_validator",	configure_authentication_validator },
	{ "websocket_maxframe",		configure_websocket_maxframe },
	{ "websocket_timeout",		configure_websocket_timeout },
#endif
#if defined(KORE_USE_PGSQL)
	{ "pgsql_conn_max",		configure_pgsql_conn_max },
#endif
#if defined(KORE_USE_TASKS)
	{ "task_threads",		configure_task_threads },
#endif
	{ NULL,				NULL },
};

#if !defined(KORE_SINGLE_BINARY)
char					*config_file = NULL;
#endif

#if !defined(KORE_NO_HTTP)
static u_int8_t				current_method = 0;
static struct kore_auth			*current_auth = NULL;
static struct kore_module_handle	*current_handler = NULL;
#endif

extern const char			*__progname;
static struct kore_domain		*current_domain = NULL;

void
kore_parse_config(void)
{
#if !defined(KORE_SINGLE_BINARY)
	kore_parse_config_file(config_file);
#else
	kore_parse_config_file(NULL);
#endif

	if (!kore_module_loaded())
		fatal("no application module was loaded");

	if (skip_chroot != 1 && chroot_path == NULL) {
		fatal("missing a chroot path");
	}

	if (getuid() != 0 && skip_chroot == 0) {
		fatal("cannot chroot, use -n to skip it");
	}

	if (skip_runas != 1 && runas_user == NULL) {
		fatal("missing runas user, use -r to skip it");
	}

	if (getuid() != 0 && skip_runas == 0) {
		fatal("cannot drop privileges, use -r to skip it");
	}
}

static void
kore_parse_config_file(const char *fpath)
{
	FILE		*fp;
	int		i, lineno;
	char		buf[BUFSIZ], *p, *t;

#if !defined(KORE_SINGLE_BINARY)
	if ((fp = fopen(fpath, "r")) == NULL)
		fatal("configuration given cannot be opened: %s", fpath);
#else
	fp = config_file_write();
#endif

	kore_debug("parsing configuration file '%s'", fpath);

	lineno = 1;
	while ((p = kore_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(p) == 0) {
			lineno++;
			continue;
		}

#if !defined(KORE_NO_HTTP)
		if (!strcmp(p, "}") && current_handler != NULL) {
			lineno++;
			current_handler = NULL;
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

		if (!strcmp(p, "}") && current_domain != NULL)
			domain_tls_init();

		if (!strcmp(p, "}")) {
			lineno++;
			continue;
		}

		if ((t = strchr(p, ' ')) == NULL) {
			printf("ignoring \"%s\" on line %d\n", p, lineno++);
			continue;
		}

		*(t)++ = '\0';

		p = kore_text_trim(p, strlen(p));
		t = kore_text_trim(t, strlen(t));

		if (strlen(p) == 0 || strlen(t) == 0) {
			printf("ignoring \"%s\" on line %d\n", p, lineno++);
			continue;
		}

		for (i = 0; config_names[i].name != NULL; i++) {
			if (!strcmp(config_names[i].name, p)) {
				if (config_names[i].configure(t))
					break;
				fatal("configuration error on line %d", lineno);
				/* NOTREACHED */
			}
		}

		if (config_names[i].name == NULL)
			printf("ignoring \"%s\" on line %d\n", p, lineno);
		lineno++;
	}

	fclose(fp);
}

static int
configure_include(char *path)
{
	kore_parse_config_file(path);
	return (KORE_RESULT_OK);
}

static int
configure_bind(char *options)
{
	char		*argv[4];

	kore_split_string(options, " ", argv, 4);
	if (argv[0] == NULL || argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	return (kore_server_bind(argv[0], argv[1], argv[2]));
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

	len = snprintf(fpath, sizeof(fpath), "/tmp/%s.XXXXXX", __progname);
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
#endif

#if !defined(KORE_NO_TLS)
static int
configure_tls_version(char *version)
{
	if (!strcmp(version, "1.2")) {
		tls_version = KORE_TLS_VERSION_1_2;
	} else if (!strcmp(version, "1.0")) {
		tls_version = KORE_TLS_VERSION_1_0;
	} else if (!strcmp(version, "both")) {
		tls_version = KORE_TLS_VERSION_BOTH;
	} else {
		printf("unknown value for tls_version: %s\n", version);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_tls_cipher(char *cipherlist)
{
	if (strcmp(kore_tls_cipher_list, KORE_DEFAULT_CIPHER_LIST)) {
		printf("tls_cipher specified twice\n");
		return (KORE_RESULT_ERROR);
	}

	kore_tls_cipher_list = kore_strdup(cipherlist);
	return (KORE_RESULT_OK);
}

static int
configure_tls_dhparam(char *path)
{
	BIO		*bio;

	if (tls_dhparam != NULL) {
		printf("tls_dhparam specified twice\n");
		return (KORE_RESULT_ERROR);
	}

	if ((bio = BIO_new_file(path, "r")) == NULL) {
		printf("%s did not exist\n", path);
		return (KORE_RESULT_ERROR);
	}

	tls_dhparam = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (tls_dhparam == NULL) {
		printf("PEM_read_bio_DHparams(): %s\n", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_client_certificates(char *options)
{
	char		*argv[3];

	if (current_domain == NULL) {
		printf("client_certificates not specified in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[0] == NULL) {
		printf("client_certificate is missing a parameter\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->cafile != NULL) {
		printf("client_certificate already set for %s\n",
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
	if (rand_file != NULL)
		kore_free(rand_file);

	rand_file = kore_strdup(path);

	return (KORE_RESULT_OK);
}

static int
configure_certfile(char *path)
{
	if (current_domain == NULL) {
		printf("certfile not specified in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->certfile != NULL) {
		printf("certfile specified twice for %s\n",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->certfile = kore_strdup(path);
	return (KORE_RESULT_OK);
}

static int
configure_certkey(char *path)
{
	if (current_domain == NULL) {
		printf("certkey not specified in domain text\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->certkey != NULL) {
		printf("certkey specified twice for %s\n",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->certkey = kore_strdup(path);
	return (KORE_RESULT_OK);
}

#endif /* !KORE_NO_TLS */

static int
configure_domain(char *options)
{
	char		*argv[3];

	if (current_domain != NULL) {
		printf("nested domain contexts are not allowed\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);

	if (strcmp(argv[1], "{")) {
		printf("domain context not opened correctly\n");
		return (KORE_RESULT_ERROR);
	}

	if (strlen(argv[0]) >= KORE_DOMAINNAME_LEN - 1) {
		printf("domain name '%s' too long\n", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_domain_new(argv[0])) {
		printf("could not create new domain %s\n", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	current_domain = kore_domain_lookup(argv[0]);
	return (KORE_RESULT_OK);
}

#if !defined(KORE_NO_HTTP)
static int
configure_static_handler(char *options)
{
	return (configure_handler(HANDLER_TYPE_STATIC, options));
}

static int
configure_dynamic_handler(char *options)
{
	return (configure_handler(HANDLER_TYPE_DYNAMIC, options));
}

static int
configure_handler(int type, char *options)
{
	char		*argv[4];

	if (current_domain == NULL) {
		printf("page handler not specified in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 4);

	if (argv[0] == NULL || argv[1] == NULL) {
		printf("missing parameters for page handler\n");
		return (KORE_RESULT_ERROR);
	}

	if (!kore_module_handler_new(argv[0],
	    current_domain->domain, argv[1], argv[2], type)) {
		printf("cannot create handler for %s\n", argv[0]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_accesslog(char *path)
{
	if (current_domain == NULL) {
		kore_debug("accesslog not specified in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->accesslog != -1) {
		printf("domain %s already has an open accesslog\n",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->accesslog = open(path,
	    O_CREAT | O_APPEND | O_WRONLY,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (current_domain->accesslog == -1) {
		printf("accesslog open(%s): %s\n", path, errno_s);
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
		printf("bad http_header_max value: %s\n", option);
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
		printf("bad http_body_max value: %s\n", option);
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
		printf("bad http_body_disk_offload value: %s\n", option);
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
configure_http_hsts_enable(char *option)
{
	int		err;

	http_hsts_enable = kore_strtonum(option, 10, 0, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_hsts_enable value: %s\n", option);
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
		printf("bad http_keepalive_time value: %s\n", option);
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
		printf("bad http_request_limit value: %s\n", option);
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
		printf("missing validator name\n");
		return (KORE_RESULT_ERROR);
	}

	*(tname)++ = '\0';
	tname = kore_text_trim(tname, strlen(tname));
	if ((value = strchr(tname, ' ')) == NULL) {
		printf("missing validator value\n");
		return (KORE_RESULT_ERROR);
	}

	*(value)++ = '\0';
	value = kore_text_trim(value, strlen(value));

	if (!strcmp(tname, "regex")) {
		type = KORE_VALIDATOR_TYPE_REGEX;
	} else if (!strcmp(tname, "function")) {
		type = KORE_VALIDATOR_TYPE_FUNCTION;
	} else {
		printf("bad type for validator %s\n", tname);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_validator_add(name, type, value)) {
		printf("bad validator specified: %s\n", tname);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_params(char *options)
{
	struct kore_module_handle	*hdlr;
	char				*argv[3];

	if (current_domain == NULL) {
		printf("params not used in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_handler != NULL) {
		printf("previous params block not closed\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (!strcasecmp(argv[0], "post")) {
		current_method = HTTP_METHOD_POST;
	} else if (!strcasecmp(argv[0], "get")) {
		current_method = HTTP_METHOD_GET;
	} else if (!strcasecmp(argv[0], "put")) {
		current_method = HTTP_METHOD_PUT;
	} else if (!strcasecmp(argv[0], "delete")) {
		current_method = HTTP_METHOD_DELETE;
	} else if (!strcasecmp(argv[0], "head")) {
		current_method = HTTP_METHOD_HEAD;
	} else {
		printf("unknown method: %s in params block for %s\n",
		    argv[0], argv[1]);
		return (KORE_RESULT_ERROR);
	}

	/*
	 * Find the handler ourselves, otherwise the regex is applied
	 * in case of a dynamic page.
	 */
	TAILQ_FOREACH(hdlr, &(current_domain->handlers), list) {
		if (!strcmp(hdlr->path, argv[1])) {
			current_handler = hdlr;
			return (KORE_RESULT_OK);
		}
	}

	printf("params for unknown page handler: %s\n", argv[1]);
	return (KORE_RESULT_ERROR);
}

static int
configure_validate(char *options)
{
	struct kore_handler_params	*p;
	struct kore_validator		*val;
	char				*argv[3];

	if (current_handler == NULL) {
		printf("validate not used in domain context\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if ((val = kore_validator_lookup(argv[1])) == NULL) {
		printf("unknown validator %s for %s\n", argv[1], argv[0]);
		return (KORE_RESULT_ERROR);
	}

	p = kore_malloc(sizeof(*p));
	p->validator = val;
	p->method = current_method;
	p->name = kore_strdup(argv[0]);

	TAILQ_INSERT_TAIL(&(current_handler->params), p, list);
	return (KORE_RESULT_OK);
}

static int
configure_authentication(char *options)
{
	char		*argv[3];

	if (current_auth != NULL) {
		printf("previous authentication block not closed\n");
		return (KORE_RESULT_ERROR);
	}

	kore_split_string(options, " ", argv, 3);
	if (argv[1] == NULL) {
		printf("missing name for authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[1], "{")) {
		printf("missing { for authentication block\n");
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
		printf("authentication_type outside authentication context\n");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(option, "cookie")) {
		current_auth->type = KORE_AUTH_TYPE_COOKIE;
	} else if (!strcmp(option, "header")) {
		current_auth->type = KORE_AUTH_TYPE_HEADER;
	} else if (!strcmp(option, "request")) {
		current_auth->type = KORE_AUTH_TYPE_REQUEST;
	} else {
		printf("unknown authentication type '%s'\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_authentication_value(char *option)
{
	if (current_auth == NULL) {
		printf("authentication_value outside authentication context\n");
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
		printf("authentication_validator outside authentication\n");
		return (KORE_RESULT_ERROR);
	}

	if ((val = kore_validator_lookup(validator)) == NULL) {
		printf("authentication validator '%s' not found\n", validator);
		return (KORE_RESULT_ERROR);
	}

	current_auth->validator = val;

	return (KORE_RESULT_OK);
}

static int
configure_authentication_uri(char *uri)
{
	if (current_auth == NULL) {
		printf("authentication_uri outside authentication context\n");
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
		printf("bad kore_websocket_maxframe value: %s\n", option);
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
		printf("bad kore_websocket_timeout value: %s\n", option);
		return (KORE_RESULT_ERROR);
	}

	kore_websocket_timeout = kore_websocket_timeout * 1000;

	return (KORE_RESULT_OK);
}

#endif /* !KORE_NO_HTTP */

static int
configure_chroot(char *path)
{
	if (chroot_path != NULL)
		kore_free(chroot_path);
	chroot_path = kore_strdup(path);

	return (KORE_RESULT_OK);
}

static int
configure_runas(char *user)
{
	if (runas_user != NULL)
		kore_free(runas_user);
	runas_user = kore_strdup(user);

	return (KORE_RESULT_OK);
}

static int
configure_workers(char *option)
{
	int		err;

	worker_count = kore_strtonum(option, 10, 1, 255, &err);
	if (err != KORE_RESULT_OK) {
		printf("%s is not a valid worker number\n", option);
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
		printf("bad value for worker_max_connections: %s\n", option);
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
		printf("bad value for worker_rlimit_nofiles: %s\n", option);
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
		printf("bad value for worker_accept_threshold: %s\n", option);
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
		printf("bad value for worker_set_affinity: %s\n", option);
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
		printf("bad socket_backlog value: %s\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static void
domain_tls_init(void)
{
	kore_domain_tlsinit(current_domain);
	current_domain = NULL;
}

#if defined(KORE_USE_PGSQL)
static int
configure_pgsql_conn_max(char *option)
{
	int		err;

	pgsql_conn_max = kore_strtonum(option, 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad value for pgsql_conn_max: %s\n", option);
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
		printf("bad value for task_threads: %s\n", option);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}
#endif

#if defined(KORE_USE_PYTHON)
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
