/*
 * Copyright (c) 2013-2014 Joris Vink <joris@coders.se>
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

#include <sys/stat.h>

#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

/* XXX - This is becoming a clusterfuck. Fix it. */

static int		configure_include(char **);
static int		configure_bind(char **);
static int		configure_load(char **);
static int		configure_handler(char **);
static int		configure_domain(char **);
static int		configure_chroot(char **);
static int		configure_runas(char **);
static int		configure_workers(char **);
static int		configure_pidfile(char **);
static int		configure_accesslog(char **);
static int		configure_certfile(char **);
static int		configure_certkey(char **);
static int		configure_rlimit_nofiles(char **);
static int		configure_max_connections(char **);
static int		configure_ssl_cipher(char **);
static int		configure_ssl_dhparam(char **);
static int		configure_ssl_no_compression(char **);
static int		configure_spdy_idle_time(char **);
static int		configure_http_header_max(char **);
static int		configure_http_body_max(char **);
static int		configure_http_hsts_enable(char **);
static int		configure_http_keepalive_time(char **);
static int		configure_validator(char **);
static int		configure_params(char **);
static int		configure_validate(char **);
static int		configure_client_certificates(char **);
static int		configure_authentication(char **);
static int		configure_authentication_uri(char **);
static int		configure_authentication_type(char **);
static int		configure_authentication_value(char **);
static int		configure_authentication_validator(char **);
static int		configure_websocket_maxframe(char **);
static int		configure_websocket_timeout(char **);

#if defined(KORE_USE_PGSQL)
static int		configure_pgsql_conn_max(char **);
#endif

static void		domain_sslstart(void);
static void		kore_parse_config_file(char *);

static struct {
	const char		*name;
	int			(*configure)(char **);
} config_names[] = {
	{ "include",			configure_include },
	{ "bind",			configure_bind },
	{ "load",			configure_load },
	{ "static",			configure_handler },
	{ "dynamic",			configure_handler },
	{ "ssl_cipher",			configure_ssl_cipher },
	{ "ssl_dhparam",		configure_ssl_dhparam },
	{ "ssl_no_compression",		configure_ssl_no_compression },
	{ "spdy_idle_time",		configure_spdy_idle_time },
	{ "domain",			configure_domain },
	{ "chroot",			configure_chroot },
	{ "runas",			configure_runas },
	{ "workers",			configure_workers },
	{ "worker_max_connections",	configure_max_connections },
	{ "worker_rlimit_nofiles",	configure_rlimit_nofiles },
	{ "pidfile",			configure_pidfile },
	{ "accesslog",			configure_accesslog },
	{ "certfile",			configure_certfile },
	{ "certkey",			configure_certkey },
	{ "client_certificates",	configure_client_certificates },
	{ "http_header_max",		configure_http_header_max },
	{ "http_body_max",		configure_http_body_max },
	{ "http_hsts_enable",		configure_http_hsts_enable },
	{ "http_keepalive_time",	configure_http_keepalive_time },
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
#if defined(KORE_USE_PGSQL)
	{ "pgsql_conn_max",		configure_pgsql_conn_max },
#endif
	{ NULL,				NULL },
};

char					*config_file = NULL;
static u_int8_t				current_method = 0;
static struct kore_auth			*current_auth = NULL;
static struct kore_domain		*current_domain = NULL;
static struct kore_module_handle	*current_handler = NULL;

void
kore_parse_config(void)
{
	char		*p;

	kore_parse_config_file(config_file);

	if (!kore_module_loaded())
		fatal("no site module was loaded");

	if (LIST_EMPTY(&listeners))
		fatal("no listeners defined");

	if (skip_chroot != 1 && chroot_path == NULL)
		fatal("missing a chroot path");

	if (runas_user == NULL) {
		if ((p = getlogin()) == NULL)
			fatal("missing a username to run as");

		/* runas_user is free'd later down the line. */
		runas_user = kore_strdup(p);
	}

	if ((pw = getpwnam(runas_user)) == NULL)
		fatal("user '%s' does not exist", runas_user);

	if (getuid() != 0 && skip_chroot == 0)
		fatal("Cannot chroot(), use -n to skip it");
}

static void
kore_parse_config_file(char *fpath)
{
	FILE		*fp;
	int		i, lineno;
	char		buf[BUFSIZ], *p, *t, *argv[5];

	if ((fp = fopen(fpath, "r")) == NULL)
		fatal("configuration given cannot be opened: %s", fpath);

	kore_debug("parsing configuration file '%s'", fpath);

	lineno = 1;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		p = buf;
		buf[strcspn(buf, "\n")] = '\0';

		while (isspace(*p))
			p++;
		if (p[0] == '#' || p[0] == '\0') {
			lineno++;
			continue;
		}

		for (t = p; *t != '\0'; t++) {
			if (*t == '\t')
				*t = ' ';
		}

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

		if (!strcmp(p, "}") && current_domain != NULL)
			domain_sslstart();

		kore_split_string(p, " ", argv, 5);
		for (i = 0; config_names[i].name != NULL; i++) {
			if (!strcmp(config_names[i].name, argv[0])) {
				if (!config_names[i].configure(argv)) {
					fatal("configuration error on line %d",
					    lineno);
				}
				break;
			}
		}

		lineno++;
	}

	fclose(fp);
}

static int
configure_include(char **argv)
{
	if (argv[1] == NULL) {
		printf("No file given in include directive\n");
		return (KORE_RESULT_ERROR);
	}

	kore_parse_config_file(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_bind(char **argv)
{
	if (argv[1] == NULL || argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	return (kore_server_bind(argv[1], argv[2]));
}

static int
configure_load(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	kore_module_load(argv[1], argv[2]);
	return (KORE_RESULT_OK);
}

static int
configure_ssl_cipher(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (strcmp(kore_ssl_cipher_list, KORE_DEFAULT_CIPHER_LIST)) {
		kore_debug("duplicate ssl_cipher directive specified");
		return (KORE_RESULT_ERROR);
	}

	kore_ssl_cipher_list = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_ssl_dhparam(char **argv)
{
#if !defined(KORE_BENCHMARK)
	BIO		*bio;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (ssl_dhparam != NULL) {
		kore_debug("duplicate ssl_dhparam directive specified");
		return (KORE_RESULT_ERROR);
	}

	if ((bio = BIO_new_file(argv[1], "r")) == NULL) {
		printf("%s did not exist\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	ssl_dhparam = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (ssl_dhparam == NULL) {
		printf("PEM_read_bio_DHparams(): %s\n", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}
#endif
	return (KORE_RESULT_OK);
}

static int
configure_ssl_no_compression(char **argv)
{
	printf("ssl_no_compression is deprecated, and always on by default\n");
	return (KORE_RESULT_OK);
}

static int
configure_spdy_idle_time(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	spdy_idle_time = kore_strtonum(argv[1], 10, 0, 65535, &err);
	if (err != KORE_RESULT_OK) {
		printf("spdy_idle_time has invalid value: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	spdy_idle_time = spdy_idle_time * 1000;
	return (KORE_RESULT_OK);
}

static int
configure_domain(char **argv)
{
	if (argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	if (current_domain != NULL) {
		printf("previous domain configuration not closed\n");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[2], "{")) {
		printf("missing { for domain directive\n");
		return (KORE_RESULT_ERROR);
	}

	if (!kore_domain_new(argv[1])) {
		printf("could not create new domain %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	current_domain = kore_domain_lookup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_handler(char **argv)
{
	int		type;

	if (current_domain == NULL) {
		printf("missing domain for page handler\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL || argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	if (!strcmp(argv[0], "static"))
		type = HANDLER_TYPE_STATIC;
	else if (!strcmp(argv[0], "dynamic"))
		type = HANDLER_TYPE_DYNAMIC;
	else
		return (KORE_RESULT_ERROR);

	if (!kore_module_handler_new(argv[1],
	    current_domain->domain, argv[2], argv[3], type)) {
		kore_debug("cannot create handler for %s", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_client_certificates(char **argv)
{
	if (current_domain == NULL) {
		printf("missing domain for require_client_cert\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL) {
		printf("missing argument for require_client_cert\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->cafile != NULL) {
		printf("require_client_cert already set for %s\n",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->cafile = kore_strdup(argv[1]);
	if (argv[2] != NULL)
		current_domain->crlfile = kore_strdup(argv[2]);

	return (KORE_RESULT_OK);
}

static int
configure_chroot(char **argv)
{
	if (chroot_path != NULL) {
		kore_debug("duplicate chroot path specified");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	chroot_path = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_runas(char **argv)
{
	if (runas_user != NULL) {
		kore_debug("duplicate runas user specified");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	runas_user = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_workers(char **argv)
{
	int		err;

	if (worker_count != 0) {
		kore_debug("duplicate worker directive specified");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	worker_count = kore_strtonum(argv[1], 10, 1, 255, &err);
	if (err != KORE_RESULT_OK) {
		printf("%s is not a correct worker number\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_pidfile(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (strcmp(kore_pidfile, KORE_PIDFILE_DEFAULT)) {
		kore_debug("duplicate pidfile directive specified");
		return (KORE_RESULT_ERROR);
	}

	kore_pidfile = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_accesslog(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (current_domain == NULL) {
		kore_debug("missing domain for accesslog");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->accesslog != -1) {
		kore_debug("domain %s already has an open accesslog",
		    current_domain->domain);
		return (KORE_RESULT_ERROR);
	}

	current_domain->accesslog = open(argv[1],
	    O_CREAT | O_APPEND | O_WRONLY,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (current_domain->accesslog == -1) {
		kore_debug("open(%s): %s", argv[1], errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_certfile(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (current_domain == NULL) {
		printf("missing domain for certfile\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->certfile != NULL) {
		kore_debug("domain already has a certfile set");
		return (KORE_RESULT_ERROR);
	}

	current_domain->certfile = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_certkey(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (current_domain == NULL) {
		printf("missing domain for certkey\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->certkey != NULL) {
		kore_debug("domain already has a certkey set");
		return (KORE_RESULT_ERROR);
	}

	current_domain->certkey = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_max_connections(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	worker_max_connections = kore_strtonum(argv[1], 10, 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad value for worker_max_connections: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_rlimit_nofiles(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	worker_rlimit_nofiles = kore_strtonum(argv[1], 10, 1, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad value for worker_rlimit_nofiles: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_header_max(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (http_header_max != HTTP_HEADER_MAX_LEN) {
		kore_debug("http_header_max already set");
		return (KORE_RESULT_ERROR);
	}

	http_header_max = kore_strtonum(argv[1], 10, 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_header_max value: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_body_max(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (http_body_max != HTTP_BODY_MAX_LEN) {
		kore_debug("http_body_max already set");
		return (KORE_RESULT_ERROR);
	}

	http_body_max = kore_strtonum(argv[1], 10, 1, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_body_max value: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_hsts_enable(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (http_hsts_enable != HTTP_HSTS_ENABLE) {
		kore_debug("http_hsts_enable already set");
		return (KORE_RESULT_ERROR);
	}

	http_hsts_enable = kore_strtonum(argv[1], 10, 0, LONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_hsts_enable value: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_http_keepalive_time(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (http_keepalive_time != HTTP_KEEPALIVE_TIME) {
		kore_debug("http_keepalive_time already set");
		return (KORE_RESULT_ERROR);
	}

	http_keepalive_time = kore_strtonum(argv[1], 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_keepalive_time value: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_validator(char **argv)
{
	u_int8_t	type;

	if (argv[3] == NULL)
		return (KORE_RESULT_ERROR);

	if (!strcmp(argv[2], "regex")) {
		type = KORE_VALIDATOR_TYPE_REGEX;
	} else if (!strcmp(argv[2], "function")) {
		type = KORE_VALIDATOR_TYPE_FUNCTION;
	} else {
		printf("bad type for validator %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_validator_add(argv[1], type, argv[3])) {
		printf("bad validator specified: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_params(char **argv)
{
	struct kore_module_handle	*hdlr;

	if (current_domain == NULL) {
		printf("params keyword used in wrong context\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_handler != NULL) {
		printf("previous params block not closed\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	if (!strcasecmp(argv[1], "post")) {
		current_method = HTTP_METHOD_POST;
	} else if (!strcasecmp(argv[1], "get")) {
		current_method = HTTP_METHOD_GET;
	} else {
		printf("unknown method: %s in params block for %s\n",
		    argv[1], argv[2]);
		return (KORE_RESULT_ERROR);
	}

	/*
	 * Find the handler ourselves, otherwise the regex is applied
	 * in case of a dynamic page.
	 */
	TAILQ_FOREACH(hdlr, &(current_domain->handlers), list) {
		if (!strcmp(hdlr->path, argv[2])) {
			current_handler = hdlr;
			return (KORE_RESULT_OK);
		}
	}

	printf("params for unknown page handler: %s\n", argv[2]);
	return (KORE_RESULT_ERROR);
}

static int
configure_validate(char **argv)
{
	struct kore_handler_params	*p;
	struct kore_validator		*val;

	if (current_handler == NULL) {
		printf("validate keyword used in wrong context\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	if ((val = kore_validator_lookup(argv[2])) == NULL) {
		printf("unknown validator %s for %s\n", argv[2], argv[1]);
		return (KORE_RESULT_ERROR);
	}

	p = kore_malloc(sizeof(*p));
	p->validator = val;
	p->method = current_method;
	p->name = kore_strdup(argv[1]);

	TAILQ_INSERT_TAIL(&(current_handler->params), p, list);

	return (KORE_RESULT_OK);
}

static int
configure_authentication(char **argv)
{
	if (argv[2] == NULL) {
		printf("Missing name for authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth != NULL) {
		printf("Previous authentication block not closed\n");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[2], "{")) {
		printf("missing { for authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (!kore_auth_new(argv[1]))
		return (KORE_RESULT_ERROR);

	current_auth = kore_auth_lookup(argv[1]);

	return (KORE_RESULT_OK);
}

static int
configure_authentication_type(char **argv)
{
	if (current_auth == NULL) {
		printf("authentication_type outside authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL) {
		printf("missing parameter for authentication_type\n");
		return (KORE_RESULT_ERROR);
	}

	if (!strcmp(argv[1], "cookie")) {
		current_auth->type = KORE_AUTH_TYPE_COOKIE;
	} else if (!strcmp(argv[1], "header")) {
		current_auth->type = KORE_AUTH_TYPE_HEADER;
	} else {
		printf("unknown authentication type '%s'\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_authentication_value(char **argv)
{
	if (current_auth == NULL) {
		printf("authentication_value outside authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL) {
		printf("missing parameter for authentication_value\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth->value != NULL) {
		printf("duplicate authentication_value found\n");
		return (KORE_RESULT_ERROR);
	}

	current_auth->value = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_authentication_validator(char **argv)
{
	struct kore_validator		*val;

	if (current_auth == NULL) {
		printf("authentication_validator outside authentication\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL) {
		printf("missing parameter for authentication_validator\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth->validator != NULL) {
		printf("duplicate authentication_validator found\n");
		return (KORE_RESULT_ERROR);
	}

	if ((val = kore_validator_lookup(argv[1])) == NULL) {
		printf("authentication validator '%s' not found\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	current_auth->validator = val;

	return (KORE_RESULT_OK);
}

static int
configure_authentication_uri(char **argv)
{
	if (current_auth == NULL) {
		printf("authentication_uri outside authentication block\n");
		return (KORE_RESULT_ERROR);
	}

	if (argv[1] == NULL) {
		printf("missing parameter for authentication_uri\n");
		return (KORE_RESULT_ERROR);
	}

	if (current_auth->redirect != NULL) {
		printf("duplicate authentication_uri found\n");
		return (KORE_RESULT_ERROR);
	}

	current_auth->redirect = kore_strdup(argv[1]);

	return (KORE_RESULT_OK);
}

static int
configure_websocket_maxframe(char **argv)
{
	int	err;

	if (argv[1] == NULL) {
		printf("missing parameter for kore_websocket_maxframe\n");
		return (KORE_RESULT_ERROR);
	}

	kore_websocket_maxframe = kore_strtonum64(argv[1], 1, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad kore_websocket_maxframe value\n");
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_websocket_timeout(char **argv)
{
	int	err;

	if (argv[1] == NULL) {
		printf("missing parameter for kore_websocket_timeout\n");
		return (KORE_RESULT_ERROR);
	}

	kore_websocket_timeout = kore_strtonum64(argv[1], 1, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad kore_websocket_timeout value\n");
		return (KORE_RESULT_ERROR);
	}

	kore_websocket_timeout = kore_websocket_timeout * 1000;

	return (KORE_RESULT_OK);
}

static void
domain_sslstart(void)
{
	kore_domain_sslstart(current_domain);
	current_domain = NULL;
}

#if defined(KORE_USE_PGSQL)

static int
configure_pgsql_conn_max(char **argv)
{
	int		err;

	if (argv[1] == NULL) {
		printf("missing parameter for pgsql_conn_max\n");
		return (KORE_RESULT_ERROR);
	}

	pgsql_conn_max = kore_strtonum(argv[1], 10, 0, USHRT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad value for pgsql_conn_max: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

#endif
