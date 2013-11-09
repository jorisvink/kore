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

#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>

#include "kore.h"
#include "http.h"

static int		configure_bind(char **);
static int		configure_load(char **);
static int		configure_onload(char **);
static int		configure_handler(char **);
static int		configure_domain(char **);
static int		configure_chroot(char **);
static int		configure_runas(char **);
static int		configure_workers(char **);
static int		configure_pidfile(char **);
static int		configure_accesslog(char **);
static int		configure_certfile(char **);
static int		configure_certkey(char **);
static int		configure_max_connections(char **);
static int		configure_ssl_cipher(char **);
static int		configure_ssl_dhparam(char **);
static int		configure_ssl_no_compression(char **);
static int		configure_spdy_idle_time(char **);
static int		configure_kore_cb(char **);
static int		configure_kore_cb_interval(char **);
static int		configure_kore_cb_worker(char **);
static int		configure_http_header_max(char **);
static int		configure_http_postbody_max(char **);
static int		configure_http_hsts_enable(char **);
static int		configure_http_keepalive_time(char **);
static int		configure_validator(char **);
static void		domain_sslstart(void);

static struct {
	const char		*name;
	int			(*configure)(char **);
} config_names[] = {
	{ "bind",			configure_bind },
	{ "load",			configure_load },
	{ "onload",			configure_onload },
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
	{ "pidfile",			configure_pidfile },
	{ "accesslog",			configure_accesslog },
	{ "certfile",			configure_certfile },
	{ "certkey",			configure_certkey },
	{ "kore_cb",			configure_kore_cb },
	{ "kore_cb_worker",		configure_kore_cb_worker },
	{ "kore_cb_interval",		configure_kore_cb_interval },
	{ "http_header_max",		configure_http_header_max },
	{ "http_postbody_max",		configure_http_postbody_max },
	{ "http_hsts_enable",		configure_http_hsts_enable },
	{ "http_keepalive_time",	configure_http_keepalive_time },
	{ "validator",			configure_validator },
	{ NULL,				NULL },
};

char				*config_file = NULL;
static struct kore_domain	*current_domain = NULL;

void
kore_parse_config(void)
{
	FILE		*fp;
	int		i, lineno;
	char		buf[BUFSIZ], *p, *t, *argv[5];

	if (config_file == NULL)
		fatal("specify a configuration file with -c");

	if ((fp = fopen(config_file, "r")) == NULL)
		fatal("configuration given cannot be opened: %s", config_file);

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

	if (!kore_module_loaded())
		fatal("no site module was loaded");

	if (LIST_EMPTY(&listeners))
		fatal("no listeners defined");
	if (chroot_path == NULL)
		fatal("missing a chroot path");
	if (runas_user == NULL)
		fatal("missing a username to run as");
	if ((pw = getpwnam(runas_user)) == NULL)
		fatal("user '%s' does not exist", runas_user);
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

	kore_module_load(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_onload(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (kore_module_onload != NULL) {
		kore_debug("duplicate onload directive found");
		return (KORE_RESULT_ERROR);
	}

	kore_module_onload = kore_strdup(argv[1]);
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

	return (KORE_RESULT_OK);
}

static int
configure_ssl_no_compression(char **argv)
{
	ssl_no_compression = 1;

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
	    current_domain->domain, argv[2], type)) {
		kore_debug("cannot create handler for %s", argv[1]);
		return (KORE_RESULT_ERROR);
	}

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
	    O_CREAT | O_APPEND | O_WRONLY, 0755);
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
configure_kore_cb(char **argv)
{
	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (kore_cb_name != NULL) {
		kore_debug("kore_cb was already set");
		return (KORE_RESULT_ERROR);
	}

	kore_cb_name = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static int
configure_kore_cb_interval(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (kore_cb_interval != 0) {
		kore_debug("kore_cb_interval already given");
		return (KORE_RESULT_ERROR);
	}

	kore_cb_interval = kore_strtonum(argv[1], 10, 1, LLONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("invalid value for kore_cb_interval: %s\n", argv[1]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
configure_kore_cb_worker(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (kore_cb_worker != -1) {
		kore_debug("kore_cb_worker already set");
		return (KORE_RESULT_ERROR);
	}

	kore_cb_worker = kore_strtonum(argv[1], 10, 0, worker_count, &err);
	if (err != KORE_RESULT_OK) {
		printf("invalid value for kore_cb_worker: %s\n", argv[1]);
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
configure_http_postbody_max(char **argv)
{
	int		err;

	if (argv[1] == NULL)
		return (KORE_RESULT_ERROR);

	if (http_postbody_max != HTTP_POSTBODY_MAX_LEN) {
		kore_debug("http_postbody_max already set");
		return (KORE_RESULT_ERROR);
	}

	http_postbody_max = kore_strtonum(argv[1], 10, 1, ULONG_MAX, &err);
	if (err != KORE_RESULT_OK) {
		printf("bad http_postbody_max value: %s\n", argv[1]);
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

	http_hsts_enable = kore_strtonum(argv[1], 10, 0, ULONG_MAX, &err);
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

static void
domain_sslstart(void)
{
	kore_domain_sslstart(current_domain);
	current_domain = NULL;
}
