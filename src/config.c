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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

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
static void		domain_sslstart(void);

static struct {
	const char		*name;
	int			(*configure)(char **);
} config_names[] = {
	{ "bind",		configure_bind },
	{ "load",		configure_load },
	{ "onload",		configure_onload },
	{ "static",		configure_handler },
	{ "dynamic",		configure_handler },
	{ "domain",		configure_domain },
	{ "chroot",		configure_chroot },
	{ "runas",		configure_runas },
	{ "workers",		configure_workers },
	{ "pidfile",		configure_pidfile },
	{ "accesslog",		configure_accesslog },
	{ "certfile",		configure_certfile },
	{ "certkey",		configure_certkey },
	{ NULL,			NULL },
};

static struct kore_domain	*current_domain = NULL;

void
kore_parse_config(const char *config_path)
{
	FILE		*fp;
	int		i, lineno;
	char		buf[BUFSIZ], *p, *t, *argv[5];

	if ((fp = fopen(config_path, "r")) == NULL)
		fatal("configuration given cannot be opened: %s", config_path);

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
}

static int
configure_bind(char **argv)
{
	int		err;

	if (argv[1] == NULL || argv[2] == NULL)
		return (KORE_RESULT_ERROR);
	if (server_ip != NULL || server_port != 0) {
		kore_debug("duplicate bind directive seen");
		return (KORE_RESULT_ERROR);
	}

	server_ip = kore_strdup(argv[1]);
	server_port = kore_strtonum(argv[2], 1, 65535, &err);
	if (err != KORE_RESULT_OK) {
		kore_debug("%s is an invalid port number", argv[2]);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
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
configure_domain(char **argv)
{
	if (argv[2] == NULL)
		return (KORE_RESULT_ERROR);

	if (current_domain != NULL) {
		kore_debug("previous domain configuration not closed");
		return (KORE_RESULT_ERROR);
	}

	if (strcmp(argv[2], "{")) {
		kore_debug("missing { for domain directive");
		return (KORE_RESULT_ERROR);
	}

	if (!kore_domain_new(argv[1])) {
		kore_debug("could not create new domain %s", current_domain);
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
		kore_debug("missing domain for page handler");
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

	worker_count = kore_strtonum(argv[1], 1, 255, &err);
	if (err != KORE_RESULT_OK) {
		kore_debug("%s is not a correct worker number", argv[1]);
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
		kore_debug("missing domain for certfile");
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
		kore_debug("missing domain for certkey");
		return (KORE_RESULT_ERROR);
	}

	if (current_domain->certkey != NULL) {
		kore_debug("domain already has a certkey set");
		return (KORE_RESULT_ERROR);
	}

	current_domain->certkey = kore_strdup(argv[1]);
	return (KORE_RESULT_OK);
}

static void
domain_sslstart(void)
{
	kore_domain_sslstart(current_domain);
	current_domain = NULL;
}
