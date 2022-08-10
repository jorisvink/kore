/*
 * Copyright (c) 2020 Joris Vink <joris@coders.se>
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

/*
 * Simple static file serving over non TLS. Heavily used by myself
 * when working on kore-site.
 */

#include <sys/types.h>
#include <kore/kore.h>
#include <kore/hooks.h>

#include <stdlib.h>

static void
usage(void)
{
	fprintf(stderr,
	    "Usage: kore-serve [-i ip] [-p port] [-r root]\n");

	exit(1);
}

void
kore_parent_configure(int argc, char *argv[])
{
	int			ch;
	struct kore_domain	*dom;
	struct kore_server	*srv;
	char			*rpath;
	const char		*ip, *port, *root;

	root = ".";
	port = "8888";
	ip = "127.0.0.1";

	kore_quiet = 1;
	kore_foreground = 1;

	skip_runas = 1;
	skip_chroot = 1;

	kore_filemap_ext = kore_strdup(".html");

	while ((ch = getopt(argc, argv, "hi:p:r:")) != -1) {
		switch (ch) {
		case 'i':
			ip = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			root = optarg;
			break;
		default:
			usage();
		}
	}

	if ((rpath = realpath(root, NULL)) == NULL)
		fatal("realpath(%s): %s", root, errno_s);

	kore_log(LOG_INFO, "%s -> http://%s:%s", rpath, ip, port);

	srv = kore_server_create("kore-serve");
	srv->tls = 0;

	if (!kore_server_bind(srv, ip, port, NULL))
		fatal("Failed to bind to %s:%s (%s)", ip, port, errno_s);

	kore_server_finalize(srv);

	dom = kore_domain_new("*");
	kore_domain_attach(dom, srv);

	if (kore_filemap_create(dom, rpath, "/", NULL) == NULL)
		fatal("failed to create filemap for %s", rpath);
}
