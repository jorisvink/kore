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
#include <sys/stat.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

static void		*mod_handle = NULL;
static time_t		mod_last_mtime = 0;

static TAILQ_HEAD(, kore_module_handle)		handlers;

void
kore_module_load(char *module_name)
{
	struct stat		st;

	kore_log("kore_module_load(%s)", module_name);

	if (mod_handle != NULL)
		fatal("site module already loaded, skipping %s", module_name);

	if (stat(module_name, &st) == -1)
		fatal("stat(%s): %s", module_name, errno_s);

	mod_last_mtime = st.st_mtime;
	mod_handle = dlopen(module_name, RTLD_NOW);
	if (mod_handle == NULL)
		fatal("%s", dlerror());

	TAILQ_INIT(&handlers);
}

int
kore_module_loaded(void)
{
	return (mod_handle != NULL ? KORE_RESULT_OK : KORE_RESULT_ERROR);
}

int
kore_module_handler_new(char *path, char *domain, char *func, int type)
{
	void				*addr;
	struct kore_module_handle	*hdlr;
	char				uri[512];

	kore_log("kore_module_handler_new(%s, %s, %s, %d)", path,
	    domain, func, type);

	addr = dlsym(mod_handle, func);
	if (addr == NULL) {
		kore_log("function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	snprintf(uri, sizeof(uri), "%s%s", domain, path);

	hdlr = (struct kore_module_handle *)kore_malloc(sizeof(*hdlr));
	hdlr->func = addr;
	hdlr->type = type;
	hdlr->uri = kore_strdup(uri);
	TAILQ_INSERT_TAIL(&(handlers), hdlr, list);

	return (KORE_RESULT_OK);
}

void *
kore_module_handler_find(char *domain, char *path)
{
	struct kore_module_handle	*hdlr;
	char				uri[512], *p;

	snprintf(uri, sizeof(uri), "%s%s", domain, path);
	p = strchr(uri, '.');

	TAILQ_FOREACH(hdlr, &handlers, list) {
		if (hdlr->uri[0] != '.' && !strcmp(hdlr->uri, uri))
			return (hdlr->func);
		if (hdlr->uri[0] == '.' && !strcmp(hdlr->uri, p))
			return (hdlr->func);
	}

	return (NULL);
}
