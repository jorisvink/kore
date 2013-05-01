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
		fatal("dlopen(%s) failed", module_name);

	TAILQ_INIT(&handlers);
}

int
kore_module_loaded(void)
{
	return (mod_handle != NULL ? KORE_RESULT_OK : KORE_RESULT_ERROR);
}

int
kore_module_handler_new(char *uri, char *func, int type)
{
	void				*addr;
	struct kore_module_handle	*hdlr;

	kore_log("kore_module_handler_new(%s, %s, %d)", uri, func, type);

	addr = dlsym(mod_handle, func);
	if (addr == NULL) {
		kore_log("function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	hdlr = (struct kore_module_handle *)kore_malloc(sizeof(*hdlr));
	hdlr->uri = kore_strdup(uri);
	hdlr->func = addr;
	hdlr->type = type;
	TAILQ_INSERT_TAIL(&(handlers), hdlr, list);

	return (KORE_RESULT_OK);
}

void *
kore_module_handler_find(char *uri)
{
	struct kore_module_handle	*hdlr;

	TAILQ_FOREACH(hdlr, &handlers, list) {
		if (!strcmp(hdlr->uri, uri))
			return (hdlr->func);
	}

	return (NULL);
}
