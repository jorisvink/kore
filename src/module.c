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
#include <syslog.h>
#include <regex.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

static void		*mod_handle = NULL;
static char		*mod_name = NULL;
static time_t		mod_last_mtime = 0;
char			*kore_module_onload = NULL;

void
kore_module_load(char *module_name)
{
	struct stat		st;
	void			(*onload)(void);

	kore_debug("kore_module_load(%s)", module_name);

	if (mod_handle != NULL)
		fatal("site module already loaded, skipping %s", module_name);

	if (stat(module_name, &st) == -1)
		fatal("stat(%s): %s", module_name, errno_s);

	mod_last_mtime = st.st_mtime;
	mod_handle = dlopen(module_name, RTLD_NOW);
	if (mod_handle == NULL)
		fatal("%s", dlerror());

	TAILQ_INIT(&domains);
	mod_name = kore_strdup(module_name);

	if (kore_module_onload != NULL) {
		onload = dlsym(mod_handle, kore_module_onload);
		if (onload == NULL)
			fatal("onload '%s' not present", kore_module_onload);
		onload();
	}
}

void
kore_module_reload(void)
{
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;
	void				(*onload)(void);

	if (dlclose(mod_handle))
		fatal("cannot close existing module: %s", dlerror());

	mod_handle = dlopen(mod_name, RTLD_NOW);
	if (mod_handle == NULL)
		fatal("kore_module_reload(): %s", dlerror());

	TAILQ_FOREACH(dom, &domains, list) {
		TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
			hdlr->addr = dlsym(mod_handle, hdlr->func);
			if (hdlr->func == NULL)
				fatal("no function '%s' found", hdlr->func);
		}
	}

	if (kore_module_onload != NULL) {
		onload = dlsym(mod_handle, kore_module_onload);
		if (onload == NULL)
			fatal("onload '%s' not present", kore_module_onload);
		onload();
	}

	kore_log(LOG_NOTICE, "reloaded '%s' module", mod_name);
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
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	kore_debug("kore_module_handler_new(%s, %s, %s, %d)", path,
	    domain, func, type);

	addr = dlsym(mod_handle, func);
	if (addr == NULL) {
		kore_debug("function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (KORE_RESULT_ERROR);

	hdlr = (struct kore_module_handle *)kore_malloc(sizeof(*hdlr));
	hdlr->addr = addr;
	hdlr->type = type;
	hdlr->path = kore_strdup(path);
	hdlr->func = kore_strdup(func);

	if (hdlr->type == HANDLER_TYPE_DYNAMIC) {
		if (regcomp(&(hdlr->rctx), hdlr->path, REG_NOSUB)) {
			kore_mem_free(hdlr->func);
			kore_mem_free(hdlr->path);
			kore_mem_free(hdlr);
			kore_debug("regcomp() on %s failed", path);
			return (KORE_RESULT_ERROR);
		}
	}

	TAILQ_INSERT_TAIL(&(dom->handlers), hdlr, list);
	return (KORE_RESULT_OK);
}

void *
kore_module_handler_find(char *domain, char *path)
{
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (NULL);

	TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
		if (hdlr->type == HANDLER_TYPE_STATIC) {
			if (!strcmp(hdlr->path, path))
				return (hdlr->addr);
		} else {
			if (!regexec(&(hdlr->rctx), path, 0, NULL, 0))
				return (hdlr->addr);
		}
	}

	return (NULL);
}
