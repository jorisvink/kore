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

#include <sys/stat.h>

#include <dlfcn.h>

#include "kore.h"

static TAILQ_HEAD(, kore_module)	modules;
char					*kore_cb_name = NULL;

void
kore_module_init(void)
{
	TAILQ_INIT(&modules);
	TAILQ_INIT(&domains);
}

void
kore_module_load(char *path, char *onload)
{
	struct stat		st;
	struct kore_module	*module;

	kore_debug("kore_module_load(%s, %s)", path, onload);

	if (stat(path, &st) == -1)
		fatal("stat(%s): %s", path, errno_s);

	module = kore_malloc(sizeof(struct kore_module));
	module->path = kore_strdup(path);
	module->mtime = st.st_mtime;
	module->onload = NULL;

	module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
	if (module->handle == NULL)
		fatal("%s: %s", path, dlerror());

	if (onload != NULL) {
		module->onload = kore_strdup(onload);
		module->ocb = dlsym(module->handle, onload);
		if (module->ocb == NULL)
			fatal("%s: onload '%s' not present", path, onload);
		module->ocb(KORE_MODULE_LOAD);
	}

	if (kore_cb_name != NULL && kore_cb == NULL)
		kore_cb = dlsym(module->handle, kore_cb_name);

	TAILQ_INSERT_TAIL(&modules, module, list);
}

void
kore_module_reload(void)
{
	struct stat			st;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;
	struct kore_module		*module;

	kore_cb = NULL;

	TAILQ_FOREACH(module, &modules, list) {
		if (stat(module->path, &st) == -1) {
			kore_log(LOG_NOTICE, "stat(%s): %s, skipping reload",
			    module->path, errno_s);
			continue;
		}

		if (module->mtime == st.st_mtime)
			continue;

		if (module->ocb != NULL)
			module->ocb(KORE_MODULE_UNLOAD);

		module->mtime = st.st_mtime;
		if (dlclose(module->handle))
			fatal("cannot close existing module: %s", dlerror());

		module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
		if (module->handle == NULL)
			fatal("kore_module_reload(): %s", dlerror());

		if (module->onload != NULL) {
			module->ocb = dlsym(module->handle, module->onload);
			if (module->ocb == NULL) {
				fatal("%s: onload '%s' not present",
				    module->path, module->onload);
			}

			module->ocb(KORE_MODULE_LOAD);
		}

		if (kore_cb_name != NULL && kore_cb == NULL)
			kore_cb = dlsym(module->handle, kore_cb_name);

		kore_log(LOG_NOTICE, "reloaded '%s' module", module->path);
	}

	if (kore_cb_name != NULL && kore_cb == NULL)
		fatal("no kore_cb %s found in loaded modules", kore_cb_name);

	TAILQ_FOREACH(dom, &domains, list) {
		TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
			hdlr->addr = kore_module_getsym(hdlr->func);
			if (hdlr->func == NULL)
				fatal("no function '%s' found", hdlr->func);
			hdlr->errors = 0;
		}
	}

	kore_validator_reload();
}

int
kore_module_loaded(void)
{
	if (TAILQ_EMPTY(&modules))
		return (0);

	return (1);
}

int
kore_module_handler_new(char *path, char *domain, char *func, int type)
{
	void				*addr;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	kore_debug("kore_module_handler_new(%s, %s, %s, %d)", path,
	    domain, func, type);

	addr = kore_module_getsym(func);
	if (addr == NULL) {
		kore_debug("function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (KORE_RESULT_ERROR);

	hdlr = kore_malloc(sizeof(*hdlr));
	hdlr->errors = 0;
	hdlr->addr = addr;
	hdlr->type = type;
	TAILQ_INIT(&(hdlr->params));
	hdlr->path = kore_strdup(path);
	hdlr->func = kore_strdup(func);

	if (hdlr->type == HANDLER_TYPE_DYNAMIC) {
		if (regcomp(&(hdlr->rctx), hdlr->path,
		    REG_EXTENDED | REG_NOSUB)) {
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

struct kore_module_handle *
kore_module_handler_find(char *domain, char *path)
{
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (NULL);

	TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
		if (hdlr->type == HANDLER_TYPE_STATIC) {
			if (!strcmp(hdlr->path, path))
				return (hdlr);
		} else {
			if (!regexec(&(hdlr->rctx), path, 0, NULL, 0))
				return (hdlr);
		}
	}

	return (NULL);
}

void *
kore_module_getsym(char *symbol)
{
	void			*ptr;
	struct kore_module	*module;

	TAILQ_FOREACH(module, &modules, list) {
		ptr = dlsym(module->handle, symbol);
		if (ptr != NULL)
			return (ptr);
	}

	return (NULL);
}
