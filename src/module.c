/*
 * Copyright (c) 2013-2017 Joris Vink <joris@coders.se>
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

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#if defined(KORE_USE_PYTHON)
#include "python_api.h"
#endif

static TAILQ_HEAD(, kore_module)	modules;

static void	native_free(struct kore_module *);
static void	native_reload(struct kore_module *);
static void	native_load(struct kore_module *, const char *);
static void	*native_getsym(struct kore_module *, const char *);

struct kore_module_functions kore_native_module = {
	.free = native_free,
	.load = native_load,
	.getsym = native_getsym,
	.reload = native_reload,
};

void
kore_module_init(void)
{
	TAILQ_INIT(&modules);
}

void
kore_module_cleanup(void)
{
	struct kore_module	*module, *next;

	for (module = TAILQ_FIRST(&modules); module != NULL; module = next) {
		next = TAILQ_NEXT(module, list);
		TAILQ_REMOVE(&modules, module, list);
		module->fun->free(module);
	}
}

void
kore_module_load(const char *path, const char *onload, int type)
{
	struct stat		st;
	struct kore_module	*module;

	kore_debug("kore_module_load(%s, %s)", path, onload);

	module = kore_malloc(sizeof(struct kore_module));
	module->ocb = NULL;
	module->type = type;
	module->onload = NULL;
	module->handle = NULL;

	if (path != NULL) {
		if (stat(path, &st) == -1)
			fatal("stat(%s): %s", path, errno_s);

		module->path = kore_strdup(path);
		module->mtime = st.st_mtime;
	} else {
		module->path = NULL;
		module->mtime = 0;
	}

	switch (module->type) {
	case KORE_MODULE_NATIVE:
		module->fun = &kore_native_module;
		module->runtime = &kore_native_runtime;
		break;
#if defined(KORE_USE_PYTHON)
	case KORE_MODULE_PYTHON:
		module->fun = &kore_python_module;
		module->runtime = &kore_python_runtime;
		break;
#endif
	default:
		fatal("kore_module_load: unknown type %d", type);
	}

	module->fun->load(module, onload);
	TAILQ_INSERT_TAIL(&modules, module, list);

	if (onload != NULL) {
		module->ocb = kore_malloc(sizeof(*module->ocb));
		module->ocb->runtime = module->runtime;
		module->ocb->addr = module->fun->getsym(module, onload);

		if (module->ocb->addr == NULL) {
			fatal("%s: onload '%s' not present",
			    module->path, onload);
		}
	}
}

void
kore_module_onload(void)
{
	struct kore_module	*module;

	TAILQ_FOREACH(module, &modules, list) {
		if (module->path == NULL || module->ocb == NULL)
			continue;

		kore_runtime_onload(module->ocb, KORE_MODULE_LOAD);
	}
}

void
kore_module_reload(int cbs)
{
	struct stat			st;
	int				ret;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;
	struct kore_module		*module;

	TAILQ_FOREACH(module, &modules, list) {
		if (module->path == NULL)
			continue;

		if (stat(module->path, &st) == -1) {
			kore_log(LOG_NOTICE, "stat(%s): %s, skipping reload",
			    module->path, errno_s);
			continue;
		}

		if (module->mtime == st.st_mtime)
			continue;

		if (module->ocb != NULL && cbs == 1) {
			ret = kore_runtime_onload(module->ocb,
			    KORE_MODULE_UNLOAD);
			if (ret == KORE_RESULT_ERROR) {
				kore_log(LOG_NOTICE,
				    "%s forced no reloaded", module->path);
				continue;
			}
		}

		module->mtime = st.st_mtime;
		module->fun->reload(module);

		if (module->onload != NULL) {
			kore_free(module->ocb);
			module->ocb = kore_malloc(sizeof(*module->ocb));
			module->ocb->runtime = module->runtime;
			module->ocb->addr =
			    module->fun->getsym(module, module->onload);
			if (module->ocb->addr == NULL) {
				fatal("%s: onload '%s' not present",
				    module->path, module->onload);
			}
		}

		if (module->ocb != NULL && cbs == 1)
			kore_runtime_onload(module->ocb, KORE_MODULE_LOAD);

		kore_log(LOG_NOTICE, "reloaded '%s' module", module->path);
	}

	TAILQ_FOREACH(dom, &domains, list) {
		TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
			kore_free(hdlr->rcall);
			hdlr->rcall = kore_runtime_getcall(hdlr->func);
			if (hdlr->rcall == NULL)
				fatal("no function '%s' found", hdlr->func);
			hdlr->errors = 0;
		}
	}

#if !defined(KORE_NO_HTTP)
	kore_validator_reload();
#endif
}

int
kore_module_loaded(void)
{
	if (TAILQ_EMPTY(&modules))
		return (0);

	return (1);
}

#if !defined(KORE_NO_HTTP)
int
kore_module_handler_new(const char *path, const char *domain,
    const char *func, const char *auth, int type)
{
	struct kore_auth		*ap;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	kore_debug("kore_module_handler_new(%s, %s, %s, %s, %d)", path,
	    domain, func, auth, type);

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (KORE_RESULT_ERROR);

	if (auth != NULL) {
		if ((ap = kore_auth_lookup(auth)) == NULL)
			fatal("no authentication block '%s' found", auth);
	} else {
		ap = NULL;
	}

	hdlr = kore_malloc(sizeof(*hdlr));
	hdlr->auth = ap;
	hdlr->dom = dom;
	hdlr->errors = 0;
	hdlr->type = type;
	hdlr->path = kore_strdup(path);
	hdlr->func = kore_strdup(func);

	TAILQ_INIT(&(hdlr->params));

	if ((hdlr->rcall = kore_runtime_getcall(func)) == NULL) {
		kore_module_handler_free(hdlr);
		kore_log(LOG_ERR, "function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	if (hdlr->type == HANDLER_TYPE_DYNAMIC) {
		if (regcomp(&(hdlr->rctx), hdlr->path,
		    REG_EXTENDED | REG_NOSUB)) {
			kore_module_handler_free(hdlr);
			kore_debug("regcomp() on %s failed", path);
			return (KORE_RESULT_ERROR);
		}
	}

	TAILQ_INSERT_TAIL(&(dom->handlers), hdlr, list);
	return (KORE_RESULT_OK);
}

void
kore_module_handler_free(struct kore_module_handle *hdlr)
{
	struct kore_handler_params *param;

	if (hdlr == NULL)
		return;

	if (hdlr->func != NULL)
		kore_free(hdlr->func);
	if (hdlr->path != NULL)
		kore_free(hdlr->path);
	if (hdlr->type == HANDLER_TYPE_DYNAMIC)
		regfree(&(hdlr->rctx));

	/* Drop all validators associated with this handler */
	while ((param = TAILQ_FIRST(&(hdlr->params))) != NULL) {
		TAILQ_REMOVE(&(hdlr->params), param, list);
		if (param->name != NULL)
			kore_free(param->name);
		kore_free(param);
	}

	kore_free(hdlr);
}

struct kore_module_handle *
kore_module_handler_find(const char *domain, const char *path)
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
#endif /* !KORE_NO_HTTP */

void *
kore_module_getsym(const char *symbol, struct kore_runtime **runtime)
{
	void			*ptr;
	struct kore_module	*module;

	if (runtime != NULL)
		*runtime = NULL;

	TAILQ_FOREACH(module, &modules, list) {
		ptr = module->fun->getsym(module, symbol);
		if (ptr != NULL) {
			if (runtime != NULL)
				*runtime = module->runtime;
			return (ptr);
		}
	}

	return (NULL);
}

static void *
native_getsym(struct kore_module *module, const char *symbol)
{
	return (dlsym(module->handle, symbol));
}

static void
native_free(struct kore_module *module)
{
	kore_free(module->path);
	(void)dlclose(module->handle);
	kore_free(module);
}

static void
native_reload(struct kore_module *module)
{
	if (dlclose(module->handle))
		fatal("cannot close existing module: %s", dlerror());
	module->fun->load(module, module->onload);
}

static void
native_load(struct kore_module *module, const char *onload)
{
	module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
	if (module->handle == NULL)
		fatal("%s: %s", module->path, dlerror());
}
