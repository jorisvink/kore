/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
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
static void	native_load(struct kore_module *);
static void	native_reload(struct kore_module *);
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

struct kore_module *
kore_module_load(const char *path, const char *onload, int type)
{
	struct stat		st;
	struct kore_module	*module;

	module = kore_malloc(sizeof(struct kore_module));
	module->ocb = NULL;
	module->type = type;
	module->onload = NULL;
	module->handle = NULL;

	if (path != NULL) {
		if (stat(path, &st) == -1)
			fatal("stat(%s): %s", path, errno_s);

		module->path = kore_strdup(path);
	} else {
		module->path = NULL;
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

	module->fun->load(module);
	TAILQ_INSERT_TAIL(&modules, module, list);

	if (onload != NULL) {
		module->onload = kore_strdup(onload);
		module->ocb = kore_malloc(sizeof(*module->ocb));
		module->ocb->runtime = module->runtime;
		module->ocb->addr = module->fun->getsym(module, onload);

		if (module->ocb->addr == NULL) {
			fatal("%s: onload '%s' not present",
			    module->path, onload);
		}
	}

	return (module);
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
	struct kore_module		*module;

	TAILQ_FOREACH(module, &modules, list) {
		if (module->path == NULL)
			continue;

		if (stat(module->path, &st) == -1) {
			kore_log(LOG_NOTICE, "stat(%s): %s, skipping reload",
			    module->path, errno_s);
			continue;
		}

		if (module->ocb != NULL && cbs == 1) {
			ret = kore_runtime_onload(module->ocb,
			    KORE_MODULE_UNLOAD);
			if (ret == KORE_RESULT_ERROR) {
				kore_log(LOG_NOTICE,
				    "%s forced no reloaded", module->path);
				continue;
			}
		}

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

#if !defined(KORE_NO_HTTP)
	kore_route_reload();
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
	module->fun->load(module);
}

static void
native_load(struct kore_module *module)
{
	module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
	if (module->handle == NULL)
		fatal("%s: %s", module->path, dlerror());
}
