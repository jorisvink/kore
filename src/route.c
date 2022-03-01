/*
 * Copyright (c) 2022 Joris Vink <joris@coders.se>
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
#include "http.h"

struct kore_route *
kore_route_create(struct kore_domain *dom, const char *path, int type)
{
	struct kore_route	*rt;

	rt = kore_calloc(1, sizeof(*rt));
	rt->dom = dom;
	rt->type = type;
	rt->path = kore_strdup(path);
	rt->methods = HTTP_METHOD_ALL;

	TAILQ_INIT(&rt->params);

	if (rt->type == HANDLER_TYPE_DYNAMIC) {
		if (regcomp(&rt->rctx, rt->path, REG_EXTENDED | REG_NOSUB)) {
			kore_route_free(rt);
			return (NULL);
		}
	}

	TAILQ_INSERT_TAIL(&dom->routes, rt, list);

	return (rt);
}

void
kore_route_free(struct kore_route *rt)
{
	struct kore_route_params	*param;

	if (rt == NULL)
		return;

	kore_free(rt->func);
	kore_free(rt->path);

	if (rt->type == HANDLER_TYPE_DYNAMIC)
		regfree(&rt->rctx);

	/* Drop all validators associated with this handler */
	while ((param = TAILQ_FIRST(&rt->params)) != NULL) {
		TAILQ_REMOVE(&rt->params, param, list);
		kore_free(param->name);
		kore_free(param);
	}

	kore_free(rt);
}

void
kore_route_callback(struct kore_route *rt, const char *func)
{
	if ((rt->rcall = kore_runtime_getcall(func)) == NULL)
		fatal("callback '%s' for '%s' not found", func, rt->path);

	kore_free(rt->func);
	rt->func = kore_strdup(func);
}

int
kore_route_lookup(struct http_request *req, struct kore_domain *dom,
    int method, struct kore_route **out)
{
	struct kore_route	*rt;
	int			exists;

	exists = 0;
	*out = NULL;

	TAILQ_FOREACH(rt, &dom->routes, list) {
		if (rt->type == HANDLER_TYPE_STATIC) {
			if (!strcmp(rt->path, req->path)) {
				if (rt->methods & method) {
					*out = rt;
					return (1);
				}
				exists++;
			}
		} else {
			if (!regexec(&rt->rctx, req->path,
			    HTTP_CAPTURE_GROUPS, req->cgroups, 0)) {
				if (rt->methods & method) {
					*out = rt;
					return (1);
				}
				exists++;
			}
		}
	}

	return (exists);
}

void
kore_route_reload(void)
{
	struct kore_route	*rt;
	struct kore_server	*srv;
	struct kore_domain	*dom;

	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			TAILQ_FOREACH(rt, &dom->routes, list) {
				kore_free(rt->rcall);
				rt->rcall = kore_runtime_getcall(rt->func);
				if (rt->rcall == NULL) {
					fatal("no function '%s' for route '%s'",
					    rt->func, rt->path);
				}
				rt->errors = 0;
			}
		}
	}
}
