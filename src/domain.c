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

#include <sys/param.h>
#include <sys/types.h>

#include <fnmatch.h>

#include "kore.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#if defined(KORE_USE_ACME)
#include "acme.h"
#endif

#define KORE_DOMAIN_CACHE	16

static u_int16_t		domain_id = 0;
struct kore_domain		*primary_dom = NULL;
static struct kore_domain	*cached[KORE_DOMAIN_CACHE];

void
kore_domain_init(void)
{
	int		i;

	for (i = 0; i < KORE_DOMAIN_CACHE; i++)
		cached[i] = NULL;
}

void
kore_domain_cleanup(void)
{
}

struct kore_domain *
kore_domain_new(const char *domain)
{
	struct kore_domain	*dom;

	dom = kore_calloc(1, sizeof(*dom));
	dom->id = domain_id++;

	dom->accesslog = -1;
	dom->x509_verify_depth = 1;

	dom->domain = kore_strdup(domain);

#if !defined(KORE_NO_HTTP)
	TAILQ_INIT(&dom->routes);
	TAILQ_INIT(&dom->redirects);
#endif

	if (dom->id < KORE_DOMAIN_CACHE) {
		if (cached[dom->id] != NULL)
			fatal("non free domain cache slot");
		cached[dom->id] = dom;
	}

	if (primary_dom == NULL)
		primary_dom = dom;

	return (dom);
}

int
kore_domain_attach(struct kore_domain *dom, struct kore_server *server)
{
	struct kore_domain	*d;

	if (dom->server != NULL)
		return (KORE_RESULT_ERROR);

	TAILQ_FOREACH(d, &server->domains, list) {
		if (!strcmp(d->domain, dom->domain))
			return (KORE_RESULT_ERROR);
	}

	dom->server = server;
	TAILQ_INSERT_TAIL(&server->domains, dom, list);

	/* The primary domain should be attached to a TLS context. */
	if (server->tls == 0 && dom == primary_dom)
		primary_dom = NULL;

	return (KORE_RESULT_OK);
}

void
kore_domain_free(struct kore_domain *dom)
{
#if !defined(KORE_NO_HTTP)
	struct kore_route		*rt;
	struct http_redirect		*rdr;
#endif
	if (dom == NULL)
		return;

	if (primary_dom == dom)
		primary_dom = NULL;

	TAILQ_REMOVE(&dom->server->domains, dom, list);

	if (dom->domain != NULL)
		kore_free(dom->domain);

	kore_tls_domain_cleanup(dom);

	kore_free(dom->cafile);
	kore_free(dom->certkey);
	kore_free(dom->certfile);
	kore_free(dom->crlfile);

#if !defined(KORE_NO_HTTP)
	/* Drop all handlers associated with this domain */
	while ((rt = TAILQ_FIRST(&dom->routes)) != NULL) {
		TAILQ_REMOVE(&dom->routes, rt, list);
		kore_route_free(rt);
	}

	while ((rdr = TAILQ_FIRST(&(dom->redirects))) != NULL) {
		TAILQ_REMOVE(&(dom->redirects), rdr, list);
		regfree(&rdr->rctx);
		kore_free(rdr->target);
		kore_free(rdr);
	}
#endif
	kore_free(dom);
}

void
kore_domain_callback(void (*cb)(struct kore_domain *))
{
	struct kore_server	*srv;
	struct kore_domain	*dom;

	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			cb(dom);
		}
	}
}

struct kore_domain *
kore_domain_lookup(struct kore_server *srv, const char *domain)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &srv->domains, list) {
		if (!strcmp(dom->domain, domain))
			return (dom);
		if (!fnmatch(dom->domain, domain, FNM_CASEFOLD))
			return (dom);
	}

	return (NULL);
}

struct kore_domain *
kore_domain_byid(u_int16_t id)
{
	struct kore_server	*srv;
	struct kore_domain	*dom;

	if (id < KORE_DOMAIN_CACHE)
		return (cached[id]);

	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			if (dom->id == id)
				return (dom);
		}
	}

	return (NULL);
}

/*
 * Called by the worker processes to close the file descriptor towards
 * the accesslog as they do not need it locally.
 */
void
kore_domain_closelogs(void)
{
	struct kore_server	*srv;
	struct kore_domain	*dom;

	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			if (dom->accesslog != -1) {
				(void)close(dom->accesslog);
				/*
				 * Turn into flag to indicate accesslogs
				 * are active.
				 */
				dom->accesslog = 1;
			} else {
				dom->accesslog = 0;
			}
		}
	}
}
