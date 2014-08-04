/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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

#include <ctype.h>

#include "kore.h"
#include "http.h"

TAILQ_HEAD(, kore_auth)		auth_list;

static int	kore_auth_cookie(struct http_request *, struct kore_auth *);
static int	kore_auth_header(struct http_request *, struct kore_auth *);
static int	kore_auth_request(struct http_request *, struct kore_auth *);

void
kore_auth_init(void)
{
	TAILQ_INIT(&auth_list);
}

int
kore_auth_new(const char *name)
{
	struct kore_auth	*auth;

	if ((auth = kore_auth_lookup(name)) != NULL)
		return (KORE_RESULT_ERROR);

	auth = kore_malloc(sizeof(*auth));
	auth->type = 0;
	auth->value = NULL;
	auth->redirect = NULL;
	auth->validator = NULL;
	auth->name = kore_strdup(name);

	TAILQ_INSERT_TAIL(&auth_list, auth, list);

	return (KORE_RESULT_OK);
}

int
kore_auth(struct http_request *req, struct kore_auth *auth)
{
	int		r;

	kore_debug("kore_auth(%p, %p)", req, auth);

	switch (auth->type) {
	case KORE_AUTH_TYPE_COOKIE:
		r = kore_auth_cookie(req, auth);
		break;
	case KORE_AUTH_TYPE_HEADER:
		r = kore_auth_header(req, auth);
		break;
	case KORE_AUTH_TYPE_REQUEST:
		r = kore_auth_request(req, auth);
		break;
	default:
		kore_log(LOG_NOTICE, "unknown auth type %d", auth->type);
		return (KORE_RESULT_ERROR);
	}

	switch (r) {
	case KORE_RESULT_OK:
		kore_debug("kore_auth() for %s successful", req->path);
		/* FALLTHROUGH */
	case KORE_RESULT_RETRY:
		return (r);
	default:
		break;
	}

	kore_debug("kore_auth() for %s failed", req->path);

	if (auth->redirect == NULL) {
		http_response(req, 403, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	http_response_header_add(req, "location", auth->redirect);
	http_response(req, 302, NULL, 0);

	return (KORE_RESULT_ERROR);
}

static int
kore_auth_cookie(struct http_request *req, struct kore_auth *auth)
{
	int		i, v;
	size_t		len, slen;
	char		*value, *c, *cookie, *cookies[HTTP_MAX_COOKIES];

	if (!http_request_header_get(req, "cookie", &cookie))
		return (KORE_RESULT_ERROR);

	slen = strlen(auth->value);
	v = kore_split_string(cookie, ";", cookies, HTTP_MAX_COOKIES);
	for (i = 0; i < v; i++) {
		for (c = cookies[i]; isspace(*c); c++)
			;

		len = MIN(slen, strlen(cookies[i]));
		if (!strncmp(c, auth->value, len))
			break;
	}

	if (i == v) {
		kore_mem_free(cookie);
		return (KORE_RESULT_ERROR);
	}

	c = cookies[i];
	if ((value = strchr(c, '=')) == NULL) {
		kore_mem_free(cookie);
		return (KORE_RESULT_ERROR);
	}

	i = kore_validator_check(req, auth->validator, ++value);
	kore_mem_free(cookie);

	return (i);
}

static int
kore_auth_header(struct http_request *req, struct kore_auth *auth)
{
	int		r;
	char		*header;

	if (!http_request_header_get(req, auth->value, &header))
		return (KORE_RESULT_ERROR);

	r = kore_validator_check(req, auth->validator, header);
	kore_mem_free(header);

	return (r);
}

static int
kore_auth_request(struct http_request *req, struct kore_auth *auth)
{
	return (kore_validator_check(req, auth->validator, req));
}

struct kore_auth *
kore_auth_lookup(const char *name)
{
	struct kore_auth	*auth;

	TAILQ_FOREACH(auth, &auth_list, list) {
		if (!strcmp(auth->name, name))
			return (auth);
	}

	return (NULL);
}
