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

#include "kore.h"

TAILQ_HEAD(, kore_validator)		validators;

void
kore_validator_init(void)
{
	TAILQ_INIT(&validators);
}

int
kore_validator_add(const char *name, u_int8_t type, const char *arg)
{
	int				ret;
	struct kore_validator		*val;

	val = kore_malloc(sizeof(*val));
	val->type = type;

	switch (val->type) {
	case KORE_VALIDATOR_TYPE_REGEX:
		ret = regcomp(&(val->rctx), arg, REG_EXTENDED | REG_NOSUB);
		if (ret) {
			kore_free(val);
			kore_log(LOG_NOTICE,
			    "validator %s has bad regex %s (%d)",
			    name, arg, ret);
			return (KORE_RESULT_ERROR);
		}
		break;
	case KORE_VALIDATOR_TYPE_FUNCTION:
		val->rcall = kore_runtime_getcall(arg);
		if (val->rcall == NULL) {
			kore_free(val);
			kore_log(LOG_NOTICE,
			    "validator %s has undefined callback %s",
			    name, arg);
			return (KORE_RESULT_ERROR);
		}
		break;
	default:
		kore_free(val);
		return (KORE_RESULT_ERROR);
	}

	val->arg = kore_strdup(arg);
	val->name = kore_strdup(name);
	TAILQ_INSERT_TAIL(&validators, val, list);

	return (KORE_RESULT_OK);
}

int
kore_validator_run(struct http_request *req, const char *name, char *data)
{
	struct kore_validator		*val;

	TAILQ_FOREACH(val, &validators, list) {
		if (strcmp(val->name, name))
			continue;

		return (kore_validator_check(req, val, data));
	}

	return (KORE_RESULT_ERROR);
}

int
kore_validator_check(struct http_request *req, struct kore_validator *val,
    const void *data)
{
	int		r;

	switch (val->type) {
	case KORE_VALIDATOR_TYPE_REGEX:
		if (!regexec(&(val->rctx), data, 0, NULL, 0))
			r = KORE_RESULT_OK;
		else
			r = KORE_RESULT_ERROR;
		break;
	case KORE_VALIDATOR_TYPE_FUNCTION:
		r = kore_runtime_validator(val->rcall, req, data);
		break;
	default:
		r = KORE_RESULT_ERROR;
		kore_log(LOG_NOTICE, "invalid type %d for validator %s",
		    val->type, val->name);
		break;
	}

	return (r);
}

void
kore_validator_reload(void)
{
	struct kore_validator		*val;

	TAILQ_FOREACH(val, &validators, list) {
		if (val->type != KORE_VALIDATOR_TYPE_FUNCTION)
			continue;

		kore_free(val->rcall);
		val->rcall = kore_runtime_getcall(val->arg);
		if (val->rcall == NULL)
			fatal("no function for validator %s found", val->arg);
	}
}

struct kore_validator *
kore_validator_lookup(const char *name)
{
	struct kore_validator		*val;

	TAILQ_FOREACH(val, &validators, list) {
		if (!strcmp(val->name, name))
			return (val);
	}

	return (NULL);
}
