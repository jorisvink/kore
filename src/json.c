/*
 * Copyright (c) 2019-2022 Joris Vink <joris@coders.se>
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

#include <float.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "kore.h"

static int	json_guess_type(u_int8_t, u_int32_t *);
static int	json_next(struct kore_json *, u_int8_t *);
static int	json_peek(struct kore_json *, u_int8_t *);

static int	json_consume_whitespace(struct kore_json *);
static int	json_next_byte(struct kore_json *, u_int8_t *, int);

static char	*json_get_string(struct kore_json *);

static int	json_parse_array(struct kore_json *, struct kore_json_item *);
static int	json_parse_object(struct kore_json *, struct kore_json_item *);
static int	json_parse_string(struct kore_json *, struct kore_json_item *);
static int	json_parse_number(struct kore_json *, struct kore_json_item *);
static int	json_parse_literal(struct kore_json *, struct kore_json_item *);

static struct kore_json_item	*json_item_alloc(int, const char *,
				    struct kore_json_item *);
static struct kore_json_item	*json_find_item(struct kore_json_item *,
				    char **, u_int32_t, int);

static u_int8_t		json_null_literal[] = { 'n', 'u', 'l', 'l' };
static u_int8_t		json_true_literal[] = { 't', 'r', 'u', 'e' };
static u_int8_t		json_false_literal[] = { 'f', 'a', 'l', 's', 'e' };

static int		json_errno = 0;

static const char *json_errtab[] = {
	"no error",
	"invalid JSON object",
	"invalid JSON array",
	"invalid JSON string",
	"invalid JSON number",
	"invalid JSON literal",
	"too many nested items",
	"end of stream while parsing JSON",
	"invalid JSON",
	"invalid search query specified",
	"item not found",
	"item found, but not expected value"
};

void
kore_json_init(struct kore_json *json, const void *data, size_t len)
{
	memset(json, 0, sizeof(*json));

	json->data = data;
	json->length = len;

	kore_buf_init(&json->tmpbuf, 1024);
}

int
kore_json_parse(struct kore_json *json)
{
	u_int8_t	ch;
	u_int32_t	type;

	if (json->root)
		return (KORE_RESULT_OK);

	json_errno = 0;

	if (json_consume_whitespace(json) == -1) {
		json_errno = KORE_JSON_ERR_INVALID_JSON;
		return (KORE_RESULT_ERROR);
	}

	if (!json_peek(json, &ch))
		return (KORE_RESULT_ERROR);

	if (!json_guess_type(ch, &type)) {
		json_errno = KORE_JSON_ERR_INVALID_JSON;
		return (KORE_RESULT_ERROR);
	}

	json->root = json_item_alloc(type, NULL, NULL);

	if (!json->root->parse(json, json->root)) {
		if (json_errno == 0)
			json_errno = KORE_JSON_ERR_INVALID_JSON;
		return (KORE_RESULT_ERROR);
	}

	/* Don't allow garbage at the end. */
	(void)json_consume_whitespace(json);
	if (json->offset != json->length) {
		json_errno = KORE_JSON_ERR_INVALID_JSON;
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

struct kore_json_item *
kore_json_find(struct kore_json_item *root, const char *path, u_int32_t type)
{
	struct kore_json_item	*item;
	char			*copy;
	char			*tokens[KORE_JSON_DEPTH_MAX + 1];

	json_errno = 0;
	copy = kore_strdup(path);

	if (!kore_split_string(copy, "/", tokens, KORE_JSON_DEPTH_MAX)) {
		kore_free(copy);
		json_errno = KORE_JSON_ERR_INVALID_SEARCH;
		return (NULL);
	}

	item = json_find_item(root, tokens, type, 0);
	kore_free(copy);

	if (item == NULL && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_SEARCH;

	return (item);
}

void
kore_json_cleanup(struct kore_json *json)
{
	if (json == NULL)
		return;

	kore_buf_cleanup(&json->tmpbuf);
	kore_json_item_free(json->root);
}

int
kore_json_errno(void)
{
	return (json_errno);
}

const char *
kore_json_strerror(void)
{
	if (json_errno >= 0 && json_errno <= KORE_JSON_ERR_LAST)
		return (json_errtab[json_errno]);

	return ("unknown JSON error");
}

struct kore_json_item *
kore_json_create_item(struct kore_json_item *parent, const char *name,
    u_int32_t type, ...)
{
	const char			*p;
	va_list				args;
	struct kore_json_item		*item;

	item = kore_calloc(1, sizeof(*item));
	item->type = type;

	va_start(args, type);

	switch (item->type) {
	case KORE_JSON_TYPE_OBJECT:
		TAILQ_INIT(&item->data.items);
		break;
	case KORE_JSON_TYPE_ARRAY:
		TAILQ_INIT(&item->data.items);
		break;
	case KORE_JSON_TYPE_STRING:
		p = va_arg(args, const char *);
		item->data.string = kore_strdup(p);
		break;
	case KORE_JSON_TYPE_NUMBER:
		item->data.number = va_arg(args, double);
		break;
	case KORE_JSON_TYPE_INTEGER:
		item->data.integer = va_arg(args, int64_t);
		break;
	case KORE_JSON_TYPE_INTEGER_U64:
		item->data.u64 = va_arg(args, u_int64_t);
		break;
	case KORE_JSON_TYPE_LITERAL:
		item->data.literal = va_arg(args, int);
		break;
	default:
		fatal("%s: unknown type %d", __func__, item->type);
	}

	if (name)
		item->name = kore_strdup(name);

	if (parent) {
		if (parent->type != KORE_JSON_TYPE_OBJECT &&
		    parent->type != KORE_JSON_TYPE_ARRAY) {
			fatal("%s: invalid parent type (%d)",
			    __func__, parent->type);
		}

		TAILQ_INSERT_TAIL(&parent->data.items, item, list);
	}

	va_end(args);

	return (item);
}

void
kore_json_item_tobuf(struct kore_json_item *item, struct kore_buf *buf)
{
	struct kore_json_item	*nitem;

	if (item->name)
		kore_buf_appendf(buf, "\"%s\":", item->name);

	switch (item->type) {
	case KORE_JSON_TYPE_OBJECT:
		kore_buf_appendf(buf, "{");
		TAILQ_FOREACH(nitem, &item->data.items, list) {
			kore_json_item_tobuf(nitem, buf);

			if (TAILQ_NEXT(nitem, list))
				kore_buf_appendf(buf, ",");
		}
		kore_buf_appendf(buf, "}");
		break;
	case KORE_JSON_TYPE_ARRAY:
		kore_buf_appendf(buf, "[");
		TAILQ_FOREACH(nitem, &item->data.items, list) {
			kore_json_item_tobuf(nitem, buf);

			if (TAILQ_NEXT(nitem, list))
				kore_buf_appendf(buf, ",");
		}
		kore_buf_appendf(buf, "]");
		break;
	case KORE_JSON_TYPE_STRING:
		kore_buf_appendf(buf, "\"%s\"", item->data.string);
		break;
	case KORE_JSON_TYPE_NUMBER:
		kore_buf_appendf(buf, "%f", item->data.number);
		break;
	case KORE_JSON_TYPE_INTEGER:
		kore_buf_appendf(buf, "%" PRId64, item->data.integer);
		break;
	case KORE_JSON_TYPE_INTEGER_U64:
		kore_buf_appendf(buf, "%" PRIu64, item->data.u64);
		break;
	case KORE_JSON_TYPE_LITERAL:
		switch (item->data.literal) {
		case KORE_JSON_TRUE:
			kore_buf_append(buf,
			    json_true_literal, sizeof(json_true_literal));
			break;
		case KORE_JSON_FALSE:
			kore_buf_append(buf,
			    json_false_literal, sizeof(json_false_literal));
			break;
		case KORE_JSON_NULL:
			kore_buf_append(buf,
			    json_null_literal, sizeof(json_null_literal));
			break;
		default:
			fatal("%s: unknown literal %d", __func__,
			    item->data.literal);
		}
		break;
	default:
		fatal("%s: unknown type %d", __func__, item->type);
	}
}

void
kore_json_item_attach(struct kore_json_item *parent,
    struct kore_json_item *item)
{
	if (item->parent != NULL)
		fatal("%s: item already has parent", __func__);

	item->parent = parent;

	if (parent->type != KORE_JSON_TYPE_OBJECT &&
	    parent->type != KORE_JSON_TYPE_ARRAY) {
		fatal("%s: invalid parent type (%d)",
		    __func__, parent->type);
	}

	TAILQ_INSERT_TAIL(&parent->data.items, item, list);
}

static struct kore_json_item *
json_find_item(struct kore_json_item *object, char **tokens,
    u_int32_t type, int pos)
{
	char			*p, *str;
	struct kore_json_item	*item, *nitem;
	int			err, idx, spot;

	if (tokens[pos] == NULL)
		return (NULL);

	if (object->type != KORE_JSON_TYPE_OBJECT &&
	    object->type != KORE_JSON_TYPE_ARRAY)
		return (NULL);

	if ((str = strchr(tokens[pos], '[')) != NULL) {
		*(str)++ = '\0';

		if ((p = strchr(str, ']')) == NULL)
			return (NULL);

		*p = '\0';

		spot = kore_strtonum(str, 10, 0, USHRT_MAX, &err);
		if (err != KORE_RESULT_OK)
			return (NULL);
	} else {
		spot = -1;
	}

	item = NULL;

	TAILQ_FOREACH(item, &object->data.items, list) {
		if (item->name && strcmp(item->name, tokens[pos]))
			continue;

		if (item->type == KORE_JSON_TYPE_ARRAY && spot != -1) {
			idx = 0;
			nitem = NULL;
			TAILQ_FOREACH(nitem, &item->data.items, list) {
				if (idx++ == spot)
					break;
			}

			if (nitem == NULL) {
				json_errno = KORE_JSON_ERR_NOT_FOUND;
				return (NULL);
			}

			item = nitem;
		}

		if (tokens[pos + 1] == NULL) {
			/*
			 * If an uint64 was required and we find an item
			 * with the same name but marked as an integer check
			 * if it can be represented as a uint64.
			 *
			 * If it can, reduce the type to integer so we match
			 * on it as well.
			 */
			if (type == KORE_JSON_TYPE_INTEGER_U64 &&
			    item->type == KORE_JSON_TYPE_INTEGER) {
				if (item->data.integer >= 0)
					type = KORE_JSON_TYPE_INTEGER;
			}

			if (item->type == type)
				return (item);

			json_errno = KORE_JSON_ERR_TYPE_MISMATCH;
			return (NULL);
		}

		if (item->type == KORE_JSON_TYPE_OBJECT ||
		    item->type == KORE_JSON_TYPE_ARRAY) {
			item = json_find_item(item, tokens, type, pos + 1);
		} else {
			item = NULL;
		}

		break;
	}

	if (item == NULL && json_errno == 0)
		json_errno = KORE_JSON_ERR_NOT_FOUND;

	return (item);
}

void
kore_json_item_free(struct kore_json_item *item)
{
	struct kore_json_item	*node;

	if (item == NULL)
		return;

	switch (item->type) {
	case KORE_JSON_TYPE_OBJECT:
	case KORE_JSON_TYPE_ARRAY:
		while ((node = TAILQ_FIRST(&item->data.items)) != NULL) {
			TAILQ_REMOVE(&item->data.items, node, list);
			kore_json_item_free(node);
		}
		break;
	case KORE_JSON_TYPE_STRING:
		kore_free(item->data.string);
		break;
	case KORE_JSON_TYPE_NUMBER:
	case KORE_JSON_TYPE_LITERAL:
	case KORE_JSON_TYPE_INTEGER:
	case KORE_JSON_TYPE_INTEGER_U64:
		break;
	default:
		fatal("%s: unknown type %d", __func__, item->type);
	}

	kore_free(item->name);
	kore_free(item);
}

static struct kore_json_item *
json_item_alloc(int type, const char *name, struct kore_json_item *parent)
{
	struct kore_json_item	*item;

	item = kore_calloc(1, sizeof(*item));
	item->type = type;
	item->parent = parent;

	switch (item->type) {
	case KORE_JSON_TYPE_OBJECT:
		TAILQ_INIT(&item->data.items);
		item->parse = json_parse_object;
		break;
	case KORE_JSON_TYPE_ARRAY:
		TAILQ_INIT(&item->data.items);
		item->parse = json_parse_array;
		break;
	case KORE_JSON_TYPE_STRING:
		item->parse = json_parse_string;
		break;
	case KORE_JSON_TYPE_NUMBER:
	case KORE_JSON_TYPE_INTEGER:
	case KORE_JSON_TYPE_INTEGER_U64:
		item->parse = json_parse_number;
		break;
	case KORE_JSON_TYPE_LITERAL:
		item->parse = json_parse_literal;
		break;
	default:
		fatal("%s: unknown type %d", __func__, item->type);
	}

	if (name)
		item->name = kore_strdup(name);

	if (parent) {
		if (parent->type != KORE_JSON_TYPE_OBJECT &&
		    parent->type != KORE_JSON_TYPE_ARRAY) {
			fatal("%s: invalid parent type (%d)",
			    __func__, parent->type);
		}

		TAILQ_INSERT_TAIL(&parent->data.items, item, list);
	}

	return (item);
}

static int
json_peek(struct kore_json *json, u_int8_t *ch)
{
	return (json_next_byte(json, ch, 1));
}

static int
json_next(struct kore_json *json, u_int8_t *ch)
{
	return (json_next_byte(json, ch, 0));
}

static int
json_next_byte(struct kore_json *json, u_int8_t *ch, int peek)
{
	if (json->offset >= json->length) {
		json_errno = KORE_JSON_ERR_EOF;
		return (KORE_RESULT_ERROR);
	}

	*ch = json->data[json->offset];

	if (peek == 0)
		json->offset++;

	return (KORE_RESULT_OK);
}

static int
json_consume_whitespace(struct kore_json *json)
{
	u_int8_t	ch;

	for (;;) {
		if (!json_peek(json, &ch))
			return (KORE_RESULT_ERROR);

		if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
			break;

		json->offset++;
	}

	return (KORE_RESULT_OK);
}

static int
json_guess_type(u_int8_t ch, u_int32_t *type)
{
	if (ch == '-' || (ch >= '0' && ch <= '9')) {
		*type = KORE_JSON_TYPE_NUMBER;
		return (KORE_RESULT_OK);
	}

	switch (ch) {
	case '{':
		*type = KORE_JSON_TYPE_OBJECT;
		break;
	case '"':
		*type = KORE_JSON_TYPE_STRING;
		break;
	case '[':
		*type = KORE_JSON_TYPE_ARRAY;
		break;
	case 'f':
	case 'n':
	case 't':
		*type = KORE_JSON_TYPE_LITERAL;
		break;
	default:
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
json_parse_object(struct kore_json *json, struct kore_json_item *object)
{
	u_int8_t		ch;
	u_int32_t		type;
	char			*key;
	struct kore_json_item	*item;
	int			ret, hasnext;

	if (json->depth++ >= KORE_JSON_DEPTH_MAX) {
		json_errno = KORE_JSON_ERR_DEPTH;
		return (KORE_RESULT_ERROR);
	}

	key = NULL;
	hasnext = 0;
	ret = KORE_RESULT_ERROR;

	if (!json_next(json, &ch))
		goto cleanup;

	if (ch != '{')
		goto cleanup;

	for (;;) {
		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_peek(json, &ch))
			goto cleanup;

		switch (ch) {
		case '}':
			if (hasnext) {
				json_errno = KORE_JSON_ERR_INVALID_JSON;
				goto cleanup;
			}
			json->offset++;
			ret = KORE_RESULT_OK;
			goto cleanup;
		case '"':
			if ((key = json_get_string(json)) == NULL)
				goto cleanup;
			break;
		default:
			goto cleanup;
		}

		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_next(json, &ch))
			goto cleanup;

		if (ch != ':')
			goto cleanup;

		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_peek(json, &ch))
			goto cleanup;

		if (!json_guess_type(ch, &type))
			goto cleanup;

		item = json_item_alloc(type, key, object);

		if (!item->parse(json, item))
			goto cleanup;

		key = NULL;

		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_next(json, &ch))
			goto cleanup;

		if (ch == ',') {
			hasnext = 1;
			continue;
		}

		if (ch == '}') {
			ret = KORE_RESULT_OK;
			break;
		}

		break;
	}

cleanup:
	if (ret == KORE_RESULT_ERROR && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_OBJECT;

	json->depth--;

	return (ret);
}

static int
json_parse_array(struct kore_json *json, struct kore_json_item *array)
{
	u_int8_t		ch;
	u_int32_t		type;
	char			*key;
	struct kore_json_item	*item;
	int			ret, hasnext;

	if (json->depth++ >= KORE_JSON_DEPTH_MAX) {
		json_errno = KORE_JSON_ERR_DEPTH;
		return (KORE_RESULT_ERROR);
	}

	key = NULL;
	hasnext = 0;
	ret = KORE_RESULT_ERROR;

	if (!json_next(json, &ch))
		goto cleanup;

	if (ch != '[')
		goto cleanup;

	for (;;) {
		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_peek(json, &ch))
			goto cleanup;

		if (ch == ']') {
			if (hasnext) {
				json_errno = KORE_JSON_ERR_INVALID_JSON;
				goto cleanup;
			}
			json->offset++;
			ret = KORE_RESULT_OK;
			goto cleanup;
		}

		if (!json_guess_type(ch, &type))
			goto cleanup;

		item = json_item_alloc(type, key, array);

		if (!item->parse(json, item))
			goto cleanup;

		key = NULL;

		if (!json_consume_whitespace(json))
			goto cleanup;

		if (!json_next(json, &ch))
			goto cleanup;

		if (ch == ',') {
			hasnext = 1;
			continue;
		}

		if (ch == ']') {
			ret = KORE_RESULT_OK;
			break;
		}

		break;
	}

cleanup:
	if (ret == KORE_RESULT_ERROR && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_ARRAY;

	json->depth--;

	return (ret);
}

static int
json_parse_string(struct kore_json *json, struct kore_json_item *string)
{
	char		*value;

	if ((value = json_get_string(json)) == NULL)
		return (KORE_RESULT_ERROR);

	string->type = KORE_JSON_TYPE_STRING;
	string->data.string = kore_strdup(value);

	return (KORE_RESULT_OK);
}

static int
json_parse_number(struct kore_json *json, struct kore_json_item *number)
{
	u_int8_t	ch;
	int		ret;
	char		*str;
	u_int32_t	type;

	str = NULL;
	ret = KORE_RESULT_ERROR;
	kore_buf_reset(&json->tmpbuf);

	type = KORE_JSON_TYPE_NUMBER | KORE_JSON_TYPE_INTEGER |
	    KORE_JSON_TYPE_INTEGER_U64;

	for (;;) {
		if (!json_peek(json, &ch))
			break;

		switch (ch) {
		case 'e':
		case 'E':
		case '.':
			type = KORE_JSON_TYPE_NUMBER;
			kore_buf_append(&json->tmpbuf, &ch, sizeof(ch));
			json->offset++;
			continue;
		case '-':
			if (json->tmpbuf.offset != 0)
				goto cleanup;
			type &= ~KORE_JSON_TYPE_INTEGER_U64;
			/* FALLTHROUGH */
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '+':
			kore_buf_append(&json->tmpbuf, &ch, sizeof(ch));
			json->offset++;
			continue;
		}

		break;
	}

	if (type & KORE_JSON_TYPE_INTEGER_U64)
		type = KORE_JSON_TYPE_INTEGER_U64;

	if (type & KORE_JSON_TYPE_INTEGER)
		type = KORE_JSON_TYPE_INTEGER;

	str = kore_buf_stringify(&json->tmpbuf, NULL);

	switch (type) {
	case KORE_JSON_TYPE_NUMBER:
		number->data.number =
		    kore_strtodouble(str, -DBL_MAX, DBL_MAX, &ret);
		break;
	case KORE_JSON_TYPE_INTEGER:
		number->data.integer = (int64_t)kore_strtonum64(str, 1, &ret);
		break;
	case KORE_JSON_TYPE_INTEGER_U64:
		number->data.u64 = kore_strtonum64(str, 0, &ret);
		if (number->data.u64 <= INT64_MAX) {
			type = KORE_JSON_TYPE_INTEGER;
			number->data.integer = number->data.u64;
		}
		break;
	default:
		goto cleanup;
	}

	number->type = type;

cleanup:
	if (ret == KORE_RESULT_ERROR && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_NUMBER;

	return (ret);
}

static int
json_parse_literal(struct kore_json *json, struct kore_json_item *literal)
{
	size_t		len, idx;
	int		ret, val;
	u_int8_t	ch, *tmpl;

	ret = KORE_RESULT_ERROR;

	if (!json_next(json, &ch))
		goto cleanup;

	switch (ch) {
	case 'f':
		val = KORE_JSON_FALSE;
		tmpl = json_false_literal;
		len = sizeof(json_false_literal) - 1;
		break;
	case 'n':
		val = KORE_JSON_NULL;
		tmpl = json_null_literal;
		len = sizeof(json_null_literal) - 1;
		break;
	case 't':
		val = KORE_JSON_TRUE;
		tmpl = json_true_literal;
		len = sizeof(json_true_literal) - 1;
		break;
	default:
		goto cleanup;
	}

	for (idx = 0; idx < len; idx++) {
		if (!json_next(json, &ch))
			goto cleanup;

		if (ch != tmpl[idx + 1])
			goto cleanup;
	}

	literal->data.literal = val;
	literal->type = KORE_JSON_TYPE_LITERAL;

	ret = KORE_RESULT_OK;

cleanup:
	if (ret == KORE_RESULT_ERROR && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_LITERAL;

	return (ret);
}

static char *
json_get_string(struct kore_json *json)
{
	u_int8_t	ch;
	char		*res;

	res = NULL;

	if (!json_next(json, &ch))
		goto cleanup;

	if (ch != '"')
		goto cleanup;

	kore_buf_reset(&json->tmpbuf);

	for (;;) {
		if (!json_next(json, &ch))
			goto cleanup;

		if (ch == '"')
			break;

		if (ch <= 0x1f)
			goto cleanup;

		if (ch == '\\') {
			if (!json_next(json, &ch))
				goto cleanup;

			switch (ch) {
			case '\"':
			case '\\':
			case '/':
				break;
			case 'b':
				ch = '\b';
				break;
			case 'f':
				ch = '\f';
				break;
			case 'n':
				ch = '\n';
				break;
			case 'r':
				ch = '\r';
				break;
			case 't':
				ch = '\t';
				break;
			case 'u':
			default:
				/* XXX - not supported. */
				goto cleanup;
			}
		}

		kore_buf_append(&json->tmpbuf, &ch, sizeof(ch));
	}

	res = kore_buf_stringify(&json->tmpbuf, NULL);

cleanup:
	if (res == NULL && json_errno == 0)
		json_errno = KORE_JSON_ERR_INVALID_STRING;

	return (res);
}
