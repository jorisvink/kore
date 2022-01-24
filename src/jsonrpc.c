/*
 * Copyright (c) 2016 Raphaël Monrouzeau <raphael.monrouzeau@gmail.com>
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

#include <limits.h>
#include <stdbool.h>

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#include "kore.h"
#include "http.h"
#include "jsonrpc.h"

static void
init_log(struct jsonrpc_log *log)
{
	log->msg = NULL;
	log->next = log;
	log->prev = log;
}

static void
append_log(struct jsonrpc_log *prev, int lvl, char *msg)
{
	struct jsonrpc_log *new = kore_malloc(sizeof(struct jsonrpc_log));

	new->lvl = lvl;
	new->msg = msg;

	new->prev = prev;
	new->next = prev->next;
	prev->next->prev = new;
	prev->next = new;
}

static void
free_log(struct jsonrpc_log *root)
{
	for (struct jsonrpc_log *it = root->next; it != root; it = it->next) {
		kore_free(it);
	}
}

static void
init_request(struct jsonrpc_request *req)
{
	init_log(&req->log);
	kore_buf_init(&req->buf, 256);
	req->gen = NULL;
	req->http = NULL;
	req->json = NULL;
	req->id = NULL;
	req->method = NULL;
	req->params = NULL;
	req->log_levels = (1 << LOG_EMERG) | (1 << LOG_ERR) | (1 << LOG_WARNING)
			| (1 << LOG_NOTICE);
        req->flags = 0;
}

void
jsonrpc_destroy_request(struct jsonrpc_request *req)
{
	if (req->gen != NULL) {
		yajl_gen_free(req->gen);
		req->gen = NULL;
	}
	if (req->json != NULL) {
		yajl_tree_free(req->json);
		req->json = NULL;
	}
	kore_buf_cleanup(&req->buf);
	free_log(&req->log);
}

void
jsonrpc_log(struct jsonrpc_request *req, int lvl, const char *fmt, ...)
{
	va_list	ap;
	char	*msg;
	size_t	start = req->buf.offset;

	va_start(ap, fmt);
	kore_buf_appendv(&req->buf, fmt, ap);
	va_end(ap);

	msg = kore_buf_stringify(&req->buf, NULL) + start;

	append_log(&req->log, lvl, msg);
}

static int
read_json_body(struct http_request *http_req, struct jsonrpc_request *req)
{
	char		*body_string;
	ssize_t		body_len = 0, chunk_len;
	u_int8_t	chunk_buffer[BUFSIZ];
	char		error_buffer[1024];

	for (;;) {
		chunk_len = http_body_read(http_req, chunk_buffer,
			sizeof(chunk_buffer));
		if (chunk_len == -1) {
			jsonrpc_log(req, LOG_CRIT,
			    "Failed to read request body");
			return (JSONRPC_SERVER_ERROR);
		}

		if (chunk_len == 0)
			break;

		if (body_len > SSIZE_MAX - chunk_len) {
			jsonrpc_log(req, LOG_CRIT,
			    "Request body bigger than the platform accepts");
			return (JSONRPC_SERVER_ERROR);
		}
		body_len += chunk_len;

		kore_buf_append(&req->buf, chunk_buffer, chunk_len);
	}

	/* Grab our body data as a NUL-terminated string. */
	body_string = kore_buf_stringify(&req->buf, NULL);

	/* Parse the body via yajl now. */
	*error_buffer = 0;
	req->json = yajl_tree_parse(body_string, error_buffer,
	    sizeof(error_buffer));
	if (req->json == NULL) {
		if (strlen(error_buffer)) {
			jsonrpc_log(req, LOG_ERR, "Invalid json: %s",
			    error_buffer);
		} else {
			jsonrpc_log(req, LOG_ERR, "Invalid json");
		}
		return (JSONRPC_PARSE_ERROR);
	}

	return (0);
}

static int
parse_json_body(struct jsonrpc_request *req)
{
	static const char	*proto_path[] = { "jsonrpc", NULL };
	static const char	*id_path[] = { "id", NULL };
	static const char	*method_path[] = { "method", NULL };
	static const char	*params_path[] = { "params", NULL };

	/* Check protocol first. */
	yajl_val proto = yajl_tree_get(req->json, proto_path, yajl_t_string);
	if (proto == NULL) {
		jsonrpc_log(req, LOG_ERR,
		    "JSON-RPC protocol MUST be indicated and \"2.0\"");
		return (JSONRPC_PARSE_ERROR);
	}

	char *proto_string = YAJL_GET_STRING(proto);
	if (proto_string == NULL) {
		jsonrpc_log(req, LOG_ERR,
		    "JSON-RPC protocol MUST be indicated and \"2.0\"");
		return (JSONRPC_PARSE_ERROR);
	}

	if (strcmp("2.0", proto_string) != 0) {
		jsonrpc_log(req, LOG_ERR,
		    "JSON-RPC protocol MUST be indicated and \"2.0\"");
		return (JSONRPC_PARSE_ERROR);
	}

	/* Check id. */ 
	if ((req->id = yajl_tree_get(req->json, id_path, yajl_t_any)) != NULL) {
		if (YAJL_IS_NUMBER(req->id)) {
			if (!YAJL_IS_INTEGER(req->id)) {
				jsonrpc_log(req, LOG_ERR,
				    "JSON-RPC id SHOULD NOT contain fractional"
				    " parts");
				return (JSONRPC_PARSE_ERROR);
			}
		} else if (!YAJL_IS_STRING(req->id)) {
			jsonrpc_log(req, LOG_ERR,
			    "JSON-RPC id MUST contain a String or Number");
			return (JSONRPC_PARSE_ERROR);
		}
	}

	/* Check method. */
	if ((req->method = YAJL_GET_STRING(yajl_tree_get(req->json, method_path,
		yajl_t_string))) == NULL) {
		jsonrpc_log(req, LOG_ERR,
		    "JSON-RPC method MUST exist and be a String");
		return (JSONRPC_PARSE_ERROR);
	}

	/* Check params. */
	req->params = yajl_tree_get(req->json, params_path, yajl_t_any);
	if (!(req->params == NULL || YAJL_IS_ARRAY(req->params)
	    || YAJL_IS_OBJECT(req->params))) {
		jsonrpc_log(req, LOG_ERR,
		    "JSON-RPC params MUST be Object or Array");
		return (JSONRPC_PARSE_ERROR);
	}

	return (0);
}

int
jsonrpc_read_request(struct http_request *http_req, struct jsonrpc_request *req)
{
	int	ret;

	init_request(req);
	req->http = http_req;

	if ((ret = read_json_body(http_req, req)) != 0)
		return (ret);

	return parse_json_body(req);
}

static int
write_id(yajl_gen gen, yajl_val id)
{
	int	status;

	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(gen, "id")))
		return (status);

	if (YAJL_IS_NULL(id))
		return yajl_gen_null(gen);

	if (YAJL_IS_NUMBER(id)) {
		if (YAJL_IS_INTEGER(id))
			return yajl_gen_integer(gen, YAJL_GET_INTEGER(id));
		return yajl_gen_null(gen);
	}

	if (YAJL_IS_STRING(id)) {
		char	*id_str = YAJL_GET_STRING(id);

		return yajl_gen_string(gen, (unsigned char *)id_str,
			strlen(id_str));
	}

	return yajl_gen_null(gen);
}

static int
open_response(yajl_gen genctx, yajl_val id)
{
	int		status;

	if (YAJL_GEN_KO(status = yajl_gen_map_open(genctx)))
		goto failed;
	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(genctx, "jsonrpc")))
		goto failed;
	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(genctx, "2.0")))
		goto failed;
	status = write_id(genctx, id);
failed:
	return (status);
}

static int
close_response(yajl_gen genctx)
{
	int	status;

	if (YAJL_GEN_KO(status = yajl_gen_map_close(genctx)))
		goto failed;
	status = yajl_gen_map_close(genctx);
failed:
	return (status);
}

static int
write_log(struct jsonrpc_request *req)
{
	bool	wrote_smth = false;
	int	status = 0;
	
	for (struct jsonrpc_log *log = req->log.next; log != &req->log;
		log = log->next) {

		if (((1 << log->lvl) & req->log_levels) == 0)
			continue;

		if (!wrote_smth) {
			if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(req->gen,
			    "data")))
				goto failed;
			if (YAJL_GEN_KO(status = yajl_gen_array_open(req->gen)))
				goto failed;
			yajl_gen_config(req->gen, yajl_gen_validate_utf8, 1);
			wrote_smth = true;
		}
		
		if (YAJL_GEN_KO(status = yajl_gen_array_open(req->gen)))
			goto failed;
		if (YAJL_GEN_KO(status = yajl_gen_integer(req->gen, log->lvl)))
			goto failed;
		if (YAJL_GEN_KO(status = yajl_gen_string(req->gen,
		    (unsigned char *)log->msg, strlen(log->msg))))
			goto failed;
		if (YAJL_GEN_KO(status = yajl_gen_array_close(req->gen)))
			goto failed;
	}

	if (wrote_smth) {
		yajl_gen_config(req->gen, yajl_gen_validate_utf8, 0);
		status = yajl_gen_array_close(req->gen);
	}
failed:
	return (status);
}

static int
write_error(struct jsonrpc_request *req, int code, const char *message)
{
	int	status;

	yajl_gen_config(req->gen, yajl_gen_validate_utf8, 0);

	if (YAJL_GEN_KO(status = open_response(req->gen, req->id)))
		goto failed;
	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(req->gen, "error")))
		goto failed;
	if (YAJL_GEN_KO(status = yajl_gen_map_open(req->gen)))
		goto failed;
	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(req->gen, "code")))
		goto failed;
	if (YAJL_GEN_KO(status = yajl_gen_integer(req->gen, code)))
		goto failed;
	if (YAJL_GEN_KO(status = YAJL_GEN_CONST_STRING(req->gen, "message")))
		goto failed;

	yajl_gen_config(req->gen, yajl_gen_validate_utf8, 1);

	if (YAJL_GEN_KO(status = yajl_gen_string(req->gen,
			(const unsigned char *)message, strlen(message))))
		goto failed;

	yajl_gen_config(req->gen, yajl_gen_validate_utf8, 0);

	if (YAJL_GEN_KO(status = write_log(req)))
		goto failed;

	status = close_response(req->gen);
failed:
	return (status);
}

static const char *
known_msg(int code)
{
	switch (code) {
	case JSONRPC_PARSE_ERROR:
		return (JSONRPC_PARSE_ERROR_MSG);
	case JSONRPC_INVALID_REQUEST:
		return (JSONRPC_INVALID_REQUEST_MSG);
	case JSONRPC_METHOD_NOT_FOUND:
		return (JSONRPC_METHOD_NOT_FOUND_MSG);
	case JSONRPC_INVALID_PARAMS:
		return (JSONRPC_INVALID_PARAMS_MSG);
	case JSONRPC_INTERNAL_ERROR:
		return (JSONRPC_INTERNAL_ERROR_MSG);
	case JSONRPC_SERVER_ERROR:
		return (JSONRPC_SERVER_ERROR_MSG);
	case JSONRPC_LIMIT_REACHED:
		return (JSONRPC_LIMIT_REACHED_MSG);
	default:
		return (NULL);
	}
}

int
jsonrpc_error(struct jsonrpc_request *req, int code, const char *msg)
{
	char			*msg_fallback;
	const unsigned char	*body = NULL;
	size_t			body_len = 0;
	int			status;

	if (req->id == NULL)
		goto succeeded;

	if ((req->gen = yajl_gen_alloc(NULL)) == NULL) {
		kore_log(LOG_ERR, "jsonrpc_error: Failed to allocate yajl gen");
		goto failed;
	}

	yajl_gen_config(req->gen, yajl_gen_beautify,
	    req->flags & yajl_gen_beautify);

	if (msg == NULL)
		msg = known_msg(code);

	if (msg == NULL) {
		size_t	start = req->buf.offset;
		kore_buf_appendf(&req->buf, "%d", code);
		msg_fallback = kore_buf_stringify(&req->buf, NULL) + start;
	}

	if (YAJL_GEN_KO(status = write_error(req, code,
	    msg ? msg : msg_fallback))) {
		kore_log(LOG_ERR, "jsonrpc_error: Failed to yajl gen text [%d]",
			status);
		goto failed;
	}

	http_response_header(req->http, "content-type", "application/json");
	yajl_gen_get_buf(req->gen, &body, &body_len);
succeeded:
	http_response(req->http, HTTP_STATUS_OK, body, body_len);
	if (req->gen != NULL)
		yajl_gen_clear(req->gen);
	jsonrpc_destroy_request(req);
	return (KORE_RESULT_OK);
failed:
	http_response(req->http, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
	jsonrpc_destroy_request(req);
	return (KORE_RESULT_OK);
}

int
jsonrpc_result(struct jsonrpc_request *req,
    int (*write_result)(struct jsonrpc_request *, void *), void *ctx)
{
	const unsigned char	*body = NULL;
	size_t			body_len = 0;

	if (req->id == NULL)
		goto succeeded;

	if ((req->gen = yajl_gen_alloc(NULL)) == NULL) {
		kore_log(LOG_ERR, "jsonrpc_result: Failed to allocate yajl gen");
		goto failed;
        }

	yajl_gen_config(req->gen, yajl_gen_beautify,
	    req->flags & yajl_gen_beautify);

	yajl_gen_config(req->gen, yajl_gen_validate_utf8, 0);

	if (YAJL_GEN_KO(open_response(req->gen, req->id)))
		goto failed;
	if (YAJL_GEN_KO(YAJL_GEN_CONST_STRING(req->gen, "result")))
		goto failed;
	if (YAJL_GEN_KO(write_result(req, ctx)))
		goto failed;
	if (YAJL_GEN_KO(yajl_gen_map_close(req->gen)))
		goto failed;
	
	http_response_header(req->http, "content-type", "application/json");
	yajl_gen_get_buf(req->gen, &body, &body_len);
succeeded:
	http_response(req->http, HTTP_STATUS_OK, body, body_len);
	if (req->gen != NULL)
		yajl_gen_clear(req->gen);
	jsonrpc_destroy_request(req);
	return (KORE_RESULT_OK);
failed:
	http_response(req->http, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
	jsonrpc_destroy_request(req);
	return (KORE_RESULT_OK);
}
