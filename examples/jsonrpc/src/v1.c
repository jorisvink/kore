#include <time.h>
#include <xlocale.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <kore/kore.h>
#include <kore/http.h>
#include <kore/jsonrpc.h>

int	v1(struct http_request *);

static int
write_string(struct jsonrpc_request *req, void *ctx)
{
	const unsigned char *str = (unsigned char *)ctx;

	return yajl_gen_string(req->gen, str, strlen((const char *)str));
}

static int
write_string_array_params(struct jsonrpc_request *req, void *ctx)
{
	int status = 0;

	if (!YAJL_GEN_KO(status = yajl_gen_array_open(req->gen))) {
		for (size_t i = 0; i < req->params->u.array.len; i++) {
			yajl_val yajl_str = req->params->u.array.values[i];
			char	 *str = YAJL_GET_STRING(yajl_str);

			if (YAJL_GEN_KO(status = yajl_gen_string(req->gen,
			    (unsigned char *)str, strlen(str))))
				break;
		}
		if (status == 0)
			status = yajl_gen_array_close(req->gen);
	}

	return status;
}

int
v1(struct http_request *http_req)
{
	struct jsonrpc_request	req;
	int			ret;
	
	/* We only allow POST/PUT methods. */
	if (http_req->method != HTTP_METHOD_POST &&
	    http_req->method != HTTP_METHOD_PUT) {
		http_response_header(http_req, "allow", "POST, PUT");
		http_response(http_req, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL, 0);
		return (KORE_RESULT_OK);
	}
	
	/* Read JSON-RPC request. */
	if ((ret = jsonrpc_read_request(http_req, &req)) != 0)
		return jsonrpc_error(&req, ret, NULL);
	
	/* Echo command takes and gives back params. */
	if (strcmp(req.method, "echo") == 0) {
		if (!YAJL_IS_ARRAY(req.params)) {
			jsonrpc_log(&req, LOG_ERR,
			    "Echo only accepts positional params");
			return jsonrpc_error(&req, JSONRPC_INVALID_PARAMS, NULL);
		}
		for (size_t i = 0; i < req.params->u.array.len; i++) {
			yajl_val v = req.params->u.array.values[i];
			if (!YAJL_IS_STRING(v)) {
				jsonrpc_log(&req, -3,
				    "Echo only accepts strings");
				return jsonrpc_error(&req,
				    JSONRPC_INVALID_PARAMS, NULL);
			}
		}
		return jsonrpc_result(&req, write_string_array_params, NULL);
	}
	
	/* Date command displays date and time according to parameters. */
	if (strcmp(req.method, "date") == 0) {
		time_t		time_value;
		struct tm	time_info;
		char		timestamp[33];
		struct tm	*(*gettm)(const time_t *, struct tm *) =
				    localtime_r;
		
		if (YAJL_IS_OBJECT(req.params)) {
			const char	*path[] = {"local", NULL};
			yajl_val	bf;

			bf = yajl_tree_get(req.params, path, yajl_t_false);
			if (bf != NULL)
				gettm = gmtime_r;
		} else if (req.params != NULL) {
			jsonrpc_log(&req, LOG_ERR,
			    "Date only accepts named params");
			return jsonrpc_error(&req, JSONRPC_INVALID_PARAMS, NULL);
		}

		if ((time_value = time(NULL)) == -1)
			return jsonrpc_error(&req, -2,
			    "Failed to get date time");
		
		if (gettm(&time_value, &time_info) == NULL)
			return jsonrpc_error(&req, -3,
			    "Failed to get date time info");
		
		memset(timestamp, 0, sizeof(timestamp));
		if (strftime_l(timestamp, sizeof(timestamp) - 1, "%c",
		    &time_info, LC_GLOBAL_LOCALE) == 0)
			return jsonrpc_error(&req, -4,
			    "Failed to get printable date time");
		
		return jsonrpc_result(&req, write_string, timestamp);
	}
	
	return jsonrpc_error(&req, JSONRPC_METHOD_NOT_FOUND, NULL);
}
