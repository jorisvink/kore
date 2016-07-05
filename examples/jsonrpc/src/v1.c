#include <time.h>
#include <xlocale.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <kore/kore.h>
#include <kore/http.h>
#include <kore/jsonrpc.h>

int	v1(struct http_request *);

static int
write_json_string(struct jsonrpc_request *req, void *ctx)
{
	char *str = (char *)ctx;
	
	return yajl_gen_string(req->gen, (unsigned char *)str, strlen(str));
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
	if ((ret = jsonrpc_request_read(http_req, 1000 * 64, &req)) != 0)
		return jsonrpc_error(&req, ret, NULL);
	
	/* Echo command takes and gives back a single string. */
	if (strcmp(req.method, "echo") == 0) {
		char *msg = YAJL_GET_STRING(req.params);
		if (msg == NULL) {
			return jsonrpc_error(&req,
			    JSONRPC_INVALID_PARAMS, NULL);
		}
		return jsonrpc_result(&req, write_json_string, msg);
	}
	
	/* Date command displays date and time according to parameters. */
	if (strcmp(req.method, "date") == 0) {
		time_t		time_value;
		struct tm	time_info;
		char		timestamp[33];
		char		*args[2] = {NULL, NULL};
		
		if ((time_value = time(NULL)) == -1)
			return jsonrpc_error(&req, -2,
			    "Failed to get date time");
		
		//gmtime_r(time_value, &time_info);
		if (localtime_r(&time_value, &time_info) == NULL)
			return jsonrpc_error(&req, -3,
			    "Failed to get date time info");
		
		memset(timestamp, 0, sizeof(timestamp));
		if (strftime_l(timestamp, sizeof(timestamp) - 1, "%c",
		    &time_info, LC_GLOBAL_LOCALE) == 0)
			return jsonrpc_error(&req, -4,
			    "Failed to get printable date time");
		
		return jsonrpc_result(&req, write_json_string,
		    timestamp);
	}
	
	return jsonrpc_error(&req, JSONRPC_METHOD_NOT_FOUND, NULL);
}
