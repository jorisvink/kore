#include <kore/kore.h>
#include <kore/http.h>

int	homepage(struct http_request *);

int
homepage(struct http_request *req)
{
	static const char	response_body[] = "JSON-RPC API\n";
	
	http_response_header(req, "content-type", "text/plain");
	http_response(req, 200, response_body, sizeof(response_body) - 1);
	return (KORE_RESULT_OK);
}
