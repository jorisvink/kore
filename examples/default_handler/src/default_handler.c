#include <kore/kore.h>
#include <kore/http.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	http_response(req, 200, NULL, 0);
	return (KORE_RESULT_OK);
}

int		default_page(struct http_request *);

int
default_page(struct http_request *req)
{
	http_response(req, 404, "Go Away\n", 8);
	return (KORE_RESULT_OK);
}
