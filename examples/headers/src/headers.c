#include <kore/kore.h>
#include <kore/http.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	const char		*custom;

	/*
	 * We'll lookup if the X-Custom-Header is given in the request.
	 * If it is we'll set it as a response header as well.
	 *
	 * The value returned by http_request_header() should not be freed.
	 */
	if (http_request_header(req, "x-custom-header", &custom))
		http_response_header(req, "x-custom-header", custom);

	/* Return 200 with "ok\n" to the client. */
	http_response(req, 200, "ok\n", 3);

	return (KORE_RESULT_OK);
}
