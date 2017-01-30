/*
 * Copyright (c) 2017 Joris Vink <joris@coders.se>
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

#include <kore/kore.h>
#include <kore/http.h>

/*
 * Just some examples of things that can be mixed with python modules.
 */

int	onload(int);
int	cpage(struct http_request *);
int	c_validator(struct http_request *, void *);

int
c_validator(struct http_request *req, void *data)
{
	kore_log(LOG_NOTICE, "c_validator(): called!");
	return (KORE_RESULT_OK);
}

int
onload(int action)
{
	kore_log(LOG_NOTICE, "onload called from native");
	return (KORE_RESULT_OK);
}

int
cpage(struct http_request *req)
{
	http_populate_get(req);
	http_response(req, 200, "native", 6);

	return (KORE_RESULT_OK);
}
