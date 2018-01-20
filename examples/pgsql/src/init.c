/*
 * Copyright (c) 2017-2018 Joris Vink <joris@coders.se>
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
#include <kore/pgsql.h>

#if !defined(KORE_NO_HTTP)
#include <kore/http.h>
#endif

int		init(int);

#if !defined(KORE_NO_HTTP)
int		hello(struct http_request *);
#endif

/* Called when our module is loaded (see config) */
int
init(int state)
{
	/* Register our database. */
	kore_pgsql_register("db", "host=/tmp dbname=test");

	return (KORE_RESULT_OK);
}

#if !defined(KORE_NO_HTTP)
int
hello(struct http_request *req)
{
	http_response(req, HTTP_STATUS_OK, "hello", 5);
	return (KORE_RESULT_OK);
}
#endif
