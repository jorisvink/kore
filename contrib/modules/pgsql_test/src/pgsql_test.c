/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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

#include "kore.h"
#include "http.h"
#include "contrib/postgres/kore_pgsql.h"

#include "static.h"

int		serve_pgsql_test(struct http_request *);

int
serve_pgsql_test(struct http_request *req)
{
	//int		r;

	KORE_PGSQL(req, "SELECT * FROM test", 0, {
		if (req->pgsql[0]->state == KORE_PGSQL_STATE_ERROR) {
			kore_log(LOG_NOTICE, "pgsql: %s",
			    (req->pgsql[0]->error) ?
			    req->pgsql[0]->error : "unknown");
			http_response(req, 500, "fail", 4);
			return (KORE_RESULT_OK);
		} else {
			//r = kore_pgsql_ntuples(req, 0);
		}
	});

	/* Query successfully completed */
	http_response(req, 200, "ok", 2);

	return (KORE_RESULT_OK);
}
