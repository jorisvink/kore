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
#include "pgsql.h"

#include "static.h"

void		pgsql_load(int);
int		serve_pgsql_test(struct http_request *);

void
pgsql_load(int state)
{
	switch (state) {
	case KORE_MODULE_LOAD:
		pgsql_conn_string = "Your connection string";
		break;
	default:
		break;
	}
}

int
serve_pgsql_test(struct http_request *req)
{
	int		r, i;
	char		*col1, *col2;

	KORE_PGSQL(req, "SELECT * FROM test", 0, {
		if (req->pgsql[0]->state == KORE_PGSQL_STATE_ERROR) {
			kore_pgsql_logerror(req->pgsql[0]);
			http_response(req, 500, "fail\n", 5);
			return (KORE_RESULT_OK);
		}

		r = kore_pgsql_ntuples(req->pgsql[0]);
		for (i = 0; i < r; i++) {
			col1 = kore_pgsql_getvalue(req->pgsql[0], i, 0);
			col2 = kore_pgsql_getvalue(req->pgsql[0], i, 1);

			kore_log(LOG_NOTICE, "%s and %s", col1, col2);
		}
	});

	KORE_PGSQL(req, "SELECT * FROM foobar", 1, {
		if (req->pgsql[1]->state != KORE_PGSQL_STATE_ERROR) {
			kore_log(LOG_NOTICE, "expected error, got %d",
			    req->pgsql[1]->state);
			http_response(req, 500, "fail2\n", 6);
			return (KORE_RESULT_OK);
		} else {
			kore_pgsql_logerror(req->pgsql[1]);
		}
	});

	/* Query successfully completed */
	http_response(req, 200, "ok\n", 3);

	return (KORE_RESULT_OK);
}
