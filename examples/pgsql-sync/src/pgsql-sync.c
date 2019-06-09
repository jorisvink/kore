/*
 * Copyright (c) 2015 Joris Vink <joris@coders.se>
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

/*
 * This example demonstrates how to use synchronous PGSQL queries
 * with Kore. For an asynchronous example see pgsql/ under examples/.
 *
 * This example does the same as the asynchronous one, select all entries
 * from a table called "coders".
 */

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

int			init(int);
int			page(struct http_request *);

/* Called when our module is loaded (see config) */
int
init(int state)
{
	/* Register our database. */
	kore_pgsql_register("db", "host=/tmp dbname=test");

	return (KORE_RESULT_OK);
}

/* Page handler entry point (see config) */
int
page(struct http_request *req)
{
	struct kore_pgsql	sql;
	char			*name;
	int			rows, i;

	req->status = HTTP_STATUS_INTERNAL_ERROR;

	kore_pgsql_init(&sql);

	/*
	 * Initialise our kore_pgsql data structure with the database name
	 * we want to connect to (note that we registered this earlier with
	 * kore_pgsql_register()). We also say we will perform a synchronous
	 * query (KORE_PGSQL_SYNC).
	 */
	if (!kore_pgsql_setup(&sql, "db", KORE_PGSQL_SYNC)) {
		kore_pgsql_logerror(&sql);
		goto out;
	}

	/*
	 * Now we can fire off the query, once it returns we either have
	 * a result on which we can operate or an error occurred.
	 */
	if (!kore_pgsql_query(&sql, "SELECT * FROM coders")) {
		kore_pgsql_logerror(&sql);
		goto out;
	}

	/*
	 * Iterate over the result and dump it to somewhere.
	 */
	rows = kore_pgsql_ntuples(&sql);
	for (i = 0; i < rows; i++) {
		name = kore_pgsql_getvalue(&sql, i, 0);
		kore_log(LOG_NOTICE, "name: '%s'", name);
	}

	/* All good. */
	req->status = HTTP_STATUS_OK;

out:
	http_response(req, req->status, NULL, 0);

	/* Don't forget to cleanup the kore_pgsql data structure. */
	kore_pgsql_cleanup(&sql);

	return (KORE_RESULT_OK);
}
