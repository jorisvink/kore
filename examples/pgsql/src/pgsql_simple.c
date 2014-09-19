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

/*
 * Same as pgsql.c except using the more simple form.
 *
 * The simple form of the pgsql API hides the wait state machine
 * from you so you only have to implement a few functions to get
 * queries up and running asynchronously.
 */

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

int	page_simple(struct http_request *);

int	page_simple_init(struct http_request *, struct kore_pgsql_simple *);
void	page_simple_done(struct http_request *, struct kore_pgsql_simple *);
void	page_simple_result(struct http_request *, struct kore_pgsql_simple *);

/*
 * Set our callbacks for initialization, result and completion.
 * At least init and done MUST be set.
 */
static struct kore_pgsql_functions simple_query = {
	page_simple_init,
	page_simple_done,
	page_simple_result
};

int
page_simple(struct http_request *req)
{
	return (kore_pgsql_run(req, &simple_query));
}

/*
 * Initialization so we can parse arguments, set states, set our query, ...
 *
 * Return KORE_RESULT_OK if we can proceed or KORE_RESULT_ERROR in case
 * you want the state machine to just stop.
 *
 * Note that if you return KORE_RESULT_ERROR you must call http_response()
 * before doing so if you want to relay an error to your client.
 */
int
page_simple_init(struct http_request *req, struct kore_pgsql_simple *simple)
{
	simple->query = "SELECT * FROM coders";

	return (KORE_RESULT_OK);
}

/*
 * Called when you get a result from your query.
 */
void
page_simple_result(struct http_request *req, struct kore_pgsql_simple *simple)
{
	char		*name;
	int		i, rows;

	rows = kore_pgsql_ntuples(&simple->sql);
	for (i = 0; i < rows; i++) {
		name = kore_pgsql_getvalue(&simple->sql, i, 0);
		kore_log(LOG_NOTICE, "name: '%s'", name);
	}
}

/*
 * When we get here req->status will reflect if something went wrong,
 * if so then status will be HTTP_STATUS_INTERNAL_ERROR.
 *
 * Any pgsql errors will already have been logged.
 */
void
page_simple_done(struct http_request *req, struct kore_pgsql_simple *simple)
{
	if (req->status != HTTP_STATUS_INTERNAL_ERROR)
		req->status = HTTP_STATUS_OK;

	http_response(req, req->status, NULL, 0);
}
