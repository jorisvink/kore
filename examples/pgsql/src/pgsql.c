/*
 * Copyright (c) 2014-2018 Joris Vink <joris@coders.se>
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
 * This example demonstrates on how to use state machines and
 * asynchronous pgsql queries. For a synchronous query example
 * see the pgsql-sync/ example under the examples/ directory.
 *
 * While this example might seem overly complex for a simple pgsql
 * query, there is a reason behind its complexity:
 *	Asynchronous pgsql queries mean that Kore will not block while
 *	executing the queries, giving a worker time to continue handling
 *	other events such as I/O or other http requests.
 *
 * The state machine framework present in Kore makes it trivial
 * to get going into dropping from your page handler into the right
 * state that you are currently in.
 */

#if !defined(KORE_NO_HTTP)

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#define REQ_STATE_INIT			0
#define REQ_STATE_QUERY			1
#define REQ_STATE_DB_WAIT		2
#define REQ_STATE_DB_READ		3
#define REQ_STATE_ERROR			4
#define REQ_STATE_DONE			5

int		page(struct http_request *);

static int	request_perform_init(struct http_request *);
static int	request_perform_query(struct http_request *);
static int	request_db_wait(struct http_request *);
static int	request_db_read(struct http_request *);
static int	request_error(struct http_request *);
static int	request_done(struct http_request *);

struct http_state	mystates[] = {
	{ "REQ_STATE_INIT",		request_perform_init },
	{ "REQ_STATE_QUERY",		request_perform_query },
	{ "REQ_STATE_DB_WAIT",		request_db_wait },
	{ "REQ_STATE_DB_READ",		request_db_read },
	{ "REQ_STATE_ERROR",		request_error },
	{ "REQ_STATE_DONE",		request_done },
};

#define mystates_size		(sizeof(mystates) / sizeof(mystates[0]))

struct rstate {
	int			cnt;
	struct kore_pgsql	sql;
};

/* Page handler entry point (see config) */
int
page(struct http_request *req)
{
	/* Drop into our state machine. */
	kore_log(LOG_NOTICE, "%p: page start", (void *)req);
	return (http_state_run(mystates, mystates_size, req));
}

/* Initialize our PGSQL data structure and prepare for an async query. */
int
request_perform_init(struct http_request *req)
{
	struct rstate	*state;

	/* Setup our state context (if not yet set). */
	if (!http_state_exists(req)) {
		state = http_state_create(req, sizeof(*state));

		/*
		 * Initialize the kore_pgsql data structure and bind it
		 * to this request so we can be put to sleep / woken up
		 * by the pgsql layer when required.
		 */
		kore_pgsql_init(&state->sql);
		kore_pgsql_bind_request(&state->sql, req);
	} else {
		state = http_state_get(req);
	}

	/*
	 * Setup the query to be asynchronous in nature, aka just fire it
	 * off and return back to us.
	 */
	if (!kore_pgsql_setup(&state->sql, "db", KORE_PGSQL_ASYNC)) {
		/*
		 * If the state was still in INIT we need to go to sleep and
		 * wait until the pgsql layer wakes us up again when there
		 * an available connection to the database.
		 */
		if (state->sql.state == KORE_PGSQL_STATE_INIT) {
			req->fsm_state = REQ_STATE_INIT;
			return (HTTP_STATE_RETRY);
		}

		kore_pgsql_logerror(&state->sql);
		req->fsm_state = REQ_STATE_ERROR;
	} else {
		/*
		 * The initial setup was complete, go for query.
		 */
		req->fsm_state = REQ_STATE_QUERY;
	}

	return (HTTP_STATE_CONTINUE);
}

/* After setting everything up we will execute our async query. */
int
request_perform_query(struct http_request *req)
{
	struct rstate	*state = http_state_get(req);

	/* We want to move to read result after this. */
	req->fsm_state = REQ_STATE_DB_WAIT;

	/* Fire off the query. */
	if (!kore_pgsql_query(&state->sql,
	    "SELECT * FROM coders, pg_sleep(5)")) {
		/*
		 * Let the state machine continue immediately since we
		 * have an error anyway.
		 */
		return (HTTP_STATE_CONTINUE);
	}

	/* Resume state machine later when the query results start coming in. */
	return (HTTP_STATE_RETRY);
}

/*
 * After firing off the query, we returned HTTP_STATE_RETRY (see above).
 * When request_db_wait() finally is called by Kore we will have results
 * from pgsql so we'll process them.
 */
int
request_db_wait(struct http_request *req)
{
	struct rstate	*state = http_state_get(req);

	kore_log(LOG_NOTICE, "request_db_wait: %d", state->sql.state);

	/*
	 * When we get here, our asynchronous pgsql query has
	 * given us something, check the state to figure out what.
	 */
	switch (state->sql.state) {
	case KORE_PGSQL_STATE_WAIT:
		return (HTTP_STATE_RETRY);
	case KORE_PGSQL_STATE_COMPLETE:
		req->fsm_state = REQ_STATE_DONE;
		break;
	case KORE_PGSQL_STATE_ERROR:
		req->fsm_state = REQ_STATE_ERROR;
		kore_pgsql_logerror(&state->sql);
		break;
	case KORE_PGSQL_STATE_RESULT:
		req->fsm_state = REQ_STATE_DB_READ;
		break;
	default:
		/* This MUST be present in order to advance the pgsql state */
		kore_pgsql_continue(&state->sql);
		break;
	}

	return (HTTP_STATE_CONTINUE);
}

/*
 * Called when there's an actual result to be gotten. After we handle the
 * entire result, we'll drop back into REQ_STATE_DB_WAIT (above) in order
 * to continue until the pgsql API returns KORE_PGSQL_STATE_COMPLETE.
 */
int
request_db_read(struct http_request *req)
{
	char		*name;
	int		i, rows;
	struct rstate	*state = http_state_get(req);

	/* We have sql data to read! */
	rows = kore_pgsql_ntuples(&state->sql);
	for (i = 0; i < rows; i++) {
		name = kore_pgsql_getvalue(&state->sql, i, 0);
		kore_log(LOG_NOTICE, "name: '%s'", name);
	}

	/* Continue processing our query results. */
	kore_pgsql_continue(&state->sql);

	/* Back to our DB waiting state. */
	req->fsm_state = REQ_STATE_DB_WAIT;
	return (HTTP_STATE_CONTINUE);
}

/* An error occurred. */
int
request_error(struct http_request *req)
{
	struct rstate	*state = http_state_get(req);

	kore_pgsql_cleanup(&state->sql);
	http_state_cleanup(req);

	http_response(req, 500, NULL, 0);

	return (HTTP_STATE_COMPLETE);
}

/* Request was completed successfully. */
int
request_done(struct http_request *req)
{
	struct rstate	*state = http_state_get(req);

	kore_pgsql_cleanup(&state->sql);
	http_state_cleanup(req);

	http_response(req, 200, NULL, 0);

	return (HTTP_STATE_COMPLETE);
}

#endif /* !KORE_NO_HTTP */
