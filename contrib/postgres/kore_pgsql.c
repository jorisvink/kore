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

#include <sys/param.h>
#include <sys/queue.h>

#include <libpq-fe.h>

#include "kore.h"
#include "http.h"
#include "contrib/postgres/kore_pgsql.h"

struct pgsql_job {
	u_int8_t		idx;
	struct http_request	*req;
	u_int64_t		start;
	char			*query;

	TAILQ_ENTRY(pgsql_job)	list;
};

#define PGSQL_CONN_MAX		2
#define PGSQL_CONN_FREE		0x01

struct pgsql_conn {
	u_int8_t			type;
	u_int8_t			flags;

	PGconn				*db;
	struct pgsql_job		*job;
	TAILQ_ENTRY(pgsql_conn)		list;
};

static void	pgsql_conn_cleanup(struct pgsql_conn *);
static int	pgsql_conn_create(struct http_request *, int);
static void	pgsql_read_result(struct http_request *, int,
		    struct pgsql_conn *);

static TAILQ_HEAD(, pgsql_conn)		pgsql_conn_free;
static u_int16_t			pgsql_conn_count;
char					*pgsql_conn_string = NULL;

void
kore_pgsql_init(void)
{
	pgsql_conn_count = 0;
	TAILQ_INIT(&pgsql_conn_free);
}

int
kore_pgsql_query(struct http_request *req, char *query, int idx)
{
	int			fd;
	struct pgsql_conn	*conn;

	if (idx >= HTTP_PGSQL_MAX)
		fatal("kore_pgsql_query: %d > %d", idx, HTTP_PGSQL_MAX);
	if (req->pgsql[idx] != NULL)
		fatal("kore_pgsql_query: %d already exists", idx);

	if (TAILQ_EMPTY(&pgsql_conn_free)) {
		if (pgsql_conn_count >= PGSQL_CONN_MAX)
			return (KORE_RESULT_ERROR);
	}

	req->pgsql[idx] = kore_malloc(sizeof(struct kore_pgsql));
	req->pgsql[idx]->state = KORE_PGSQL_STATE_INIT;
	req->pgsql[idx]->result = NULL;
	req->pgsql[idx]->error = NULL;
	req->pgsql[idx]->conn = NULL;

	if (TAILQ_EMPTY(&pgsql_conn_free)) {
		if (pgsql_conn_create(req, idx) == KORE_RESULT_ERROR)
			return (KORE_RESULT_ERROR);
	}

	req->flags |= HTTP_REQUEST_SLEEPING;
	conn = TAILQ_FIRST(&pgsql_conn_free);
	if (!(conn->flags & PGSQL_CONN_FREE))
		fatal("received a pgsql conn that was not free?");

	conn->flags &= ~PGSQL_CONN_FREE;
	TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	req->pgsql[idx]->conn = conn;
	conn->job = kore_malloc(sizeof(struct pgsql_job));
	conn->job->query = kore_strdup(query);
	conn->job->start = kore_time_ms();
	conn->job->req = req;
	conn->job->idx = idx;

	if (!PQsendQuery(conn->db, query)) {
		pgsql_conn_cleanup(conn);
		return (KORE_RESULT_ERROR);
	}

	fd = PQsocket(conn->db);
	if (fd < 0)
		fatal("PQsocket returned < 0 fd on open connection");

	kore_platform_schedule_read(fd, conn);
	req->pgsql[idx]->state = KORE_PGSQL_STATE_WAIT;
	kore_debug("query '%s' for %p sent on %p", query, req, conn);

	return (KORE_RESULT_OK);
}

void
kore_pgsql_handle(void *c, int err)
{
	int			i;
	struct http_request	*req;
	struct pgsql_conn	*conn = (struct pgsql_conn *)c;

	if (err) {
		pgsql_conn_cleanup(conn);
		return;
	}

	i = conn->job->idx;
	req = conn->job->req;
	kore_debug("kore_pgsql_handle(): %p (%d)", req, i);

	if (!PQconsumeInput(conn->db)) {
		req->pgsql[i]->state = KORE_PGSQL_STATE_ERROR;
		req->pgsql[i]->error = kore_strdup(PQerrorMessage(conn->db));
	} else {
		pgsql_read_result(req, i, conn);
	}

	if (req->pgsql[i]->state == KORE_PGSQL_STATE_WAIT)
		req->flags |= HTTP_REQUEST_SLEEPING;
	else
		req->flags &= ~HTTP_REQUEST_SLEEPING;
}

void
kore_pgsql_continue(struct http_request *req, int i)
{
	int				fd;
	struct pgsql_conn		*conn;

	if (req->pgsql[i]->error) {
		kore_mem_free(req->pgsql[i]->error);
		req->pgsql[i]->error = NULL;
	}

	if (req->pgsql[i]->result)
		PQclear(req->pgsql[i]->result);

	conn = req->pgsql[i]->conn;
	switch (req->pgsql[i]->state) {
	case KORE_PGSQL_STATE_INIT:
	case KORE_PGSQL_STATE_WAIT:
		break;
	case KORE_PGSQL_STATE_DONE:
		req->pgsql[i]->conn = NULL;
		req->flags &= ~HTTP_REQUEST_SLEEPING;
		req->pgsql[i]->state = KORE_PGSQL_STATE_COMPLETE;

		kore_mem_free(conn->job->query);
		kore_mem_free(conn->job);

		conn->job = NULL;
		conn->flags |= PGSQL_CONN_FREE;
		TAILQ_INSERT_TAIL(&pgsql_conn_free, conn, list);

		fd = PQsocket(conn->db);
		kore_platform_disable_read(fd);
		break;
	case KORE_PGSQL_STATE_ERROR:
	case KORE_PGSQL_STATE_RESULT:
		kore_pgsql_handle(conn, 0);
		break;
	default:
		fatal("unknown pgsql state");
	}
}

void
kore_pgsql_cleanup(struct http_request *req)
{
	int			i;
	struct pgsql_conn	*conn;

	for (i = 0; i < HTTP_PGSQL_MAX; i++) {
		if (req->pgsql[i] == NULL)
			continue;

		if (req->pgsql[i]->result != NULL) {
			kore_log(LOG_NOTICE, "cleaning up leaked pgsql result");
			PQclear(req->pgsql[i]->result);
		}

		if (req->pgsql[i]->error != NULL)
			kore_mem_free(req->pgsql[i]->error);

		if (req->pgsql[i]->conn != NULL) {
			conn = req->pgsql[i]->conn;
			while (PQgetResult(conn->db) != NULL)
				;
		}

		req->pgsql[i]->conn = NULL;
		kore_mem_free(req->pgsql[i]);
		req->pgsql[i] = NULL;
	}
}

void
kore_pgsql_logerror(struct kore_pgsql *pgsql)
{
	kore_log(LOG_NOTICE, "pgsql error: %s",
	    (pgsql->error) ? pgsql->error : "unknown");
}

int
kore_pgsql_ntuples(struct kore_pgsql *pgsql)
{
	return (PQntuples(pgsql->result));
}

char *
kore_pgsql_getvalue(struct kore_pgsql *pgsql, int row, int col)
{
	return (PQgetvalue(pgsql->result, row, col));
}

static int
pgsql_conn_create(struct http_request *req, int idx)
{
	struct pgsql_conn	*conn;

	if (pgsql_conn_string == NULL)
		fatal("pgsql_conn_create: no connection string");

	pgsql_conn_count++;
	conn = kore_malloc(sizeof(*conn));
	kore_debug("pgsql_conn_create(): %p", conn);
	memset(conn, 0, sizeof(*conn));

	conn->db = PQconnectdb(pgsql_conn_string);
	if (conn->db == NULL || (PQstatus(conn->db) != CONNECTION_OK)) {
		req->pgsql[idx]->state = KORE_PGSQL_STATE_ERROR;
		req->pgsql[idx]->error = kore_strdup(PQerrorMessage(conn->db));
		pgsql_conn_cleanup(conn);
		return (KORE_RESULT_ERROR);
	}

	conn->job = NULL;
	conn->flags = PGSQL_CONN_FREE;
	conn->type = KORE_TYPE_PGSQL_CONN;
	TAILQ_INSERT_TAIL(&pgsql_conn_free, conn, list);

	return (KORE_RESULT_OK);
}

static void
pgsql_conn_cleanup(struct pgsql_conn *conn)
{
	int			i;
	struct http_request	*req;

	kore_debug("pgsql_conn_cleanup(): %p", conn);

	if (conn->flags & PGSQL_CONN_FREE)
		TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	if (conn->job) {
		i = conn->job->idx;
		req = conn->job->req;

		req->pgsql[i]->conn = NULL;
		req->pgsql[i]->state = KORE_PGSQL_STATE_ERROR;
		req->pgsql[i]->error = kore_strdup(PQerrorMessage(conn->db));
		req->flags &= ~HTTP_REQUEST_SLEEPING;

		kore_mem_free(conn->job->query);
		kore_mem_free(conn->job);
		conn->job = NULL;
	}

	if (conn->db != NULL)
		PQfinish(conn->db);

	pgsql_conn_count--;
	kore_mem_free(conn);
}

static void
pgsql_read_result(struct http_request *req, int i, struct pgsql_conn *conn)
{
	if (PQisBusy(conn->db)) {
		req->pgsql[i]->state = KORE_PGSQL_STATE_WAIT;
		return;
	}

	req->pgsql[i]->result = PQgetResult(conn->db);
	if (req->pgsql[i]->result == NULL) {
		req->pgsql[i]->state = KORE_PGSQL_STATE_DONE;
		return;
	}

	switch (PQresultStatus(req->pgsql[i]->result)) {
	case PGRES_COPY_OUT:
	case PGRES_COPY_IN:
	case PGRES_NONFATAL_ERROR:
	case PGRES_COPY_BOTH:
		break;
	case PGRES_COMMAND_OK:
		req->pgsql[i]->state = KORE_PGSQL_STATE_DONE;
		break;
	case PGRES_TUPLES_OK:
	case PGRES_SINGLE_TUPLE:
		req->pgsql[i]->state = KORE_PGSQL_STATE_RESULT;
		break;
	case PGRES_EMPTY_QUERY:
	case PGRES_BAD_RESPONSE:
	case PGRES_FATAL_ERROR:
		req->pgsql[i]->state = KORE_PGSQL_STATE_ERROR;
		req->pgsql[i]->error =
		    kore_strdup(PQresultErrorMessage(req->pgsql[i]->result));
		break;
	}
}
