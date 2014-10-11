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
#include <pg_config.h>

#include "kore.h"
#include "http.h"
#include "pgsql.h"

struct pgsql_job {
	char			*query;
	struct http_request	*req;
	struct kore_pgsql	*pgsql;

	TAILQ_ENTRY(pgsql_job)	list;
};

struct pgsql_wait {
	struct http_request		*req;
	TAILQ_ENTRY(pgsql_wait)		list;
};

#define PGSQL_IS_BLOCKING	0
#define PGSQL_IS_ASYNC		1

#define PGSQL_CONN_MAX		2
#define PGSQL_CONN_FREE		0x01

static void	pgsql_queue_wakeup(void);
static int	pgsql_conn_create(struct kore_pgsql *);
static void	pgsql_queue_add(struct http_request *);
static void	pgsql_conn_release(struct kore_pgsql *);
static void	pgsql_conn_cleanup(struct pgsql_conn *);
static void	pgsql_read_result(struct kore_pgsql *, int);
static void	pgsql_schedule(struct kore_pgsql *, struct http_request *);
static int	pgsql_prepare(struct kore_pgsql *, struct http_request *,
		    const char *);

static struct kore_pool			pgsql_job_pool;
static struct kore_pool			pgsql_wait_pool;
static TAILQ_HEAD(, pgsql_conn)		pgsql_conn_free;
static TAILQ_HEAD(, pgsql_wait)		pgsql_wait_queue;
static u_int16_t			pgsql_conn_count;
char					*pgsql_conn_string = NULL;
u_int16_t				pgsql_conn_max = PGSQL_CONN_MAX;

void
kore_pgsql_init(void)
{
	pgsql_conn_count = 0;
	TAILQ_INIT(&pgsql_conn_free);
	TAILQ_INIT(&pgsql_wait_queue);

	kore_pool_init(&pgsql_job_pool, "pgsql_job_pool",
	    sizeof(struct pgsql_job), 100);
	kore_pool_init(&pgsql_wait_pool, "pgsql_wait_pool",
	    sizeof(struct pgsql_wait), 100);
}

int
kore_pgsql_query(struct kore_pgsql *pgsql, struct http_request *req,
    const char *query)
{
	if (!pgsql_prepare(pgsql, req, query))
		return (KORE_RESULT_ERROR);

	if (!PQsendQuery(pgsql->conn->db, query)) {
		pgsql_conn_cleanup(pgsql->conn);
		return (KORE_RESULT_ERROR);
	}

	pgsql_schedule(pgsql, req);
	return (KORE_RESULT_OK);
}

int
kore_pgsql_query_params(struct kore_pgsql *pgsql, struct http_request *req,
    const char *query, int result, u_int8_t count, ...)
{
	u_int8_t	i;
	va_list		args;
	char		**values;
	int		*lengths, *formats;

	if (!pgsql_prepare(pgsql, req, query))
		return (KORE_RESULT_ERROR);

	if (count > 0) {
		va_start(args, count);

		lengths = kore_calloc(count, sizeof(int));
		formats = kore_calloc(count, sizeof(int));
		values = kore_calloc(count, sizeof(char *));

		for (i = 0; i < count; i++) {
			values[i] = va_arg(args, void *);
			lengths[i] = va_arg(args, u_int32_t);
			formats[i] = va_arg(args, int);
		}
	} else {
		lengths = NULL;
		formats = NULL;
		values = NULL;
	}

	if (!PQsendQueryParams(pgsql->conn->db, query, count, NULL,
	    (const char * const *)values, lengths, formats, result)) {
		kore_mem_free(values);
		kore_mem_free(lengths);
		kore_mem_free(formats);
		pgsql_conn_cleanup(pgsql->conn);
		return (KORE_RESULT_ERROR);
	}

	kore_mem_free(values);
	kore_mem_free(lengths);
	kore_mem_free(formats);

	pgsql_schedule(pgsql, req);
	return (KORE_RESULT_OK);
}

void
kore_pgsql_handle(void *c, int err)
{
	struct http_request	*req;
	struct kore_pgsql	*pgsql;
	struct pgsql_conn	*conn = (struct pgsql_conn *)c;

	if (err) {
		pgsql_conn_cleanup(conn);
		return;
	}

	req = conn->job->req;
	pgsql = conn->job->pgsql;
	kore_debug("kore_pgsql_handle: %p (%d)", req, pgsql->state);

	if (!PQconsumeInput(conn->db)) {
		pgsql->state = KORE_PGSQL_STATE_ERROR;
		pgsql->error = kore_strdup(PQerrorMessage(conn->db));
	} else {
		pgsql_read_result(pgsql, PGSQL_IS_ASYNC);
	}

	if (pgsql->state == KORE_PGSQL_STATE_WAIT) {
		http_request_sleep(req);
	} else {
		http_request_wakeup(req);
	}
}

void
kore_pgsql_continue(struct http_request *req, struct kore_pgsql *pgsql)
{
	kore_debug("kore_pgsql_continue: %p->%p (%d)",
	    req->owner, req, pgsql->state);

	if (pgsql->error) {
		kore_mem_free(pgsql->error);
		pgsql->error = NULL;
	}

	if (pgsql->result) {
		PQclear(pgsql->result);
		pgsql->result = NULL;
	}

	switch (pgsql->state) {
	case KORE_PGSQL_STATE_INIT:
	case KORE_PGSQL_STATE_WAIT:
		break;
	case KORE_PGSQL_STATE_DONE:
		http_request_wakeup(req);
		pgsql_conn_release(pgsql);
		break;
	case KORE_PGSQL_STATE_ERROR:
	case KORE_PGSQL_STATE_RESULT:
		kore_pgsql_handle(pgsql->conn, 0);
		break;
	default:
		fatal("unknown pgsql state %d", pgsql->state);
	}
}

void
kore_pgsql_cleanup(struct kore_pgsql *pgsql)
{
	kore_debug("kore_pgsql_cleanup(%p)", pgsql);

	if (pgsql->result != NULL)
		PQclear(pgsql->result);

	if (pgsql->error != NULL)
		kore_mem_free(pgsql->error);

	if (pgsql->conn != NULL)
		pgsql_conn_release(pgsql);

	pgsql->result = NULL;
	pgsql->error = NULL;
	pgsql->conn = NULL;

	LIST_REMOVE(pgsql, rlist);
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

int
kore_pgsql_getlength(struct kore_pgsql *pgsql, int row, int col)
{
	return (PQgetlength(pgsql->result, row, col));
}

char *
kore_pgsql_getvalue(struct kore_pgsql *pgsql, int row, int col)
{
	return (PQgetvalue(pgsql->result, row, col));
}

void
kore_pgsql_queue_remove(struct http_request *req)
{
	struct pgsql_wait	*pgw, *next;

	for (pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next) {
		next = TAILQ_NEXT(pgw, list);
		if (pgw->req != req)
			continue;

		TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
		kore_pool_put(&pgsql_wait_pool, pgw);
		return;
	}
}

static int
pgsql_prepare(struct kore_pgsql *pgsql, struct http_request *req,
    const char *query)
{
	struct pgsql_conn	*conn;

	pgsql->state = KORE_PGSQL_STATE_INIT;
	pgsql->result = NULL;
	pgsql->error = NULL;
	pgsql->conn = NULL;

	if (TAILQ_EMPTY(&pgsql_conn_free)) {
		if (pgsql_conn_count >= pgsql_conn_max) {
			pgsql_queue_add(req);
			return (KORE_RESULT_ERROR);
		}

		if (!pgsql_conn_create(pgsql))
			return (KORE_RESULT_ERROR);
	}

	http_request_sleep(req);
	conn = TAILQ_FIRST(&pgsql_conn_free);
	if (!(conn->flags & PGSQL_CONN_FREE))
		fatal("received a pgsql conn that was not free?");

	conn->flags &= ~PGSQL_CONN_FREE;
	TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	pgsql->conn = conn;
	conn->job = kore_pool_get(&pgsql_job_pool);
	conn->job->query = kore_strdup(query);
	conn->job->pgsql = pgsql;
	conn->job->req = req;

	LIST_INSERT_HEAD(&(req->pgsqls), pgsql, rlist);
	return (KORE_RESULT_OK);
}

static void
pgsql_schedule(struct kore_pgsql *pgsql, struct http_request *req)
{
	int		fd;

	fd = PQsocket(pgsql->conn->db);
	if (fd < 0)
		fatal("PQsocket returned < 0 fd on open connection");

	kore_platform_schedule_read(fd, pgsql->conn);
	pgsql->state = KORE_PGSQL_STATE_WAIT;
}

static void
pgsql_queue_add(struct http_request *req)
{
	struct pgsql_wait	*pgw;

	http_request_sleep(req);

	pgw = kore_pool_get(&pgsql_wait_pool);
	pgw->req = req;
	pgw->req->flags |= HTTP_REQUEST_PGSQL_QUEUE;

	TAILQ_INSERT_TAIL(&pgsql_wait_queue, pgw, list);
}

static void
pgsql_queue_wakeup(void)
{
	struct pgsql_wait	*pgw, *next;

	for (pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next) {
		next = TAILQ_NEXT(pgw, list);
		if (pgw->req->flags & HTTP_REQUEST_DELETE)
			continue;

		http_request_wakeup(pgw->req);
		pgw->req->flags &= ~HTTP_REQUEST_PGSQL_QUEUE;

		TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
		kore_pool_put(&pgsql_wait_pool, pgw);
		return;
	}
}

static int
pgsql_conn_create(struct kore_pgsql *pgsql)
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
		pgsql->state = KORE_PGSQL_STATE_ERROR;
		pgsql->error = kore_strdup(PQerrorMessage(conn->db));
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
pgsql_conn_release(struct kore_pgsql *pgsql)
{
	int		fd;

	if (pgsql->conn == NULL)
		return;

	kore_mem_free(pgsql->conn->job->query);
	kore_pool_put(&pgsql_job_pool, pgsql->conn->job);

	/* Drain just in case. */
	while (PQgetResult(pgsql->conn->db) != NULL)
		;

	pgsql->conn->job = NULL;
	pgsql->conn->flags |= PGSQL_CONN_FREE;
	TAILQ_INSERT_TAIL(&pgsql_conn_free, pgsql->conn, list);

	fd = PQsocket(pgsql->conn->db);
	kore_platform_disable_read(fd);

	pgsql->conn = NULL;
	pgsql->state = KORE_PGSQL_STATE_COMPLETE;

	pgsql_queue_wakeup();
}

static void
pgsql_conn_cleanup(struct pgsql_conn *conn)
{
	struct http_request	*req;
	struct kore_pgsql	*pgsql;

	kore_debug("pgsql_conn_cleanup(): %p", conn);

	if (conn->flags & PGSQL_CONN_FREE)
		TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	if (conn->job) {
		req = conn->job->req;
		pgsql = conn->job->pgsql;
		http_request_wakeup(req);

		pgsql->conn = NULL;
		pgsql->state = KORE_PGSQL_STATE_ERROR;
		pgsql->error = kore_strdup(PQerrorMessage(conn->db));

		kore_mem_free(conn->job->query);
		kore_pool_put(&pgsql_job_pool, conn->job);
		conn->job = NULL;
	}

	if (conn->db != NULL)
		PQfinish(conn->db);

	pgsql_conn_count--;
	kore_mem_free(conn);
}

static void
pgsql_read_result(struct kore_pgsql *pgsql, int async)
{
	if (async) {
		if (PQisBusy(pgsql->conn->db)) {
			pgsql->state = KORE_PGSQL_STATE_WAIT;
			return;
		}
	}

	pgsql->result = PQgetResult(pgsql->conn->db);
	if (pgsql->result == NULL) {
		pgsql->state = KORE_PGSQL_STATE_DONE;
		return;
	}

	switch (PQresultStatus(pgsql->result)) {
	case PGRES_COPY_OUT:
	case PGRES_COPY_IN:
	case PGRES_NONFATAL_ERROR:
	case PGRES_COPY_BOTH:
		break;
	case PGRES_COMMAND_OK:
		pgsql->state = KORE_PGSQL_STATE_DONE;
		break;
	case PGRES_TUPLES_OK:
#if PG_VERSION_NUM >= 90200
	case PGRES_SINGLE_TUPLE:
#endif
		pgsql->state = KORE_PGSQL_STATE_RESULT;
		break;
	case PGRES_EMPTY_QUERY:
	case PGRES_BAD_RESPONSE:
	case PGRES_FATAL_ERROR:
		pgsql->state = KORE_PGSQL_STATE_ERROR;
		pgsql->error = kore_strdup(PQresultErrorMessage(pgsql->result));
		break;
	}
}
