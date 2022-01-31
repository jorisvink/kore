/*
 * Copyright (c) 2014-2022 Joris Vink <joris@coders.se>
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

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#include "pgsql.h"

#if defined(__linux__)
#include "seccomp.h"

static struct sock_filter filter_pgsql[] = {
	/* Allow us to create sockets and call connect. */
	KORE_SYSCALL_ALLOW(connect),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET6),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_UNIX),

	/* Requires these calls. */
	KORE_SYSCALL_ALLOW(getsockopt),
	KORE_SYSCALL_ALLOW(getsockname),
};
#endif

struct pgsql_wait {
	struct kore_pgsql	*pgsql;
	TAILQ_ENTRY(pgsql_wait)	list;
};

struct pgsql_job {
	struct kore_pgsql	*pgsql;
	TAILQ_ENTRY(pgsql_job)	list;
};

#define PGSQL_CONN_MAX		2
#define PGSQL_CONN_FREE		0x01
#define PGSQL_LIST_INSERTED	0x0100
#define PGSQL_QUEUE_LIMIT	1000

static void	pgsql_queue_wakeup(void);
static void	pgsql_cancel(struct kore_pgsql *);
static void	pgsql_set_error(struct kore_pgsql *, const char *);
static void	pgsql_queue_add(struct kore_pgsql *);
static void	pgsql_queue_remove(struct kore_pgsql *);
static void	pgsql_conn_release(struct kore_pgsql *);
static void	pgsql_conn_cleanup(struct pgsql_conn *);
static void	pgsql_read_result(struct kore_pgsql *);
static void	pgsql_schedule(struct kore_pgsql *);

static struct pgsql_conn	*pgsql_conn_create(struct kore_pgsql *,
				    struct pgsql_db *);
static struct pgsql_conn	*pgsql_conn_next(struct kore_pgsql *,
				    struct pgsql_db *);

static struct kore_pool			pgsql_job_pool;
static struct kore_pool			pgsql_wait_pool;
static TAILQ_HEAD(, pgsql_conn)		pgsql_conn_free;
static TAILQ_HEAD(, pgsql_wait)		pgsql_wait_queue;
static LIST_HEAD(, pgsql_db)		pgsql_db_conn_strings;

u_int32_t	pgsql_queue_count = 0;
u_int16_t	pgsql_conn_max = PGSQL_CONN_MAX;
u_int32_t	pgsql_queue_limit = PGSQL_QUEUE_LIMIT;

void
kore_pgsql_sys_init(void)
{
	TAILQ_INIT(&pgsql_conn_free);
	TAILQ_INIT(&pgsql_wait_queue);
	LIST_INIT(&pgsql_db_conn_strings);

	kore_pool_init(&pgsql_job_pool, "pgsql_job_pool",
	    sizeof(struct pgsql_job), 100);
	kore_pool_init(&pgsql_wait_pool, "pgsql_wait_pool",
	    sizeof(struct pgsql_wait), pgsql_queue_limit);

#if defined(__linux__)
	kore_seccomp_filter("pgsql", filter_pgsql,
	    KORE_FILTER_LEN(filter_pgsql));
#endif
}

void
kore_pgsql_sys_cleanup(void)
{
	struct pgsql_conn	*conn, *next;

	kore_pool_cleanup(&pgsql_job_pool);
	kore_pool_cleanup(&pgsql_wait_pool);

	for (conn = TAILQ_FIRST(&pgsql_conn_free); conn != NULL; conn = next) {
		next = TAILQ_NEXT(conn, list);
		pgsql_conn_cleanup(conn);
	}
}

void
kore_pgsql_init(struct kore_pgsql *pgsql)
{
	memset(pgsql, 0, sizeof(*pgsql));
	pgsql->state = KORE_PGSQL_STATE_INIT;
}

int
kore_pgsql_setup(struct kore_pgsql *pgsql, const char *dbname, int flags)
{
	struct pgsql_db		*db;

	if ((flags & KORE_PGSQL_ASYNC) && (flags & KORE_PGSQL_SYNC)) {
		pgsql_set_error(pgsql, "invalid query init parameters");
		return (KORE_RESULT_ERROR);
	}

	if (flags & KORE_PGSQL_ASYNC) {
		if (pgsql->req == NULL && pgsql->cb == NULL) {
			pgsql_set_error(pgsql, "nothing was bound");
			return (KORE_RESULT_ERROR);
		}
	}

	db = NULL;
	pgsql->flags |= flags;

	LIST_FOREACH(db, &pgsql_db_conn_strings, rlist) {
		if (!strcmp(db->name, dbname))
			break;
	}

	if (db == NULL) {
		pgsql_set_error(pgsql, "no database found");
		return (KORE_RESULT_ERROR);
	}

	if ((pgsql->conn = pgsql_conn_next(pgsql, db)) == NULL)
		return (KORE_RESULT_ERROR);

	if (pgsql->flags & KORE_PGSQL_ASYNC) {
		pgsql->conn->job = kore_pool_get(&pgsql_job_pool);
		pgsql->conn->job->pgsql = pgsql;
	}

	return (KORE_RESULT_OK);
}

#if !defined(KORE_NO_HTTP)
void
kore_pgsql_bind_request(struct kore_pgsql *pgsql, struct http_request *req)
{
	if (pgsql->req != NULL || pgsql->cb != NULL)
		fatal("kore_pgsql_bind_request: already bound");

	pgsql->req = req;
	pgsql->flags |= PGSQL_LIST_INSERTED;

	LIST_INSERT_HEAD(&(req->pgsqls), pgsql, rlist);
}
#endif

void
kore_pgsql_bind_callback(struct kore_pgsql *pgsql,
    void (*cb)(struct kore_pgsql *, void *), void *arg)
{
	if (pgsql->req != NULL)
		fatal("kore_pgsql_bind_callback: already bound");

	if (pgsql->cb != NULL)
		fatal("kore_pgsql_bind_callback: already bound");

	pgsql->cb = cb;
	pgsql->arg = arg;
}

int
kore_pgsql_query(struct kore_pgsql *pgsql, const void *query)
{
	if (pgsql->conn == NULL) {
		pgsql_set_error(pgsql, "no connection was set before query");
		return (KORE_RESULT_ERROR);
	}

	if (pgsql->flags & KORE_PGSQL_SYNC) {
		pgsql->result = PQexec(pgsql->conn->db, query);
		if ((PQresultStatus(pgsql->result) != PGRES_TUPLES_OK) &&
		    (PQresultStatus(pgsql->result) != PGRES_COMMAND_OK)) {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
			return (KORE_RESULT_ERROR);
		}

		pgsql->state = KORE_PGSQL_STATE_DONE;
	} else {
		if (!PQsendQuery(pgsql->conn->db, query)) {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
			return (KORE_RESULT_ERROR);
		}

		pgsql_schedule(pgsql);
	}

	return (KORE_RESULT_OK);
}

int
kore_pgsql_v_query_params(struct kore_pgsql *pgsql,
    const void *query, int binary, int count, va_list args)
{
	int		i;
	const char	**values;
	int		*lengths, *formats, ret;

	if (pgsql->conn == NULL) {
		pgsql_set_error(pgsql, "no connection was set before query");
		return (KORE_RESULT_ERROR);
	}

	if (count > 0) {
		lengths = kore_calloc(count, sizeof(int));
		formats = kore_calloc(count, sizeof(int));
		values = kore_calloc(count, sizeof(char *));

		for (i = 0; i < count; i++) {
			values[i] = va_arg(args, void *);
			lengths[i] = va_arg(args, int);
			formats[i] = va_arg(args, int);
		}
	} else {
		lengths = NULL;
		formats = NULL;
		values = NULL;
	}

	ret = kore_pgsql_query_param_fields(pgsql, query, binary, count,
	    values, lengths, formats);

	kore_free(values);
	kore_free(lengths);
	kore_free(formats);

	return (ret);
}

int
kore_pgsql_query_param_fields(struct kore_pgsql *pgsql, const void *query,
    int binary, int count, const char **values, int *lengths, int *formats)
{
	if (pgsql->conn == NULL) {
		pgsql_set_error(pgsql, "no connection was set before query");
		return (KORE_RESULT_ERROR);
	}

	if (pgsql->flags & KORE_PGSQL_SYNC) {
		pgsql->result = PQexecParams(pgsql->conn->db, query, count,
		    NULL, (const char * const *)values, lengths, formats,
		    binary);

		if ((PQresultStatus(pgsql->result) != PGRES_TUPLES_OK) &&
		    (PQresultStatus(pgsql->result) != PGRES_COMMAND_OK)) {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
			return (KORE_RESULT_ERROR);
		}

		pgsql->state = KORE_PGSQL_STATE_DONE;
	} else {
		if (!PQsendQueryParams(pgsql->conn->db, query, count, NULL,
		    (const char * const *)values, lengths, formats, binary)) {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
			return (KORE_RESULT_ERROR);
		}

		pgsql_schedule(pgsql);
	}

	return (KORE_RESULT_OK);
}

int
kore_pgsql_query_params(struct kore_pgsql *pgsql,
    const void *query, int binary, int count, ...)
{
	int		ret;
	va_list		args;

	va_start(args, count);
	ret = kore_pgsql_v_query_params(pgsql, query, binary, count, args);
	va_end(args);

	return (ret);
}

int
kore_pgsql_register(const char *dbname, const char *connstring)
{
	struct pgsql_db		*pgsqldb;

	LIST_FOREACH(pgsqldb, &pgsql_db_conn_strings, rlist) {
		if (!strcmp(pgsqldb->name, dbname))
			return (KORE_RESULT_ERROR);
	}

	pgsqldb = kore_malloc(sizeof(*pgsqldb));
	pgsqldb->name = kore_strdup(dbname);
	pgsqldb->conn_count = 0;
	pgsqldb->conn_max = pgsql_conn_max;
	pgsqldb->conn_string = kore_strdup(connstring);
	LIST_INSERT_HEAD(&pgsql_db_conn_strings, pgsqldb, rlist);

	return (KORE_RESULT_OK);
}

void
kore_pgsql_handle(void *c, int err)
{
	struct kore_pgsql	*pgsql;
	struct pgsql_conn	*conn = (struct pgsql_conn *)c;

	if (err) {
		pgsql_conn_cleanup(conn);
		return;
	}

	if (!(conn->evt.flags & KORE_EVENT_READ))
		fatal("%s: read event not set", __func__);

	pgsql = conn->job->pgsql;

	pgsql_read_result(pgsql);

	if (pgsql->state == KORE_PGSQL_STATE_WAIT) {
#if !defined(KORE_NO_HTTP)
		if (pgsql->req != NULL)
			http_request_sleep(pgsql->req);
#endif
		if (pgsql->cb != NULL)
			pgsql->cb(pgsql, pgsql->arg);
	} else {
#if !defined(KORE_NO_HTTP)
		if (pgsql->req != NULL)
			http_request_wakeup(pgsql->req);
#endif
		if (pgsql->cb != NULL)
			pgsql->cb(pgsql, pgsql->arg);
	}
}

void
kore_pgsql_continue(struct kore_pgsql *pgsql)
{
	if (pgsql->error) {
		kore_free(pgsql->error);
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
#if !defined(KORE_NO_HTTP)
		if (pgsql->req != NULL)
			http_request_wakeup(pgsql->req);
#endif
		pgsql_conn_release(pgsql);
		break;
	case KORE_PGSQL_STATE_ERROR:
	case KORE_PGSQL_STATE_RESULT:
	case KORE_PGSQL_STATE_NOTIFY:
		kore_pgsql_handle(pgsql->conn, 0);
		break;
	default:
		fatal("unknown pgsql state %d", pgsql->state);
	}
}

void
kore_pgsql_cleanup(struct kore_pgsql *pgsql)
{
	pgsql_queue_remove(pgsql);

	if (pgsql->result != NULL)
		PQclear(pgsql->result);

	if (pgsql->error != NULL)
		kore_free(pgsql->error);

	if (pgsql->conn != NULL)
		pgsql_conn_release(pgsql);

	pgsql->result = NULL;
	pgsql->error = NULL;
	pgsql->conn = NULL;

	if (pgsql->flags & PGSQL_LIST_INSERTED) {
		LIST_REMOVE(pgsql, rlist);
		pgsql->flags &= ~PGSQL_LIST_INSERTED;
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

int
kore_pgsql_nfields(struct kore_pgsql *pgsql)
{
	return (PQnfields(pgsql->result));
}

int
kore_pgsql_getlength(struct kore_pgsql *pgsql, int row, int col)
{
	return (PQgetlength(pgsql->result, row, col));
}

char *
kore_pgsql_fieldname(struct kore_pgsql *pgsql, int field)
{
	return (PQfname(pgsql->result, field));
}

char *
kore_pgsql_getvalue(struct kore_pgsql *pgsql, int row, int col)
{
	return (PQgetvalue(pgsql->result, row, col));
}

int
kore_pgsql_column_binary(struct kore_pgsql *pgsql, int col)
{
	return (PQfformat(pgsql->result, col));
}

static struct pgsql_conn *
pgsql_conn_next(struct kore_pgsql *pgsql, struct pgsql_db *db)
{
	PGTransactionStatusType		state;
	struct pgsql_conn		*conn;
	struct kore_pgsql		rollback;

rescan:
	conn = NULL;

	TAILQ_FOREACH(conn, &pgsql_conn_free, list) {
		if (!(conn->flags & PGSQL_CONN_FREE))
			fatal("got a pgsql connection that was not free?");
		if (!strcmp(conn->name, db->name))
			break;
	}

	if (conn != NULL) {
		state = PQtransactionStatus(conn->db);
		if (state == PQTRANS_INERROR) {
			conn->flags &= ~PGSQL_CONN_FREE;
			TAILQ_REMOVE(&pgsql_conn_free, conn, list);

			kore_pgsql_init(&rollback);
			rollback.conn = conn;
			rollback.flags = KORE_PGSQL_SYNC;

			if (!kore_pgsql_query(&rollback, "ROLLBACK")) {
				kore_pgsql_logerror(&rollback);
				kore_pgsql_cleanup(&rollback);
				pgsql_conn_cleanup(conn);
			} else {
				kore_pgsql_cleanup(&rollback);
			}

			goto rescan;
		}
	}

	if (conn == NULL) {
		if (db->conn_max != 0 &&
		    db->conn_count >= db->conn_max) {
			if ((pgsql->flags & KORE_PGSQL_ASYNC) &&
			    pgsql_queue_count < pgsql_queue_limit) {
				pgsql_queue_add(pgsql);
			} else {
				pgsql_set_error(pgsql,
				    "no available connection");
			}

			return (NULL);
		}

		if ((conn = pgsql_conn_create(pgsql, db)) == NULL)
			return (NULL);
	}

	conn->flags &= ~PGSQL_CONN_FREE;
	TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	return (conn);
}

static void
pgsql_set_error(struct kore_pgsql *pgsql, const char *msg)
{
	if (pgsql->error != NULL)
		kore_free(pgsql->error);

	pgsql->error = kore_strdup(msg);
	pgsql->state = KORE_PGSQL_STATE_ERROR;
}

static void
pgsql_schedule(struct kore_pgsql *pgsql)
{
	int		fd;

	fd = PQsocket(pgsql->conn->db);
	if (fd < 0)
		fatal("PQsocket returned < 0 fd on open connection");

	kore_platform_schedule_read(fd, pgsql->conn);
	pgsql->state = KORE_PGSQL_STATE_WAIT;
	pgsql->flags |= KORE_PGSQL_SCHEDULED;

#if !defined(KORE_NO_HTTP)
	if (pgsql->req != NULL)
		http_request_sleep(pgsql->req);
#endif
	if (pgsql->cb != NULL)
		pgsql->cb(pgsql, pgsql->arg);
}

static void
pgsql_queue_add(struct kore_pgsql *pgsql)
{
	struct pgsql_wait	*pgw;

#if !defined(KORE_NO_HTTP)
	if (pgsql->req != NULL)
		http_request_sleep(pgsql->req);
#endif

	pgw = kore_pool_get(&pgsql_wait_pool);
	pgw->pgsql = pgsql;

	pgsql_queue_count++;
	TAILQ_INSERT_TAIL(&pgsql_wait_queue, pgw, list);
}

static void
pgsql_queue_remove(struct kore_pgsql *pgsql)
{
	struct pgsql_wait	*pgw, *next;

	for (pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next) {
		next = TAILQ_NEXT(pgw, list);
		if (pgw->pgsql != pgsql)
			continue;

		pgsql_queue_count--;
		TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
		kore_pool_put(&pgsql_wait_pool, pgw);
		return;
	}
}

static void
pgsql_queue_wakeup(void)
{
	struct pgsql_wait	*pgw, *next;

	for (pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next) {
		next = TAILQ_NEXT(pgw, list);

#if !defined(KORE_NO_HTTP)
		if (pgw->pgsql->req != NULL) {
			if (pgw->pgsql->req->flags & HTTP_REQUEST_DELETE) {
				pgsql_queue_count--;
				TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
				kore_pool_put(&pgsql_wait_pool, pgw);
				continue;
			}

			http_request_wakeup(pgw->pgsql->req);
		}
#endif
		if (pgw->pgsql->cb != NULL)
			pgw->pgsql->cb(pgw->pgsql, pgw->pgsql->arg);

		pgsql_queue_count--;
		TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
		kore_pool_put(&pgsql_wait_pool, pgw);
		return;
	}
}

static struct pgsql_conn *
pgsql_conn_create(struct kore_pgsql *pgsql, struct pgsql_db *db)
{
	struct pgsql_conn	*conn;

	if (db == NULL || db->conn_string == NULL)
		fatal("pgsql_conn_create: no connection string");

	db->conn_count++;

	conn = kore_calloc(1, sizeof(*conn));
	conn->job = NULL;
	conn->flags = PGSQL_CONN_FREE;
	conn->name = kore_strdup(db->name);
	TAILQ_INSERT_TAIL(&pgsql_conn_free, conn, list);

	conn->evt.type = KORE_TYPE_PGSQL_CONN;
	conn->evt.handle = kore_pgsql_handle;

	conn->db = PQconnectdb(db->conn_string);
	if (conn->db == NULL || (PQstatus(conn->db) != CONNECTION_OK)) {
		pgsql_set_error(pgsql, PQerrorMessage(conn->db));
		pgsql_conn_cleanup(conn);
		return (NULL);
	}

	return (conn);
}

static void
pgsql_conn_release(struct kore_pgsql *pgsql)
{
	int		fd;
	PGresult	*result;

	if (pgsql->conn == NULL)
		return;

	/* Async query cleanup */
	if (pgsql->flags & KORE_PGSQL_ASYNC) {
		if (pgsql->flags & KORE_PGSQL_SCHEDULED) {
			fd = PQsocket(pgsql->conn->db);
			kore_platform_disable_read(fd);

			if (pgsql->state != KORE_PGSQL_STATE_DONE)
				pgsql_cancel(pgsql);
		}
		kore_pool_put(&pgsql_job_pool, pgsql->conn->job);
	}

	/* Drain just in case. */
	while ((result = PQgetResult(pgsql->conn->db)) != NULL)
		PQclear(result);

	pgsql->conn->job = NULL;
	pgsql->conn->flags |= PGSQL_CONN_FREE;
	TAILQ_INSERT_TAIL(&pgsql_conn_free, pgsql->conn, list);

	pgsql->conn = NULL;
	pgsql->state = KORE_PGSQL_STATE_COMPLETE;

	if (pgsql->cb != NULL)
		pgsql->cb(pgsql, pgsql->arg);

	pgsql_queue_wakeup();
}

static void
pgsql_conn_cleanup(struct pgsql_conn *conn)
{
	struct kore_pgsql	*pgsql;
	struct pgsql_db		*pgsqldb;

	if (conn->flags & PGSQL_CONN_FREE)
		TAILQ_REMOVE(&pgsql_conn_free, conn, list);

	if (conn->job) {
		pgsql = conn->job->pgsql;
#if !defined(KORE_NO_HTTP)
		if (pgsql->req != NULL)
			http_request_wakeup(pgsql->req);
#endif
		pgsql->conn = NULL;
		pgsql_set_error(pgsql, PQerrorMessage(conn->db));

		kore_pool_put(&pgsql_job_pool, conn->job);
		conn->job = NULL;
	}

	if (conn->db != NULL)
		PQfinish(conn->db);

	LIST_FOREACH(pgsqldb, &pgsql_db_conn_strings, rlist) {
		if (!strcmp(pgsqldb->name, conn->name)) {
			pgsqldb->conn_count--;
			break;
		}
	}

	kore_free(conn->name);
	kore_free(conn);
}

static void
pgsql_read_result(struct kore_pgsql *pgsql)
{
	struct pgsql_conn	*conn;
	PGnotify		*notify;
	int			saved_errno;

	conn = pgsql->conn;

	for (;;) {
		if (!PQconsumeInput(conn->db)) {
			pgsql->state = KORE_PGSQL_STATE_ERROR;
			pgsql->error = kore_strdup(PQerrorMessage(conn->db));
			return;
		}

		saved_errno = errno;

		if (PQisBusy(conn->db)) {
			if (saved_errno != EAGAIN && saved_errno != EWOULDBLOCK)
				continue;
			pgsql->state = KORE_PGSQL_STATE_WAIT;
			conn->evt.flags &= ~KORE_EVENT_READ;
			return;
		}

		break;
	}

	while ((notify = PQnotifies(conn->db)) != NULL) {
		pgsql->state = KORE_PGSQL_STATE_NOTIFY;
		pgsql->notify.extra = notify->extra;
		pgsql->notify.channel = notify->relname;

		if (pgsql->cb != NULL)
			pgsql->cb(pgsql, pgsql->arg);

		PQfreemem(notify);
	}

	pgsql->result = PQgetResult(conn->db);
	if (pgsql->result == NULL) {
		pgsql->state = KORE_PGSQL_STATE_DONE;
		return;
	}

	switch (PQresultStatus(pgsql->result)) {
#if PG_VERSION_NUM >= 140000
	case PGRES_PIPELINE_SYNC:
	case PGRES_PIPELINE_ABORTED:
#endif
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
		pgsql_set_error(pgsql, PQresultErrorMessage(pgsql->result));
		break;
	}
}

static void
pgsql_cancel(struct kore_pgsql *pgsql)
{
	PGcancel	*cancel;
	char		buf[256];

	if ((cancel = PQgetCancel(pgsql->conn->db)) != NULL) {
		if (!PQcancel(cancel, buf, sizeof(buf)))
			kore_log(LOG_ERR, "failed to cancel: %s", buf);
		PQfreeCancel(cancel);
	}
}
