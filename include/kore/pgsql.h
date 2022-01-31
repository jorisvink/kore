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

#ifndef _H_KORE_PGSQL
#define _H_KORE_PGSQL

#include <libpq-fe.h>

#define KORE_PGSQL_FORMAT_TEXT		0
#define KORE_PGSQL_FORMAT_BINARY	1

#define KORE_PGSQL_SYNC			0x0001
#define KORE_PGSQL_ASYNC		0x0002
#define KORE_PGSQL_SCHEDULED		0x0004

#define KORE_PGSQL_PARAM_BINARY(v, l)	v, l, 1
#define KORE_PGSQL_PARAM_TEXT_LEN(v, l)	v, l, 0
#define KORE_PGSQL_PARAM_TEXT(v)	v, strlen(v), 0

#if defined(__cplusplus)
extern "C" {
#endif

struct pgsql_conn {
	struct kore_event		evt;
	u_int8_t			flags;
	char				*name;

	PGconn				*db;
	struct pgsql_job		*job;
	TAILQ_ENTRY(pgsql_conn)		list;
};

struct pgsql_db {
	char			*name;
	char			*conn_string;
	u_int16_t		conn_max;
	u_int16_t		conn_count;

	LIST_ENTRY(pgsql_db)	rlist;
};

struct kore_pgsql {
	u_int8_t		state;
	int			flags;
	char			*error;
	PGresult		*result;
	struct pgsql_conn	*conn;

	struct {
		char		*channel;
		char		*extra;
	} notify;

	struct http_request	*req;
	void			*arg;
	void			(*cb)(struct kore_pgsql *, void *);

	LIST_ENTRY(kore_pgsql)	rlist;
};

extern u_int16_t	pgsql_conn_max;
extern u_int32_t	pgsql_queue_limit;

void	kore_pgsql_sys_init(void);
void	kore_pgsql_sys_cleanup(void);
void	kore_pgsql_init(struct kore_pgsql *);
void	kore_pgsql_bind_request(struct kore_pgsql *, struct http_request *);
void	kore_pgsql_bind_callback(struct kore_pgsql *,
	    void (*cb)(struct kore_pgsql *, void *), void *);
int	kore_pgsql_setup(struct kore_pgsql *, const char *, int);
void	kore_pgsql_handle(void *, int);
void	kore_pgsql_cleanup(struct kore_pgsql *);
void	kore_pgsql_continue(struct kore_pgsql *);
int	kore_pgsql_query(struct kore_pgsql *, const void *);
int	kore_pgsql_query_params(struct kore_pgsql *,
	    const void *, int, int, ...);
int	kore_pgsql_v_query_params(struct kore_pgsql *,
	    const void *, int, int, va_list);
int	kore_pgsql_query_param_fields(struct kore_pgsql *, const void *,
	    int, int, const char **, int *, int *);
int	kore_pgsql_register(const char *, const char *);
int	kore_pgsql_ntuples(struct kore_pgsql *);
int	kore_pgsql_nfields(struct kore_pgsql *);
void	kore_pgsql_logerror(struct kore_pgsql *);
char	*kore_pgsql_fieldname(struct kore_pgsql *, int);
char	*kore_pgsql_getvalue(struct kore_pgsql *, int, int);
int	kore_pgsql_getlength(struct kore_pgsql *, int, int);
int	kore_pgsql_column_binary(struct kore_pgsql *, int);

#if defined(__cplusplus)
}
#endif

#define KORE_PGSQL_STATE_INIT		1
#define KORE_PGSQL_STATE_WAIT		2
#define KORE_PGSQL_STATE_RESULT		3
#define KORE_PGSQL_STATE_ERROR		4
#define KORE_PGSQL_STATE_DONE		5
#define KORE_PGSQL_STATE_COMPLETE	6
#define KORE_PGSQL_STATE_NOTIFY		7

#endif
