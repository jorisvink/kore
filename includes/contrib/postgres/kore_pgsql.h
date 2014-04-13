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

#ifndef _H_KORE_PGSQL
#define _H_KORE_PGSQL

#include <libpq-fe.h>

struct kore_pgsql {
	u_int8_t		state;
	char			*error;
	PGresult		*result;
	void			*conn;
};

void		kore_pgsql_init(void);
void		kore_pgsql_handle(void *, int);
void		kore_pgsql_cleanup(struct http_request *);
void		kore_pgsql_continue(struct http_request *, int);
int		kore_pgsql_query(struct http_request *, char *, int);

int		kore_pgsql_ntuples(struct kore_pgsql *);
void		kore_pgsql_logerror(struct kore_pgsql *);
char		*kore_pgsql_getvalue(struct kore_pgsql *, int, int);

#define KORE_PGSQL_STATE_INIT		1
#define KORE_PGSQL_STATE_WAIT		2
#define KORE_PGSQL_STATE_RESULT		3
#define KORE_PGSQL_STATE_ERROR		4
#define KORE_PGSQL_STATE_DONE		5
#define KORE_PGSQL_STATE_COMPLETE	6

#define KORE_PGSQL(r, q, i, s)						\
	do {								\
		if (r->pgsql[i] == NULL)				\
			if (!kore_pgsql_query(r, q, i)) {		\
				if (r->pgsql[i] == NULL)		\
					return (KORE_RESULT_RETRY);	\
				s;					\
				r->pgsql[i]->state =			\
				    KORE_PGSQL_STATE_COMPLETE;		\
			}						\
		if (r->pgsql[i] == NULL)				\
			return (KORE_RESULT_RETRY);			\
		switch (r->pgsql[i]->state) {				\
		case KORE_PGSQL_STATE_ERROR:				\
		case KORE_PGSQL_STATE_RESULT:				\
			s;						\
		case KORE_PGSQL_STATE_COMPLETE:				\
			break;						\
		default:						\
			kore_pgsql_continue(r, i);			\
			return (KORE_RESULT_RETRY);			\
		}							\
		if (r->pgsql[i]->state == KORE_PGSQL_STATE_ERROR ||	\
		    r->pgsql[i]->state == KORE_PGSQL_STATE_RESULT) {	\
			kore_pgsql_continue(r, i);			\
			return (KORE_RESULT_RETRY);			\
		}							\
	} while (0);

#define KORE_PGSQL_EXEC(r, q, i)					\
	do {								\
		if (r->pgsql[i] == NULL)				\
			kore_pgsql_query(r, q, i);			\
		if (r->pgsql[i] == NULL)				\
			return (KORE_RESULT_RETRY);			\
	} while (0);

#endif
