/*
 * Copyright (c) 2017 Joris Vink <joris@coders.se>
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
 * This is the same as pgsql.c except the query is fired off when
 * a new connection is made to Kore on port 8889.
 *
 * Instead of binding an http_request to the pgsql data structure we
 * use a callback function that is called for every state change.
 *
 * We pass the connection as an argument to this function.
 */

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

void	connection_del(struct connection *c);
void	connection_new(struct connection *);

void	db_state_change(struct kore_pgsql *, void *);
void	db_init(struct connection *, struct kore_pgsql *);
void	db_results(struct kore_pgsql *, struct connection *);

void
connection_new(struct connection *c)
{
	struct kore_pgsql	*pgsql;

	c->disconnect = connection_del;
	c->proto = CONN_PROTO_UNKNOWN;
	c->state = CONN_STATE_ESTABLISHED;

	pgsql = kore_calloc(1, sizeof(*pgsql));

	kore_pgsql_init(pgsql);
	kore_pgsql_bind_callback(pgsql, db_state_change, c);

	c->hdlr_extra = pgsql;
	printf("new connection %p\n", (void *)c);

	db_init(c, pgsql);
}

void
db_init(struct connection *c, struct kore_pgsql *pgsql)
{
	if (!kore_pgsql_setup(pgsql, "db", KORE_PGSQL_ASYNC)) {
		if (pgsql->state == KORE_PGSQL_STATE_INIT) {
			printf("\twaiting for available pgsql connection\n");
			return;
		}

		kore_pgsql_logerror(pgsql);
		kore_connection_disconnect(c);
		return;
	}

	printf("\tgot pgsql connection\n");
	if (!kore_pgsql_query(pgsql, "SELECT * FROM coders, pg_sleep(5)")) {
		kore_pgsql_logerror(pgsql);
		kore_connection_disconnect(c);
		return;
	}
	printf("\tquery fired off!\n");
}

void
connection_del(struct connection *c)
{
	printf("%p: disconnecting\n", (void *)c);

	if (c->hdlr_extra != NULL)
		kore_pgsql_cleanup(c->hdlr_extra);

	kore_free(c->hdlr_extra);
	c->hdlr_extra = NULL;
}

void
db_state_change(struct kore_pgsql *pgsql, void *arg)
{
	struct connection	*c = arg;

	printf("%p: state change on pgsql %d\n", arg, pgsql->state);

	switch (pgsql->state) {
	case KORE_PGSQL_STATE_INIT:
		db_init(c, pgsql);
		break;
	case KORE_PGSQL_STATE_WAIT:
		break;
	case KORE_PGSQL_STATE_COMPLETE:
		kore_connection_disconnect(c);
		break;
	case KORE_PGSQL_STATE_ERROR:
		kore_pgsql_logerror(pgsql);
		kore_connection_disconnect(c);
		break;
	case KORE_PGSQL_STATE_RESULT:
		db_results(pgsql, c);
		break;
	default:
		kore_pgsql_continue(pgsql);
		break;
	}
}

void
db_results(struct kore_pgsql *pgsql, struct connection *c)
{
	char		*name;
	int		i, rows;

	rows = kore_pgsql_ntuples(pgsql);
	for (i = 0; i < rows; i++) {
		name = kore_pgsql_getvalue(pgsql, i, 0);
		net_send_queue(c, name, strlen(name));
	}

	net_send_flush(c);
	kore_pgsql_continue(pgsql);
}
