/*
 * Copyright (c) 2016 Joris Vink <joris@coders.se>
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

#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "kore.h"

#if !defined(KORE_NO_TLS)
struct key {
	RSA			*rsa;
	struct kore_domain	*dom;
	TAILQ_ENTRY(key)	list;
};

static TAILQ_HEAD(, key)	keys;
extern volatile sig_atomic_t	sig_recv;
static int			initialized = 0;

static void	keymgr_load_privatekey(struct kore_domain *);
static void	keymgr_msg_recv(struct kore_msg *, const void *);

void
kore_keymgr_run(void)
{
	int		quit;

	quit = 0;
	initialized = 1;
	TAILQ_INIT(&keys);

	kore_listener_cleanup();
	kore_module_cleanup();

	kore_domain_callback(keymgr_load_privatekey);
	kore_worker_privdrop();

	net_init();
	kore_connection_init();
	kore_platform_event_init();

	kore_msg_worker_init();
	kore_msg_register(KORE_MSG_KEYMGR_REQ, keymgr_msg_recv);

	kore_log(LOG_NOTICE, "key manager started");

	while (quit != 1) {
		if (sig_recv != 0) {
			switch (sig_recv) {
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;
			default:
				break;
			}
			sig_recv = 0;
		}

		kore_platform_event_wait(1000);
		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	}

	kore_keymgr_cleanup();
	kore_platform_event_cleanup();
	kore_connection_cleanup();
	net_cleanup();
}

void
kore_keymgr_cleanup(void)
{
	struct key		*key, *next;

	kore_log(LOG_NOTICE, "cleaning up keys");

	if (initialized == 0)
		return;

	for (key = TAILQ_FIRST(&keys); key != NULL; key = next) {
		next = TAILQ_NEXT(key, list);
		TAILQ_REMOVE(&keys, key, list);

		RSA_free(key->rsa);
		kore_mem_free(key);
	}
}

static void
keymgr_load_privatekey(struct kore_domain *dom)
{
	FILE			*fp;
	struct key		*key;

	if (dom->certkey == NULL)
		return;

	if ((fp = fopen(dom->certkey, "r")) == NULL)
		fatal("failed to open private key: %s", dom->certkey);

	key = kore_malloc(sizeof(*key));
	key->dom = dom;

	if ((key->rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL)
		fatal("PEM_read_RSAPrivateKey: %s", ssl_errno_s);

	(void)fclose(fp);
	kore_mem_free(dom->certkey);
	dom->certkey = NULL;

	TAILQ_INSERT_TAIL(&keys, key, list);
}

static void
keymgr_msg_recv(struct kore_msg *msg, const void *data)
{
	int				ret;
	const struct kore_keyreq	*req;
	struct key			*key;
	size_t				keylen;
	u_int8_t			buf[1024];

	if (msg->length < sizeof(*req))
		return;

	key = NULL;
	req = (const struct kore_keyreq *)data;

	if (msg->length != (sizeof(*req) + req->data_len))
		return;

	TAILQ_FOREACH(key, &keys, list) {
		if (strncmp(key->dom->domain, req->domain, req->domain_len))
			continue;

		keylen = RSA_size(key->rsa);
		if (req->data_len > keylen || keylen > sizeof(buf))
			return;

		ret = RSA_private_encrypt(req->data_len, req->data,
		    buf, key->rsa, req->padding);
		if (ret != RSA_size(key->rsa))
			return;

		kore_msg_send(msg->src, KORE_MSG_KEYMGR_RESP, buf, ret);
		break;
	}
}

#endif
