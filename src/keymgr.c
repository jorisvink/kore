/*
 * Copyright (c) 2016-2017 Joris Vink <joris@coders.se>
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
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "kore.h"

#if !defined(KORE_NO_TLS)

#define RAND_TMP_FILE		"rnd.tmp"
#define RAND_POLL_INTERVAL	(1800 * 1000)
#define RAND_FILE_SIZE		1024

struct key {
	EVP_PKEY		*pkey;
	struct kore_domain	*dom;
	TAILQ_ENTRY(key)	list;
};

char				*rand_file = NULL;

static TAILQ_HEAD(, key)	keys;
extern volatile sig_atomic_t	sig_recv;
static int			initialized = 0;

static void	keymgr_load_randfile(void);
static void	keymgr_save_randfile(void);

static void	keymgr_load_privatekey(struct kore_domain *);
static void	keymgr_msg_recv(struct kore_msg *, const void *);
static void	keymgr_entropy_request(struct kore_msg *, const void *);

static void	keymgr_rsa_encrypt(struct kore_msg *, const void *,
		    struct key *);
static void	keymgr_ecdsa_sign(struct kore_msg *, const void *,
		    struct key *);

void
kore_keymgr_run(void)
{
	int		quit;
	u_int64_t	now, last_seed;

	if (rand_file != NULL) {
		keymgr_load_randfile();
		keymgr_save_randfile();
	} else {
		kore_log(LOG_WARNING, "no rand_file location specified");
	}

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
	kore_msg_register(KORE_MSG_ENTROPY_REQ, keymgr_entropy_request);

	last_seed = 0;
	kore_log(LOG_NOTICE, "key manager started");

	while (quit != 1) {
		now = kore_time_ms();
		if ((now - last_seed) > RAND_POLL_INTERVAL) {
			RAND_poll();
			last_seed = now;
		}

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

		EVP_PKEY_free(key->pkey);
		kore_free(key);
	}
}

static void
keymgr_load_randfile(void)
{
	int		fd;
	struct stat	st;
	ssize_t		ret;
	size_t		total;
	u_int8_t	buf[RAND_FILE_SIZE];

	if (rand_file == NULL)
		return;

	if ((fd = open(rand_file, O_RDONLY)) == -1)
		fatal("open(%s): %s", rand_file, errno_s);

	if (fstat(fd, &st) == -1)
		fatal("stat(%s): %s", rand_file, errno_s);
	if (!S_ISREG(st.st_mode))
		fatal("%s is not a file", rand_file);
	if (st.st_size != RAND_FILE_SIZE)
		fatal("%s has an invalid size", rand_file);

	total = 0;

	while (total != RAND_FILE_SIZE) {
		ret = read(fd, buf, sizeof(buf));
		if (ret == 0)
			fatal("EOF on %s", rand_file);

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("read(%s): %s", rand_file, errno_s);
		}

		total += (size_t)ret;
		RAND_seed(buf, (int)ret);
		OPENSSL_cleanse(buf, sizeof(buf));
	}

	(void)close(fd);
	if (unlink(rand_file) == -1) {
		kore_log(LOG_WARNING, "failed to unlink %s: %s",
		    rand_file, errno_s);
	}
}

static void
keymgr_save_randfile(void)
{
	int		fd;
	struct stat	st;
	ssize_t		ret;
	u_int8_t	buf[RAND_FILE_SIZE];

	if (rand_file == NULL)
		return;

	if (stat(RAND_TMP_FILE, &st) != -1) {
		kore_log(LOG_WARNING, "removing stale %s file", RAND_TMP_FILE);
		(void)unlink(RAND_TMP_FILE);
	}

	if (RAND_bytes(buf, sizeof(buf)) != 1) {
		kore_log(LOG_WARNING, "RAND_bytes: %s", ssl_errno_s);
		goto cleanup;
	}

	if ((fd = open(RAND_TMP_FILE,
	    O_CREAT | O_TRUNC | O_WRONLY, 0400)) == -1) {
		kore_log(LOG_WARNING,
		    "failed to open %s: %s - random data not written",
		    RAND_TMP_FILE, errno_s);
		goto cleanup;
	}

	ret = write(fd, buf, sizeof(buf));
	if (ret == -1 || (size_t)ret != sizeof(buf)) {
		kore_log(LOG_WARNING, "failed to write random data");
		(void)close(fd);
		(void)unlink(RAND_TMP_FILE);
		goto cleanup;
	}

	if (close(fd) == -1)
		kore_log(LOG_WARNING, "close(%s): %s", RAND_TMP_FILE, errno_s);

	if (rename(RAND_TMP_FILE, rand_file) == -1) {
		kore_log(LOG_WARNING, "rename(%s, %s): %s",
		    RAND_TMP_FILE, rand_file, errno_s);
		(void)unlink(rand_file);
		(void)unlink(RAND_TMP_FILE);
	}

cleanup:
	OPENSSL_cleanse(buf, sizeof(buf));
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

	if ((key->pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL)
		fatal("PEM_read_PrivateKey: %s", ssl_errno_s);

	(void)fclose(fp);
	kore_free(dom->certkey);
	dom->certkey = NULL;

	TAILQ_INSERT_TAIL(&keys, key, list);
}

static void
keymgr_entropy_request(struct kore_msg *msg, const void *data)
{
	u_int8_t	buf[RAND_FILE_SIZE];

	if (RAND_bytes(buf, sizeof(buf)) != 1) {
		kore_log(LOG_WARNING,
		    "failed to generate entropy for worker %u: %s",
		    msg->src, ssl_errno_s);
		return;
	}

	/* No cleanse, this stuff is leaked in the kernel path anyway. */
	kore_msg_send(msg->src, KORE_MSG_ENTROPY_RESP, buf, sizeof(buf));
}

static void
keymgr_msg_recv(struct kore_msg *msg, const void *data)
{
	const struct kore_keyreq	*req;
	struct key			*key;

	if (msg->length < sizeof(*req))
		return;

	req = (const struct kore_keyreq *)data;
	if (msg->length != (sizeof(*req) + req->data_len))
		return;

	key = NULL;
	TAILQ_FOREACH(key, &keys, list) {
		if (!strncmp(key->dom->domain, req->domain, req->domain_len))
			break;
	}

	if (key == NULL)
		return;

	switch (EVP_PKEY_id(key->pkey)) {
	case EVP_PKEY_RSA:
		keymgr_rsa_encrypt(msg, data, key);
		break;
	case EVP_PKEY_EC:
		keymgr_ecdsa_sign(msg, data, key);
		break;
	default:
		break;
	}
}

static void
keymgr_rsa_encrypt(struct kore_msg *msg, const void *data, struct key *key)
{
	int				ret;
	const struct kore_keyreq	*req;
	size_t				keylen;
	u_int8_t			buf[1024];

	req = (const struct kore_keyreq *)data;

	keylen = RSA_size(key->pkey->pkey.rsa);
	if (req->data_len > keylen || keylen > sizeof(buf))
		return;

	ret = RSA_private_encrypt(req->data_len, req->data,
	    buf, key->pkey->pkey.rsa, req->padding);
	if (ret != RSA_size(key->pkey->pkey.rsa))
		return;

	kore_msg_send(msg->src, KORE_MSG_KEYMGR_RESP, buf, ret);
}

static void
keymgr_ecdsa_sign(struct kore_msg *msg, const void *data, struct key *key)
{
	size_t				len;
	const struct kore_keyreq	*req;
	unsigned int			siglen;
	u_int8_t			sig[1024];

	req = (const struct kore_keyreq *)data;

	len = ECDSA_size(key->pkey->pkey.ec);
	if (req->data_len > len || len > sizeof(sig))
		return;

	if (ECDSA_sign(key->pkey->save_type, req->data, req->data_len,
	    sig, &siglen, key->pkey->pkey.ec) == 0)
		return;

	if (siglen > sizeof(sig))
		return;

	kore_msg_send(msg->src, KORE_MSG_KEYMGR_RESP, sig, siglen);
}

#endif
