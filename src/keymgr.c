/*
 * Copyright (c) 2017-2019 Joris Vink <joris@coders.se>
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
 * The kore keymgr process is responsible for managing certificates
 * and their matching private keys.
 *
 * It is the only process in Kore that holds the private keys (the workers
 * do not have a copy of them in memory).
 *
 * When a worker requires the private key for signing it will send a message
 * to the keymgr with the to-be-signed data (KORE_MSG_KEYMGR_REQ). The keymgr
 * will perform the signing and respond with a KORE_MSG_KEYMGR_RESP message.
 *
 * The keymgr can transparently reload the private keys and certificates
 * for a configured domain when it receives a SIGUSR1. It it reloads them
 * it will send the newly loaded certificate chains to the worker processes
 * which will update their TLS contexts accordingly.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "kore.h"

#define RAND_TMP_FILE		"rnd.tmp"
#define RAND_POLL_INTERVAL	(1800 * 1000)
#define RAND_FILE_SIZE		1024

#if defined(__linux__)
#include "seccomp.h"

/* The syscalls our keymgr is allowed to perform, only. */
static struct sock_filter filter_keymgr[] = {
	/* Required to deal with private keys and certs. */
	KORE_SYSCALL_ALLOW(open),
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(fstat),
	KORE_SYSCALL_ALLOW(futex),
	KORE_SYSCALL_ALLOW(writev),
	KORE_SYSCALL_ALLOW(openat),

	/* Net related. */
	KORE_SYSCALL_ALLOW(poll),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(recvfrom),
	KORE_SYSCALL_ALLOW(epoll_wait),
	KORE_SYSCALL_ALLOW(epoll_pwait),

	/* Process things. */
	KORE_SYSCALL_ALLOW(exit),
	KORE_SYSCALL_ALLOW(kill),
	KORE_SYSCALL_ALLOW(getuid),
	KORE_SYSCALL_ALLOW(getpid),
	KORE_SYSCALL_ALLOW(arch_prctl),
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(sigaltstack),
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(rt_sigaction),
	KORE_SYSCALL_ALLOW(rt_sigprocmask),

	/* Other things. */
	KORE_SYSCALL_ALLOW(brk),
	KORE_SYSCALL_ALLOW(mmap),
	KORE_SYSCALL_ALLOW(munmap),
	KORE_SYSCALL_ALLOW(clock_gettime),
#if defined(__NR_getrandom)
	KORE_SYSCALL_ALLOW(getrandom),
#endif
};
#endif

struct key {
	EVP_PKEY		*pkey;
	struct kore_domain	*dom;
	TAILQ_ENTRY(key)	list;
};

char				*rand_file = NULL;

static TAILQ_HEAD(, key)	keys;
static int			initialized = 0;

static void	keymgr_reload(void);
static void	keymgr_load_randfile(void);
static void	keymgr_save_randfile(void);

static void	keymgr_load_privatekey(struct kore_domain *);
static void	keymgr_msg_recv(struct kore_msg *, const void *);
static void	keymgr_entropy_request(struct kore_msg *, const void *);
static void	keymgr_certificate_request(struct kore_msg *, const void *);
static void	keymgr_submit_certificates(struct kore_domain *, u_int16_t);
static void	keymgr_submit_file(u_int8_t, struct kore_domain *,
		    const char *, u_int16_t, int);

static void	keymgr_rsa_encrypt(struct kore_msg *, const void *,
		    struct key *);
static void	keymgr_ecdsa_sign(struct kore_msg *, const void *,
		    struct key *);

int	keymgr_active = 0;
char	*keymgr_root_path = NULL;
char	*keymgr_runas_user = NULL;

void
kore_keymgr_run(void)
{
	int		quit;
	u_int64_t	now, last_seed;

	if (keymgr_active == 0)
		fatal("%s: called with keymgr_active == 0", __func__);

	quit = 0;

	kore_server_closeall();
	kore_module_cleanup();

	net_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_worker_init();
	kore_msg_register(KORE_MSG_KEYMGR_REQ, keymgr_msg_recv);
	kore_msg_register(KORE_MSG_ENTROPY_REQ, keymgr_entropy_request);
	kore_msg_register(KORE_MSG_CERTIFICATE_REQ, keymgr_certificate_request);

#if defined(__linux__)
	/* Drop all enabled seccomp filters, and add only ours. */
	kore_seccomp_drop();
	kore_seccomp_filter("keymgr", filter_keymgr,
	    KORE_FILTER_LEN(filter_keymgr));
#endif

	kore_worker_privdrop(keymgr_runas_user, keymgr_root_path);

	if (rand_file != NULL) {
		keymgr_load_randfile();
		keymgr_save_randfile();
	} else if (!kore_quiet) {
		kore_log(LOG_WARNING, "no rand_file location specified");
	}

	initialized = 1;

	keymgr_reload();
	RAND_poll();
	last_seed = 0;

#if defined(__OpenBSD__)
	if (pledge("stdio rpath", NULL) == -1)
		fatal("failed to pledge keymgr process");
#endif

	if (!kore_quiet)
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
			case SIGUSR1:
				keymgr_reload();
				break;
			default:
				break;
			}
			sig_recv = 0;
		}

		kore_platform_event_wait(1000);
		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	}

	kore_keymgr_cleanup(1);
	kore_platform_event_cleanup();
	kore_connection_cleanup();
	net_cleanup();
}

void
kore_keymgr_cleanup(int final)
{
	struct key		*key, *next;

	if (final && !kore_quiet)
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
keymgr_reload(void)
{
	struct kore_server	*srv;
	struct kore_domain	*dom;

	if (!kore_quiet)
		kore_log(LOG_INFO, "(re)loading certificates, keys and CRLs");

	kore_keymgr_cleanup(0);
	TAILQ_INIT(&keys);

	kore_domain_callback(keymgr_load_privatekey);

	/* can't use kore_domain_callback() due to dst parameter. */
	LIST_FOREACH(srv, &kore_servers, list) {
		if (srv->tls == 0)
			continue;
		TAILQ_FOREACH(dom, &srv->domains, list)
			keymgr_submit_certificates(dom, KORE_MSG_WORKER_ALL);
	}
}

static void
keymgr_submit_certificates(struct kore_domain *dom, u_int16_t dst)
{
	keymgr_submit_file(KORE_MSG_CERTIFICATE, dom, dom->certfile, dst, 0);

	if (dom->crlfile != NULL)
		keymgr_submit_file(KORE_MSG_CRL, dom, dom->crlfile, dst, 1);
}

static void
keymgr_submit_file(u_int8_t id, struct kore_domain *dom,
    const char *file, u_int16_t dst, int can_fail)
{
	int				fd;
	struct stat			st;
	ssize_t				ret;
	size_t				len;
	struct kore_x509_msg		*msg;
	u_int8_t			*payload;

	if ((fd = open(file, O_RDONLY)) == -1) {
		if (errno == ENOENT && can_fail)
			return;
		fatal("open(%s): %s", file, errno_s);
	}

	if (fstat(fd, &st) == -1)
		fatal("stat(%s): %s", file, errno_s);

	if (!S_ISREG(st.st_mode))
		fatal("%s is not a file", file);

	if (st.st_size <= 0 || st.st_size > (1024 * 1024 * 10)) {
		fatal("%s length is not valid (%jd)", file,
		    (intmax_t)st.st_size);
	}

	len = sizeof(*msg) + st.st_size;
	payload = kore_calloc(1, len);

	msg = (struct kore_x509_msg *)payload;
	msg->domain_len = strlen(dom->domain);
	if (msg->domain_len > sizeof(msg->domain))
		fatal("domain name '%s' too long", dom->domain);
	memcpy(msg->domain, dom->domain, msg->domain_len);

	msg->data_len = st.st_size;
	ret = read(fd, &msg->data[0], msg->data_len);
	if (ret == -1)
		fatal("failed to read from %s: %s", file, errno_s);
	if (ret == 0)
		fatal("eof while reading %s", file);

	if ((size_t)ret != msg->data_len) {
		fatal("bad read on %s: expected %zu, got %zd",
		    file, msg->data_len, ret);
	}

	kore_msg_send(dst, id, payload, len);
	kore_free(payload);
	close(fd);
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

	if (dom->server->tls == 0)
		return;

	if ((fp = fopen(dom->certkey, "r")) == NULL)
		fatal("failed to open private key: %s", dom->certkey);

	key = kore_calloc(1, sizeof(*key));
	key->dom = dom;

	if ((key->pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL)
		fatal("PEM_read_PrivateKey: %s", ssl_errno_s);

	(void)fclose(fp);

	TAILQ_INSERT_TAIL(&keys, key, list);
}

static void
keymgr_certificate_request(struct kore_msg *msg, const void *data)
{
	struct kore_server	*srv;
	struct kore_domain	*dom;

	LIST_FOREACH(srv, &kore_servers, list) {
		if (srv->tls == 0)
			continue;
		TAILQ_FOREACH(dom, &srv->domains, list)
			keymgr_submit_certificates(dom, msg->src);
	}
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
	if (req->domain_len > KORE_DOMAINNAME_LEN)
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
	RSA				*rsa;
	const struct kore_keyreq	*req;
	size_t				keylen;
	u_int8_t			buf[1024];

	req = (const struct kore_keyreq *)data;

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	rsa = EVP_PKEY_get0_RSA(key->pkey);
#else
	rsa = key->pkey->pkey.rsa;
#endif
	keylen = RSA_size(rsa);
	if (req->data_len > keylen || keylen > sizeof(buf))
		return;

	ret = RSA_private_encrypt(req->data_len, req->data,
	    buf, rsa, req->padding);
	if (ret != RSA_size(rsa))
		return;

	kore_msg_send(msg->src, KORE_MSG_KEYMGR_RESP, buf, ret);
}

static void
keymgr_ecdsa_sign(struct kore_msg *msg, const void *data, struct key *key)
{
	size_t				len;
	EC_KEY				*ec;
	const struct kore_keyreq	*req;
	unsigned int			siglen;
	u_int8_t			sig[1024];

	req = (const struct kore_keyreq *)data;
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	ec = EVP_PKEY_get0_EC_KEY(key->pkey);
#else
	ec = key->pkey->pkey.ec;
#endif
	len = ECDSA_size(ec);
	if (req->data_len > len || len > sizeof(sig))
		return;

	if (ECDSA_sign(EVP_PKEY_NONE, req->data, req->data_len,
	    sig, &siglen, ec) == 0)
		return;

	if (siglen > sizeof(sig))
		return;

	kore_msg_send(msg->src, KORE_MSG_KEYMGR_RESP, sig, siglen);
}
