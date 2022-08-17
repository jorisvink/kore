/*
 * Copyright (c) 2017-2022 Joris Vink <joris@coders.se>
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
 *
 * If ACME is turned on the keymgr will also hold all account and domain
 * keys and will initiate the process of acquiring new certificates against
 * the ACME provider that is configured if those certificates do not exist
 * or are expired (or are expiring soon).
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "kore.h"

#if defined(KORE_USE_ACME)
#include "acme.h"
#endif

#define RAND_TMP_FILE		"rnd.tmp"
#define RAND_POLL_INTERVAL	(1800 * 1000)
#define RAND_FILE_SIZE		1024

#if defined(__linux__)
#include "seccomp.h"

/* The syscalls our keymgr is allowed to perform, only. */
static struct sock_filter filter_keymgr[] = {
	/* Deny these, but with EACCESS instead of dying. */
	KORE_SYSCALL_DENY(ioctl, EACCES),

	/* Required to deal with private keys and certs. */
#if defined(SYS_open)
	KORE_SYSCALL_ALLOW(open),
#endif
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(lseek),
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(close),
#if defined(SYS_stat)
	KORE_SYSCALL_ALLOW(stat),
#endif
	KORE_SYSCALL_ALLOW(fstat),
#if defined(SYS_fstat64)
	KORE_SYSCALL_ALLOW(fstat64),
#endif
#if defined(SYS_newfstatat)
	KORE_SYSCALL_ALLOW(newfstatat),
#endif
	KORE_SYSCALL_ALLOW(futex),
	KORE_SYSCALL_ALLOW(writev),
	KORE_SYSCALL_ALLOW(openat),
#if defined(SYS_access)
	KORE_SYSCALL_ALLOW(access),
#endif
	KORE_SYSCALL_ALLOW(faccessat),

	/* Net related. */
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
#if defined(SYS_send)
	KORE_SYSCALL_ALLOW(send),
#endif
	KORE_SYSCALL_ALLOW(sendto),
#if defined(SYS_recv)
	KORE_SYSCALL_ALLOW(recv),
#endif
	KORE_SYSCALL_ALLOW(recvfrom),
#if defined(SYS_epoll_wait)
	KORE_SYSCALL_ALLOW(epoll_wait),
#endif
	KORE_SYSCALL_ALLOW(epoll_pwait),

	/* Process things. */
	KORE_SYSCALL_ALLOW(exit),
	KORE_SYSCALL_ALLOW(kill),
	KORE_SYSCALL_ALLOW(getuid),
	KORE_SYSCALL_ALLOW(getpid),
#if defined(SYS_arch_prctl)
	KORE_SYSCALL_ALLOW(arch_prctl),
#endif
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(sigaltstack),
#if defined(SYS_sigreturn)
	KORE_SYSCALL_ALLOW(sigreturn),
#endif
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(rt_sigaction),
	KORE_SYSCALL_ALLOW(rt_sigprocmask),

	/* Other things. */
	KORE_SYSCALL_ALLOW(brk),
#if defined(SYS_mmap)
	KORE_SYSCALL_ALLOW(mmap),
#endif
#if defined(SYS_mmap2)
	KORE_SYSCALL_ALLOW(mmap2),
#endif
#if defined(SYS_madvise)
	KORE_SYSCALL_ALLOW(madvise),
#endif
	KORE_SYSCALL_ALLOW(munmap),
	KORE_SYSCALL_ALLOW(clock_gettime),
#if defined(__NR_getrandom)
	KORE_SYSCALL_ALLOW(getrandom),
#endif

#if defined(KORE_USE_ACME)
#if defined(SYS_mkdir)
	KORE_SYSCALL_ALLOW(mkdir),
#endif
	KORE_SYSCALL_ALLOW(mkdirat),
	KORE_SYSCALL_ALLOW(umask),
#endif
};
#endif

struct key {
	KORE_PRIVATE_KEY	*pkey;
	struct kore_domain	*dom;
	TAILQ_ENTRY(key)	list;
};

char				*kore_rand_file = NULL;

static TAILQ_HEAD(, key)	keys;
static int			initialized = 0;

#if defined(KORE_USE_ACME)

#define ACME_ORDER_STATE_INIT		1
#define ACME_ORDER_STATE_SUBMIT		2

#define ACME_X509_EXPIRATION		120
#define ACME_TLS_ALPN_01_OID		"1.3.6.1.5.5.7.1.31"

#define ACME_RENEWAL_THRESHOLD		5
#define ACME_RENEWAL_TIMER		(3600 * 1000)

/* UTCTIME in format of YYMMDDHHMMSSZ */
#define ASN1_UTCTIME_LEN		13

/* GENERALIZEDTIME in format of YYYYMMDDHHMMSSZ */
#define ASN1_GENERALIZEDTIME_LEN	15

/* Set to 1 when we receive KORE_ACME_PROC_READY. */
static int			acmeproc_ready = 0;

/* Renewal timer for all domains under acme control. */
static struct kore_timer	*acme_renewal = NULL;

/* oid for acme extension. */
static int			acme_oid = -1;

struct acme_order {
	int			state;
	struct kore_timer	*timer;
	char			*domain;
};

static char	*keymgr_bignum_base64(const BIGNUM *);

static void	keymgr_acme_init(void);
static void	keymgr_acme_renewal(void *, u_int64_t);
static void	keymgr_acme_check(struct kore_domain *);
static void	keymgr_acme_sign(struct kore_msg *, const void *);
static void	keymgr_acme_ready(struct kore_msg *, const void *);
static void	keymgr_acme_domainkey(struct kore_domain *, struct key *);

static void	keymgr_acme_order_create(const char *);
static void	keymgr_acme_order_redo(void *, u_int64_t);
static void	keymgr_acme_order_start(void *, u_int64_t);

static void	keymgr_x509_ext(STACK_OF(X509_EXTENSION) *,
		    int, const char *, ...)
		    __attribute__((format (printf, 3, 4)));

static void	keymgr_acme_csr(const struct kore_keyreq *, struct key *);
static void	keymgr_acme_install_cert(const void *, size_t, struct key *);
static void	keymgr_acme_order_failed(const void *, size_t, struct key *);
static void	keymgr_acme_challenge_cert(const void *, size_t, struct key *);

static int	keymgr_x509_not_after(X509 *, time_t *);
static int	keymgr_asn1_convert_utctime(const ASN1_TIME *, time_t *);
static int	keymgr_asn1_convert_generalizedtime(const void *,
		    size_t, time_t *);

#endif /* KORE_USE_ACME */

static void	keymgr_reload(void);
static void	keymgr_load_randfile(void);
static void	keymgr_save_randfile(void);

static struct key	*keymgr_load_privatekey(const char *);
static void		keymgr_load_domain_privatekey(struct kore_domain *);

static void	keymgr_msg_recv(struct kore_msg *, const void *);
static void	keymgr_entropy_request(struct kore_msg *, const void *);
static void	keymgr_certificate_request(struct kore_msg *, const void *);
static void	keymgr_submit_certificates(struct kore_domain *, u_int16_t);
static void	keymgr_submit_file(u_int8_t, struct kore_domain *,
		    const char *, u_int16_t, int);
static void	keymgr_x509_msg(const char *, const void *, size_t, int, int);

static void	keymgr_rsa_encrypt(struct kore_msg *, const void *,
		    struct key *);
static void	keymgr_ecdsa_sign(struct kore_msg *, const void *,
		    struct key *);

#if defined(__OpenBSD__)
#if defined(KORE_USE_ACME)
static const char *keymgr_pledges = "stdio rpath wpath cpath";
#else
static const char *keymgr_pledges = "stdio rpath";
#endif
#endif

void
kore_keymgr_run(void)
{
	int		quit;
	u_int64_t	now, netwait, last_seed;

	if (kore_keymgr_active == 0)
		fatalx("%s: called with kore_keymgr_active == 0", __func__);

	quit = 0;

	kore_server_closeall();
	kore_module_cleanup();

	net_init();
	kore_timer_init();
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
#if defined(KORE_USE_PYTHON)
	kore_msg_unregister(KORE_PYTHON_SEND_OBJ);
#endif
	kore_worker_privsep();

	if (kore_rand_file != NULL) {
		keymgr_load_randfile();
		keymgr_save_randfile();
	} else if (!kore_quiet) {
		kore_log(LOG_WARNING, "no rand_file location specified");
	}

	RAND_poll();
	last_seed = 0;

	initialized = 1;
	keymgr_reload();

#if defined(__OpenBSD__)
	if (pledge(keymgr_pledges, NULL) == -1)
		fatalx("failed to pledge keymgr process");
#endif

#if defined(KORE_USE_ACME)
	acme_oid = OBJ_create(ACME_TLS_ALPN_01_OID, "acme", "acmeIdentifier");
	X509V3_EXT_add_alias(acme_oid, NID_subject_key_identifier);
#endif

	kore_worker_started();

	while (quit != 1) {
		now = kore_time_ms();
		if ((now - last_seed) > RAND_POLL_INTERVAL) {
			RAND_poll();
			last_seed = now;
		}

		netwait = kore_timer_next_run(now);
		kore_platform_event_wait(netwait);

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

		if (quit)
			break;

		now = kore_time_ms();
		kore_timer_run(now);
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

#if defined(KORE_USE_ACME)
	keymgr_acme_init();
#endif

	kore_domain_callback(keymgr_load_domain_privatekey);

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
	if (access(dom->certfile, R_OK) == -1) {
#if defined(KORE_USE_ACME)
		if (dom->acme && errno == ENOENT)
			return;
#endif
		fatalx("cannot read '%s' for %s: %s",
		    dom->certfile, dom->domain, errno_s);
	}

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
	u_int8_t			*payload;

	if ((fd = open(file, O_RDONLY)) == -1) {
		if (errno == ENOENT && can_fail)
			return;
		fatalx("open(%s): %s", file, errno_s);
	}

	if (fstat(fd, &st) == -1)
		fatalx("stat(%s): %s", file, errno_s);

	if (!S_ISREG(st.st_mode))
		fatalx("%s is not a file", file);

	payload = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (payload == MAP_FAILED)
		fatalx("mmap(): %s", errno_s);

	keymgr_x509_msg(dom->domain, payload, st.st_size, dst, id);

	(void)munmap(payload, st.st_size);
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

	if (kore_rand_file == NULL)
		return;

	if ((fd = open(kore_rand_file, O_RDONLY)) == -1)
		fatalx("open(%s): %s", kore_rand_file, errno_s);

	if (fstat(fd, &st) == -1)
		fatalx("stat(%s): %s", kore_rand_file, errno_s);
	if (!S_ISREG(st.st_mode))
		fatalx("%s is not a file", kore_rand_file);
	if (st.st_size != RAND_FILE_SIZE)
		fatalx("%s has an invalid size", kore_rand_file);

	total = 0;

	while (total != RAND_FILE_SIZE) {
		ret = read(fd, buf, sizeof(buf));
		if (ret == 0)
			fatalx("EOF on %s", kore_rand_file);

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatalx("read(%s): %s", kore_rand_file, errno_s);
		}

		total += (size_t)ret;
		RAND_seed(buf, (int)ret);
		OPENSSL_cleanse(buf, sizeof(buf));
	}

	(void)close(fd);
	if (unlink(kore_rand_file) == -1) {
		kore_log(LOG_WARNING, "failed to unlink %s: %s",
		    kore_rand_file, errno_s);
	}
}

static void
keymgr_save_randfile(void)
{
	int		fd;
	struct stat	st;
	ssize_t		ret;
	u_int8_t	buf[RAND_FILE_SIZE];

	if (kore_rand_file == NULL)
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

	if (rename(RAND_TMP_FILE, kore_rand_file) == -1) {
		kore_log(LOG_WARNING, "rename(%s, %s): %s",
		    RAND_TMP_FILE, kore_rand_file, errno_s);
		(void)unlink(kore_rand_file);
		(void)unlink(RAND_TMP_FILE);
	}

cleanup:
	OPENSSL_cleanse(buf, sizeof(buf));
}

static void
keymgr_load_domain_privatekey(struct kore_domain *dom)
{
	struct key	*key;

	if (dom->server->tls == 0)
		return;

	key = keymgr_load_privatekey(dom->certkey);

	if (key->pkey == NULL) {
#if defined(KORE_USE_ACME)
		if (dom->acme)
			keymgr_acme_domainkey(dom, key);
#endif
		if (key->pkey == NULL) {
			fatalx("failed to load private key for '%s' (%s)",
			    dom->domain, errno_s);
		}
	}

	key->dom = dom;

	if (!kore_quiet)
		kore_log(LOG_INFO, "loaded private key for '%s'", dom->domain);
}

static struct key *
keymgr_load_privatekey(const char *path)
{
	struct key		*key;

	key = kore_calloc(1, sizeof(*key));
	TAILQ_INSERT_TAIL(&keys, key, list);

	/* Caller should check if pkey was loaded. */
	if (path)
		key->pkey = kore_tls_rsakey_load(path);

	return (key);
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

	if (req->domain[KORE_DOMAINNAME_LEN] != '\0')
		return;

	key = NULL;
	TAILQ_FOREACH(key, &keys, list) {
		if (key->dom == NULL)
			continue;
		if (!strcmp(key->dom->domain, req->domain))
			break;
	}

	if (key == NULL)
		return;

	switch (msg->id) {
	case KORE_MSG_KEYMGR_REQ:
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
		break;
#if defined(KORE_USE_ACME)
	case KORE_ACME_CSR_REQUEST:
		keymgr_acme_csr(req, key);
		break;
	case KORE_ACME_ORDER_FAILED:
		keymgr_acme_order_failed(req->data, req->data_len, key);
		break;
	case KORE_ACME_CHALLENGE_CERT:
		keymgr_acme_challenge_cert(req->data, req->data_len, key);
		break;
	case KORE_ACME_INSTALL_CERT:
		keymgr_acme_install_cert(req->data, req->data_len, key);
		break;
#endif
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
	rsa = EVP_PKEY_get0_RSA(key->pkey);

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
	ec = EVP_PKEY_get0_EC_KEY(key->pkey);

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

static void
keymgr_x509_msg(const char *domain, const void *data, size_t len,
    int target, int msg)
{
	struct kore_buf			buf;
	struct kore_x509_msg		hdr;

	memset(&hdr, 0, sizeof(hdr));

	hdr.data_len = len;

	if (kore_strlcpy(hdr.domain, domain, sizeof(hdr.domain)) >=
	    sizeof(hdr.domain))
		fatalx("%s: domain truncated", __func__);

	kore_buf_init(&buf, sizeof(hdr) + len);
	kore_buf_append(&buf, &hdr, sizeof(hdr));
	kore_buf_append(&buf, data, len);

	kore_msg_send(target, msg, buf.data, buf.offset);
	kore_buf_cleanup(&buf);
}

#if defined(KORE_USE_ACME)
static void
keymgr_acme_init(void)
{
	RSA		*rsa;
	struct key	*key;
	char		*e, *n;
	int		needsreg;
	const BIGNUM	*be, *bn;

	if (acme_provider == NULL)
		return;

	if (mkdir(KORE_ACME_CERTDIR, 0700) == -1) {
		if (errno != EEXIST)
			fatalx("mkdir(%s): %s", KORE_ACME_CERTDIR, errno_s);
	}

	umask(S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);

	needsreg = 0;
	acmeproc_ready = 0;
	key = keymgr_load_privatekey(KORE_ACME_ACCOUNT_KEY);

	if (acme_renewal != NULL)
		kore_timer_remove(acme_renewal);

	acme_renewal = kore_timer_add(keymgr_acme_renewal,
	    ACME_RENEWAL_TIMER, NULL, 0);

	if (key->pkey == NULL) {
		kore_log(LOG_INFO, "generating new ACME account key");
		key->pkey = kore_tls_rsakey_generate(KORE_ACME_ACCOUNT_KEY);
		needsreg = 1;
	} else {
		kore_log(LOG_INFO, "loaded existing ACME account key");
	}

	rsa = EVP_PKEY_get0_RSA(key->pkey);
	RSA_get0_key(rsa, &bn, &be, NULL);

	e = keymgr_bignum_base64(be);
	n = keymgr_bignum_base64(bn);

	kore_msg_send(KORE_WORKER_ACME, KORE_ACME_RSAKEY_E, e, strlen(e));
	kore_msg_send(KORE_WORKER_ACME, KORE_ACME_RSAKEY_N, n, strlen(n));

	kore_free(e);
	kore_free(n);

	if (needsreg) {
		kore_msg_send(KORE_WORKER_ACME,
		    KORE_ACME_ACCOUNT_CREATE, NULL, 0);
	} else {
		kore_msg_send(KORE_WORKER_ACME,
		    KORE_ACME_ACCOUNT_RESOLVE, NULL, 0);
	}

	kore_msg_register(KORE_ACME_SIGN, keymgr_acme_sign);
	kore_msg_register(KORE_ACME_CSR_REQUEST, keymgr_msg_recv);
	kore_msg_register(KORE_ACME_PROC_READY, keymgr_acme_ready);
	kore_msg_register(KORE_ACME_ORDER_FAILED, keymgr_msg_recv);
	kore_msg_register(KORE_ACME_INSTALL_CERT, keymgr_msg_recv);
	kore_msg_register(KORE_ACME_CHALLENGE_CERT, keymgr_msg_recv);
}

static void
keymgr_acme_domainkey(struct kore_domain *dom, struct key *key)
{
	char		*p;

	kore_log(LOG_INFO, "generated new domain key for %s", dom->domain);

	if ((p = strrchr(dom->certkey, '/')) == NULL)
		fatalx("invalid certkey path '%s'", dom->certkey);

	*p = '\0';

	if (mkdir(dom->certkey, 0700) == -1) {
		if (errno != EEXIST)
			fatalx("mkdir(%s): %s", dom->certkey, errno_s);
	}

	*p = '/';
	key->pkey = kore_tls_rsakey_generate(dom->certkey);
}

static void
keymgr_acme_order_create(const char *domain)
{
	struct acme_order	*order;

	order = kore_calloc(1, sizeof(*order));

	order->state = ACME_ORDER_STATE_INIT;
	order->domain = kore_strdup(domain);
	order->timer = kore_timer_add(keymgr_acme_order_start,
	    1000, order, KORE_TIMER_ONESHOT);
}

static void
keymgr_acme_order_redo(void *udata, u_int64_t now)
{
	struct kore_domain	*dom = udata;

	kore_log(LOG_INFO, "[%s] redoing order", dom->domain);
	keymgr_acme_order_create(dom->domain);
}

static void
keymgr_acme_order_start(void *udata, u_int64_t now)
{
	struct acme_order	*order = udata;

	switch (order->state) {
	case ACME_ORDER_STATE_INIT:
		if (acmeproc_ready == 0)
			break;
		order->state = ACME_ORDER_STATE_SUBMIT;
		/* fallthrough */
	case ACME_ORDER_STATE_SUBMIT:
		kore_msg_send(KORE_WORKER_ACME, KORE_ACME_ORDER_CREATE,
		    order->domain, strlen(order->domain));
		kore_free(order->domain);
		kore_free(order);
		order = NULL;
		break;
	default:
		fatalx("%s: unknown order state %d", __func__, order->state);
	}

	if (order != NULL) {
		order->timer = kore_timer_add(keymgr_acme_order_start,
		    5000, order, KORE_TIMER_ONESHOT);
	}
}

static void
keymgr_acme_ready(struct kore_msg *msg, const void *data)
{
	acmeproc_ready = 1;
	kore_log(LOG_INFO, "acme process ready to receive orders");

	keymgr_acme_renewal(NULL, kore_time_ms());
}

static void
keymgr_acme_check(struct kore_domain *dom)
{
	FILE			*fp;
	int			days;
	X509			*x509;
	time_t			expires, now;

	if (dom->acme == 0)
		return;

	if (access(dom->certfile, R_OK) == -1) {
		if (errno == ENOENT) {
			keymgr_acme_order_create(dom->domain);
			return;
		}
		kore_log(LOG_ERR, "access(%s): %s", dom->certfile, errno_s);
		return;
	}

	if ((fp = fopen(dom->certfile, "r")) == NULL) {
		kore_log(LOG_ERR, "fopen(%s): %s", dom->certfile, errno_s);
		return;
	}

	if ((x509 = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
		fclose(fp);
		kore_log(LOG_ERR, "PEM_read_X509: %s", ssl_errno_s);
		return;
	}

	fclose(fp);

	if (!keymgr_x509_not_after(x509, &expires)) {
		X509_free(x509);
		return;
	}

	time(&now);
	days = (expires - now) / 86400;

	kore_log(LOG_INFO, "%s certificate expires in %d days",
	    dom->domain, days);

	if (days <= ACME_RENEWAL_THRESHOLD) {
		kore_log(LOG_INFO, "%s renewing certificate", dom->domain);
		keymgr_acme_order_create(dom->domain);
	}

	X509_free(x509);
}

static void
keymgr_acme_renewal(void *udata, u_int64_t now)
{
	kore_domain_callback(keymgr_acme_check);
}

static void
keymgr_acme_sign(struct kore_msg *msg, const void *data)
{
	u_int32_t		id;
	struct kore_buf		buf;
	const u_int8_t		*ptr;
	u_int8_t		*sig;
	EVP_MD_CTX		*ctx;
	struct key		*key;
	char			*b64;
	unsigned int		siglen;

	TAILQ_FOREACH(key, &keys, list) {
		if (key->dom == NULL)
			break;
	}

	if (key == NULL)
		fatalx("%s: missing key", __func__);

	if (msg->length < sizeof(id))
		fatalx("%s: invalid length (%zu)", __func__, msg->length);

	ptr = data;
	memcpy(&id, ptr, sizeof(id));

	ptr += sizeof(id);
	msg->length -= sizeof(id);

	sig = kore_calloc(1, EVP_PKEY_size(key->pkey));

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		fatalx("EVP_MD_CTX_create: %s", ssl_errno_s);

	if (!EVP_SignInit_ex(ctx, EVP_sha256(), NULL))
		fatalx("EVP_SignInit_ex: %s", ssl_errno_s);

	if (!EVP_SignUpdate(ctx, ptr, msg->length))
		fatalx("EVP_SignUpdate: %s", ssl_errno_s);

	if (!EVP_SignFinal(ctx, sig, &siglen, key->pkey))
		fatalx("EVP_SignFinal: %s", ssl_errno_s);

	if (!kore_base64url_encode(sig, siglen, &b64, KORE_BASE64_RAW))
		fatalx("%s: failed to b64url encode signed data", __func__);

	kore_buf_init(&buf, siglen + sizeof(id));
	kore_buf_append(&buf, &id, sizeof(id));
	kore_buf_append(&buf, b64, strlen(b64));

	kore_msg_send(KORE_WORKER_ACME,
	    KORE_ACME_SIGN_RESULT, buf.data, buf.offset);

	EVP_MD_CTX_destroy(ctx);

	kore_free(sig);
	kore_free(b64);
	kore_buf_cleanup(&buf);
}

static void
keymgr_acme_install_cert(const void *data, size_t len, struct key *key)
{
	int		fd;
	ssize_t		ret;

	fd = open(key->dom->certfile, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd == -1)
		fatalx("open(%s): %s", key->dom->certfile, errno_s);

	kore_log(LOG_INFO, "writing %zu bytes of data", len);

	for (;;) {
		ret = write(fd, data, len);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatalx("write(%s): %s", key->dom->certfile, errno_s);
		}

		break;
	}

	if ((size_t)ret != len) {
		fatalx("incorrect write on %s (%zd/%zu)",
		    key->dom->certfile, ret, len);
	}

	if (close(fd) == -1) {
		kore_log(LOG_NOTICE,
		    "close error on '%s' (%s)", key->dom->certfile, errno_s);
	}

	keymgr_submit_certificates(key->dom, KORE_MSG_WORKER_ALL);

	keymgr_x509_msg(key->dom->domain, NULL, 0,
	    KORE_MSG_WORKER_ALL, KORE_ACME_CHALLENGE_CLEAR_CERT);
}

static void
keymgr_acme_order_failed(const void *data, size_t len, struct key *key)
{
	u_int32_t	retry;

	if (len != sizeof(retry)) {
		kore_log(LOG_ERR, "%s: invalid payload (%zu)", __func__, len);
		return;
	}

	memcpy(&retry, data, len);

	kore_timer_add(keymgr_acme_order_redo, retry, key->dom,
	    KORE_TIMER_ONESHOT);
}

static void
keymgr_acme_challenge_cert(const void *data, size_t len, struct key *key)
{
	STACK_OF(X509_EXTENSION)	*sk;
	size_t				idx;
	time_t				now;
	X509_EXTENSION			*ext;
	X509_NAME			*name;
	X509				*x509;
	const u_int8_t			*digest;
	int				slen, i;
	u_int8_t			*cert, *uptr;
	char				hex[(SHA256_DIGEST_LENGTH * 2) + 1];

	kore_log(LOG_INFO, "[%s] generating tls-alpn-01 challenge cert",
	    key->dom->domain);

	if (len != SHA256_DIGEST_LENGTH)
		fatalx("invalid digest length of %zu bytes", len);

	digest = data;

	for (idx = 0; idx < SHA256_DIGEST_LENGTH; idx++) {
		slen = snprintf(hex + (idx * 2), sizeof(hex) - (idx * 2),
		    "%02x", digest[idx]);
		if (slen == -1 || (size_t)slen >= sizeof(hex))
			fatalx("failed to convert digest to hex");
	}

	if ((x509 = X509_new()) == NULL)
		fatalx("X509_new(): %s", ssl_errno_s);

	if (!X509_set_version(x509, 2))
		fatalx("X509_set_version(): %s", ssl_errno_s);

	time(&now);
	if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), now))
		fatalx("ASN1_INTEGER_set(): %s", ssl_errno_s);

	if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
		fatalx("X509_gmtime_adj(): %s", ssl_errno_s);

	if (!X509_gmtime_adj(X509_get_notAfter(x509), ACME_X509_EXPIRATION))
		fatalx("X509_gmtime_adj(): %s", ssl_errno_s);

	if (!X509_set_pubkey(x509, key->pkey))
		fatalx("X509_set_pubkey(): %s", ssl_errno_s);

	if ((name = X509_get_subject_name(x509)) == NULL)
		fatalx("X509_get_subject_name(): %s", ssl_errno_s);

	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (const unsigned char *)key->dom->domain, -1, -1, 0))
		fatalx("X509_NAME_add_entry_by_txt(): CN %s", ssl_errno_s);

	if (!X509_set_issuer_name(x509, name))
		fatalx("X509_set_issuer_name(): %s", ssl_errno_s);

	sk = sk_X509_EXTENSION_new_null();
	keymgr_x509_ext(sk, acme_oid, "critical,%s", hex);
	keymgr_x509_ext(sk, NID_subject_alt_name, "DNS:%s", key->dom->domain);

	for (i = 0; i < sk_X509_EXTENSION_num(sk); i++) {
		ext = sk_X509_EXTENSION_value(sk, i);
		if (!X509_add_ext(x509, ext, 0))
			fatalx("X509_add_ext(): %s", ssl_errno_s);
	}

	if (!X509_sign(x509, key->pkey, EVP_sha256()))
		fatalx("X509_sign(): %s", ssl_errno_s);

	if ((slen = i2d_X509(x509, NULL)) <= 0)
		fatalx("i2d_X509: %s", ssl_errno_s);

	cert = kore_calloc(1, slen);
	uptr = cert;

	if (i2d_X509(x509, &uptr) <= 0)
		fatalx("i2d_X509: %s", ssl_errno_s);

	keymgr_x509_msg(key->dom->domain, cert, slen,
	    KORE_MSG_WORKER_ALL, KORE_ACME_CHALLENGE_SET_CERT);

	kore_free(cert);
	X509_free(x509);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
}

static void
keymgr_acme_csr(const struct kore_keyreq *req, struct key *key)
{
	int				len;
	STACK_OF(X509_EXTENSION)	*sk;
	X509_REQ			*csr;
	X509_NAME			*name;
	u_int8_t			*data, *uptr;

	kore_log(LOG_INFO, "[%s] creating CSR", req->domain);

	if ((csr = X509_REQ_new()) == NULL)
		fatalx("X509_REQ_new: %s", ssl_errno_s);

	if (!X509_REQ_set_version(csr, 3))
		fatalx("X509_REQ_set_version(): %s", ssl_errno_s);

	if (!X509_REQ_set_pubkey(csr, key->pkey))
		fatalx("X509_REQ_set_pubkey(): %s", ssl_errno_s);

	if ((name = X509_REQ_get_subject_name(csr)) == NULL)
		fatalx("X509_REQ_get_subject_name(): %s", ssl_errno_s);

	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (const unsigned char *)key->dom->domain, -1, -1, 0))
		fatalx("X509_NAME_add_entry_by_txt(): %s", ssl_errno_s);

	sk = sk_X509_EXTENSION_new_null();
	keymgr_x509_ext(sk, NID_subject_alt_name, "DNS:%s", key->dom->domain);

	if (!X509_REQ_add_extensions(csr, sk))
		fatalx("X509_REQ_add_extensions(): %s", ssl_errno_s);

	if (!X509_REQ_sign(csr, key->pkey, EVP_sha256()))
		fatalx("X509_REQ_sign(): %s", ssl_errno_s);

	if ((len = i2d_X509_REQ(csr, NULL)) <= 0)
		fatalx("i2d_X509_REQ: %s", ssl_errno_s);

	data = kore_calloc(1, len);
	uptr = data;

	if (i2d_X509_REQ(csr, &uptr) <= 0)
		fatalx("i2d_X509_REQ: %s", ssl_errno_s);

	keymgr_x509_msg(key->dom->domain, data, len,
	    KORE_WORKER_ACME, KORE_ACME_CSR_RESPONSE);

	kore_free(data);
	X509_REQ_free(csr);

	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
}

static void
keymgr_x509_ext(STACK_OF(X509_EXTENSION) *sk, int extnid, const char *fmt, ...)
{
	int			len;
	va_list			args;
	X509_EXTENSION		*ext;
	char			buf[1024];

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len == -1 || (size_t)len >= sizeof(buf))
		fatalx("failed to create buffer for extension %d", extnid);

	if ((ext = X509V3_EXT_conf_nid(NULL, NULL, extnid, buf)) == NULL) {
		fatalx("X509V3_EXT_conf_nid(%d, %s): %s",
		    extnid, buf, ssl_errno_s);
	}

	sk_X509_EXTENSION_push(sk, ext);
}

static char *
keymgr_bignum_base64(const BIGNUM *bn)
{
	int		len;
	void		*buf;
	char		*encoded;

	len = BN_num_bytes(bn);
	buf = kore_calloc(1, len);

	if (BN_bn2bin(bn, buf) != len)
		fatalx("BN_bn2bin: %s", ssl_errno_s);

	if (!kore_base64url_encode(buf, len, &encoded, KORE_BASE64_RAW))
		fatalx("failed to base64 encode BIGNUM");

	return (encoded);
}

static int
keymgr_x509_not_after(X509 *x509, time_t *out)
{
	const ASN1_TIME		*na;
	int			ret;

	ret = KORE_RESULT_ERROR;

	if ((na = X509_get_notAfter(x509)) == NULL) {
		kore_log(LOG_ERR, "no notAfter date in x509");
		return (KORE_RESULT_ERROR);
	}

	switch (na->type) {
	case V_ASN1_UTCTIME:
		ret = keymgr_asn1_convert_utctime(na, out);
		break;
	case V_ASN1_GENERALIZEDTIME:
		ret = keymgr_asn1_convert_generalizedtime(na->data,
		    na->length, out);
		break;
	default:
		kore_log(LOG_ERR, "invalid notAfter type (%d)", na->type);
		break;
	}

	return (ret);
}

static int
keymgr_asn1_convert_utctime(const ASN1_TIME *na, time_t *out)
{
	int	len, year;
	char	buf[ASN1_GENERALIZEDTIME_LEN + 1];

	if (na->length != ASN1_UTCTIME_LEN) {
		kore_log(LOG_ERR, "invalid UTCTIME: too short (%d)",
		    na->length);
		return (KORE_RESULT_ERROR);
	}

	if (!isdigit(na->data[0]) || !isdigit(na->data[1])) {
		kore_log(LOG_ERR, "invalid UTCTIME: YY are not digits");
		return (KORE_RESULT_ERROR);
	}

	year = (na->data[0] - '0') * 10 + (na->data[1] - '0');

	/* RFC 5280 says years >= 50 are interpreted as 19YY */
	if (year >= 50)
		year = 1900 + year;
	else
		year = 2000 + year;

	/* Convert it to GENERALIZEDTIME format and call that parser. */
	len = snprintf(buf, sizeof(buf), "%04d%.*s", year,
	    na->length - 2, (const char *)na->data+ 2);
	if (len == -1 || (size_t)len >= sizeof(buf)) {
		kore_log(LOG_ERR, "invalid UTCTIME: failed to convert");
		return (KORE_RESULT_ERROR);
	}

	return (keymgr_asn1_convert_generalizedtime(buf, len, out));
}

static int
keymgr_asn1_convert_generalizedtime(const void *ptr, size_t len, time_t *out)
{
	size_t			i;
	struct tm		tm;
	const u_int8_t		*buf;

	if (len != ASN1_GENERALIZEDTIME_LEN) {
		kore_log(LOG_ERR, "invalid GENERALIZEDTIME: too short (%zu)",
		    len);
		return (KORE_RESULT_ERROR);
	}

	buf = ptr;

	for (i = 0; i < len - 1; i++) {
		if (!isdigit(buf[i])) {
			kore_log(LOG_ERR,
			    "invalid GENERALIZEDTIME: invalid bytes");
			return (KORE_RESULT_ERROR);
		}
	}

	/* RFC 5280 states that Zulu time must be used (Z). */
	if (buf[i] != 'Z') {
		kore_log(LOG_ERR, "invalid GENERALIZEDTIME: not Zulu time");
		return (KORE_RESULT_ERROR);
	}

	memset(&tm, 0, sizeof(tm));

	tm.tm_year = (buf[0] - '0') * 1000 + (buf[1] - '0') * 100 +
	    (buf[2] - '0') * 10 + (buf[3] - '0');

	tm.tm_mon = (buf[4] - '0') * 10 + (buf[5] - '0');
	tm.tm_mday = (buf[6] - '0') * 10 + (buf[7] - '0');
	tm.tm_hour = (buf[8] - '0') * 10 + (buf[9] - '0');
	tm.tm_min = (buf[10] - '0') * 10 + (buf[11] - '0');
	tm.tm_sec = (buf[12] - '0') * 10 + (buf[13] - '0');

	tm.tm_mon = tm.tm_mon - 1;
	tm.tm_year = tm.tm_year - 1900;

	*out = mktime(&tm);

	return (KORE_RESULT_OK);
}
#endif
