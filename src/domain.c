/*
 * Copyright (c) 2013-2018 Joris Vink <joris@coders.se>
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
 * XXX - Lots of OPENSSL ifdefs here for 1.0.2 and 1.1.0 release lines.
 * The idea is to only support 1.1.0 down the line and remove the 1.0.2 goo.
 */

#include <sys/param.h>

#if !defined(KORE_NO_TLS)
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <poll.h>
#endif

#include <fnmatch.h>

#include "kore.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#define SSL_SESSION_ID		"kore_ssl_sessionid"

struct kore_domain_h		domains;
struct kore_domain		*primary_dom = NULL;

#if !defined(KORE_NO_TLS)
static u_int8_t			keymgr_buf[2048];
static size_t			keymgr_buflen = 0;
static int			keymgr_response = 0;
DH				*tls_dhparam = NULL;
int				tls_version = KORE_TLS_VERSION_1_2;
#endif

#if !defined(KORE_NO_TLS)
static void load_certificate(struct kore_domain *dom);
static int	domain_x509_verify(int, X509_STORE_CTX *);
static void	domain_load_crl(struct kore_domain *);

static void	keymgr_init(void);
static void	keymgr_await_data(void);
static void	keymgr_msg_response(struct kore_msg *, const void *);

static int	keymgr_rsa_init(RSA *);
static int	keymgr_rsa_finish(RSA *);
static int	keymgr_rsa_privenc(int, const unsigned char *,
		    unsigned char *, RSA *, int);

static ECDSA_SIG	*keymgr_ecdsa_sign(const unsigned char *, int,
			    const BIGNUM *, const BIGNUM *, EC_KEY *);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
static RSA_METHOD	*keymgr_rsa_meth = NULL;
static EC_KEY_METHOD	*keymgr_ec_meth = NULL;
#else
#if !defined(LIBRESSL_VERSION_TEXT)
/*
 * Run own ecdsa_method data structure as OpenSSL has this in ecs_locl.h
 * and does not export this on systems.
 */
struct ecdsa_method {
	const char	*name;
	ECDSA_SIG	*(*ecdsa_do_sign)(const unsigned char *,
			    int, const BIGNUM *, const BIGNUM *, EC_KEY *);
	int		(*ecdsa_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **,
			    BIGNUM **);
	int		(*ecdsa_do_verify)(const unsigned char *, int,
			    const ECDSA_SIG *, EC_KEY *);
	int		flags;
	char		*app_data;
};
#endif

static ECDSA_METHOD	keymgr_ecdsa = {
	"kore ECDSA keymgr method",
	keymgr_ecdsa_sign,
	NULL,
	NULL,
	0,
	NULL
};

static RSA_METHOD	keymgr_rsa = {
	"kore RSA keymgr method",
	NULL,
	NULL,
	keymgr_rsa_privenc,
	NULL,
	NULL,
	NULL,
	keymgr_rsa_init,
	keymgr_rsa_finish,
	RSA_METHOD_FLAG_NO_CHECK,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif /* OPENSSL_VERSION_NUMBER */
#endif /* KORE_NO_TLS */

void
kore_domain_init(void)
{
	TAILQ_INIT(&domains);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (keymgr_rsa_meth == NULL) {
		if ((keymgr_rsa_meth = RSA_meth_new("kore RSA keymgr method",
		    RSA_METHOD_FLAG_NO_CHECK)) == NULL)
			fatal("failed to allocate RSA method");
	}

	RSA_meth_set_init(keymgr_rsa_meth, keymgr_rsa_init);
	RSA_meth_set_finish(keymgr_rsa_meth, keymgr_rsa_finish);
	RSA_meth_set_priv_enc(keymgr_rsa_meth, keymgr_rsa_privenc);

	if (keymgr_ec_meth == NULL) {
		if ((keymgr_ec_meth = EC_KEY_METHOD_new(NULL)) == NULL)
			fatal("failed to allocate EC KEY method");
	}

	EC_KEY_METHOD_set_sign(keymgr_ec_meth, NULL, NULL, keymgr_ecdsa_sign);
#endif
}

void
kore_domain_cleanup(void)
{
	struct kore_domain *dom;

	while ((dom = TAILQ_FIRST(&domains)) != NULL) {
		kore_free(dom->certfile);
		kore_free(dom->certkey);
		TAILQ_REMOVE(&domains, dom, list);
		kore_domain_free(dom);
	}

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (keymgr_rsa_meth != NULL) {
		RSA_meth_free(keymgr_rsa_meth);
		keymgr_rsa_meth = NULL;
	}

	if (keymgr_ec_meth != NULL) {
		EC_KEY_METHOD_free(keymgr_ec_meth);
		keymgr_ec_meth = NULL;
	}
#endif
}

int
kore_domain_new(char *domain)
{
	struct kore_domain	*dom;

	if (kore_domain_lookup(domain) != NULL)
		return (KORE_RESULT_ERROR);

	kore_debug("kore_domain_new(%s)", domain);

	dom = kore_malloc(sizeof(*dom));
	dom->accesslog = -1;
#if !defined(KORE_NO_TLS)
	dom->cafile = NULL;
	dom->certkey = NULL;
	dom->ssl_ctx = NULL;
	dom->certfile = NULL;
	dom->crlfile = NULL;
	dom->x509_verify_depth = 1;
#endif
	dom->domain = kore_strdup(domain);
	TAILQ_INIT(&(dom->handlers));
	TAILQ_INSERT_TAIL(&domains, dom, list);

	if (primary_dom == NULL)
		primary_dom = dom;

	return (KORE_RESULT_OK);
}

void
kore_domain_free(struct kore_domain *dom)
{
#if !defined(KORE_NO_HTTP)
	struct kore_module_handle *hdlr;
#endif
	if (dom == NULL)
		return;

	if (primary_dom == dom)
		primary_dom = NULL;

	TAILQ_REMOVE(&domains, dom, list);

	if (dom->domain != NULL)
		kore_free(dom->domain);

#if !defined(KORE_NO_TLS)
	if (dom->ssl_ctx != NULL)
		SSL_CTX_free(dom->ssl_ctx);
	if (dom->cafile != NULL)
		kore_free(dom->cafile);
	if (dom->certkey != NULL)
		kore_free(dom->certkey);
	if (dom->certfile != NULL)
		kore_free(dom->certfile);
	if (dom->crlfile != NULL)
		kore_free(dom->crlfile);
#endif

#if !defined(KORE_NO_HTTP)
	/* Drop all handlers associated with this domain */
	while ((hdlr = TAILQ_FIRST(&(dom->handlers))) != NULL) {
		TAILQ_REMOVE(&(dom->handlers), hdlr, list);
		kore_module_handler_free(hdlr);
	}
#endif
	kore_free(dom);
}

static void
load_certificate(struct kore_domain *dom)
{
#if !defined(KORE_NO_TLS)
	BIO			*in;
	RSA			*rsa;
	X509			*x509;
	EVP_PKEY		*pkey;
	STACK_OF(X509_NAME)	*certs;
	EC_KEY			*eckey;
	X509_STORE		*store;
#if !defined(OPENSSL_NO_EC)
	EC_KEY			*ecdh;
#endif

	if (!SSL_CTX_use_certificate_chain_file(dom->ssl_ctx, dom->certfile)) {
		fatal("SSL_CTX_use_certificate_chain_file(%s): %s",
		    dom->certfile, ssl_errno_s);
	}

	if ((in = BIO_new(BIO_s_file())) == NULL)
		fatal("BIO_new: %s", ssl_errno_s);
	if (BIO_read_filename(in, dom->certfile) <= 0)
		fatal("BIO_read_filename: %s", ssl_errno_s);

	if ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
		fatal("PEM_read_bio_X509: %s", ssl_errno_s);

	BIO_free(in);

	if ((pkey = X509_get_pubkey(x509)) == NULL)
		fatal("certificate has no public key");

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if ((rsa = EVP_PKEY_get1_RSA(pkey)) == NULL)
			fatal("no RSA public key present");
		RSA_set_app_data(rsa, dom);
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
		RSA_set_method(rsa, keymgr_rsa_meth);
#else
		RSA_set_method(rsa, &keymgr_rsa);
#endif
		break;
	case EVP_PKEY_EC:
		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) == NULL)
			fatal("no EC public key present");
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
		EC_KEY_set_ex_data(eckey, 0, dom);
		EC_KEY_set_method(eckey, keymgr_ec_meth);
#else
		ECDSA_set_ex_data(eckey, 0, dom);
		ECDSA_set_method(eckey, &keymgr_ecdsa);
#endif
		break;
	default:
		fatal("unknown public key in certificate");
	}

	if (!SSL_CTX_use_PrivateKey(dom->ssl_ctx, pkey))
		fatal("SSL_CTX_use_PrivateKey(): %s", ssl_errno_s);

	if (!SSL_CTX_check_private_key(dom->ssl_ctx))
		fatal("Public/Private key for %s do not match", dom->domain);

	if (tls_dhparam == NULL)
		fatal("No DH parameters given");

	SSL_CTX_set_tmp_dh(dom->ssl_ctx, tls_dhparam);
	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_DH_USE);

	if ((ecdh = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL)
		fatal("EC_KEY_new_by_curve_name: %s", ssl_errno_s);

	SSL_CTX_set_tmp_ecdh(dom->ssl_ctx, ecdh);
	EC_KEY_free(ecdh);

	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_COMPRESSION);

	if (dom->cafile != NULL) {
		if ((certs = SSL_load_client_CA_file(dom->cafile)) == NULL) {
			fatal("SSL_load_client_CA_file(%s): %s",
			    dom->cafile, ssl_errno_s);
		}

		SSL_CTX_load_verify_locations(dom->ssl_ctx, dom->cafile, NULL);
		SSL_CTX_set_verify_depth(dom->ssl_ctx, dom->x509_verify_depth);
		SSL_CTX_set_client_CA_list(dom->ssl_ctx, certs);
		SSL_CTX_set_verify(dom->ssl_ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, domain_x509_verify);
	}

	SSL_CTX_set_session_id_context(dom->ssl_ctx,
	    (unsigned char *)SSL_SESSION_ID, strlen(SSL_SESSION_ID));
	SSL_CTX_set_mode(dom->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	if (tls_version == KORE_TLS_VERSION_BOTH) {
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_SSLv3);
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_TLSv1_1);
	}

	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_cipher_list(dom->ssl_ctx, kore_tls_cipher_list);

	SSL_CTX_set_info_callback(dom->ssl_ctx, kore_tls_info_callback);
	SSL_CTX_set_tlsext_servername_callback(dom->ssl_ctx, kore_tls_sni_cb);
#endif
}

void
kore_domain_tlsinit(struct kore_domain *dom)
{
#if !defined(KORE_NO_TLS)
	const SSL_METHOD	*method;

	kore_debug("kore_domain_sslstart(%s)", dom->domain);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if ((method = TLS_method()) == NULL)
		fatal("TLS_method(): %s", ssl_errno_s);
#else
	switch (tls_version) {
	case KORE_TLS_VERSION_1_2:
		method = TLSv1_2_server_method();
		break;
	case KORE_TLS_VERSION_1_0:
		method = TLSv1_server_method();
		break;
	case KORE_TLS_VERSION_BOTH:
		method = SSLv23_server_method();
		break;
	default:
		fatal("unknown tls_version: %d", tls_version);
		return;
	}
#endif

	if ((dom->ssl_ctx = SSL_CTX_new(method)) == NULL)
		fatal("SSL_ctx_new(): %s", ssl_errno_s);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (!SSL_CTX_set_min_proto_version(dom->ssl_ctx, TLS1_VERSION))
		fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
	if (!SSL_CTX_set_max_proto_version(dom->ssl_ctx, TLS1_2_VERSION))
		fatal("SSL_CTX_set_max_proto_version: %s", ssl_errno_s);

	switch (tls_version) {
	case KORE_TLS_VERSION_1_2:
		if (!SSL_CTX_set_min_proto_version(dom->ssl_ctx,
		    TLS1_2_VERSION))
			fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
		break;
	case KORE_TLS_VERSION_1_0:
		if (!SSL_CTX_set_max_proto_version(dom->ssl_ctx, TLS1_VERSION))
			fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
		break;
	case KORE_TLS_VERSION_BOTH:
		break;
	default:
		fatal("unknown tls_version: %d", tls_version);
		return;
	}
#endif
	load_certificate(dom);
#endif
}

void
kore_domain_callback(void (*cb)(struct kore_domain *))
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list) {
		cb(dom);
	}
}

struct kore_domain *
kore_domain_lookup(const char *domain)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list) {
		if (!strcmp(dom->domain, domain))
			return (dom);
		if (!fnmatch(dom->domain, domain, FNM_CASEFOLD))
			return (dom);
	}

	return (NULL);
}

void
kore_domain_closelogs(void)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list) {
		if (dom->accesslog != -1) {
			(void)close(dom->accesslog);
		}
	}
}

void
kore_domain_load_crl(void)
{
#if !defined(KORE_NO_TLS)
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list)
		domain_load_crl(dom);
#endif
}

void
kore_domain_keymgr_init(void)
{
#if !defined(KORE_NO_TLS)
	keymgr_init();
	kore_msg_register(KORE_MSG_KEYMGR_RESP, keymgr_msg_response);
#endif
}

#if !defined(KORE_NO_TLS)
static void
domain_load_crl(struct kore_domain *dom)
{
	X509_STORE		*store;

	if (dom->cafile == NULL)
		return;

	if (dom->crlfile == NULL) {
		kore_log(LOG_WARNING, "WARNING: no CRL configured for '%s'",
		    dom->domain);
		return;
	}

	ERR_clear_error();
	if ((store = SSL_CTX_get_cert_store(dom->ssl_ctx)) == NULL) {
		kore_log(LOG_ERR, "SSL_CTX_get_cert_store(): %s", ssl_errno_s);
		return;
	}

	if (!X509_STORE_load_locations(store, dom->crlfile, NULL)) {
		kore_log(LOG_ERR, "X509_STORE_load_locations(): %s",
		    ssl_errno_s);
		return;
	}

	X509_STORE_set_flags(store,
	    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}
#endif

#if !defined(KORE_NO_TLS)
static void
keymgr_init(void)
{
	const RSA_METHOD	*meth;

	if ((meth = RSA_get_default_method()) == NULL)
		fatal("failed to obtain RSA method");

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	RSA_meth_set_pub_enc(keymgr_rsa_meth, RSA_meth_get_pub_enc(meth));
	RSA_meth_set_pub_dec(keymgr_rsa_meth, RSA_meth_get_pub_dec(meth));
	RSA_meth_set_bn_mod_exp(keymgr_rsa_meth, RSA_meth_get_bn_mod_exp(meth));
#else
	keymgr_rsa.rsa_pub_enc = meth->rsa_pub_enc;
	keymgr_rsa.rsa_pub_dec = meth->rsa_pub_dec;
	keymgr_rsa.bn_mod_exp = meth->bn_mod_exp;
#endif
}

static int
keymgr_rsa_init(RSA *rsa)
{
	if (rsa != NULL) {
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
		RSA_set_flags(rsa, RSA_flags(rsa) |
		    RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK);
#else
		rsa->flags |= RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK;
#endif
		return (1);
	}

	return (0);
}

static int
keymgr_rsa_privenc(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	int			ret;
	size_t			len;
	struct kore_keyreq	*req;
	struct kore_domain	*dom;

	len = sizeof(*req) + flen;
	if (len > sizeof(keymgr_buf))
		fatal("keymgr_buf too small");

	if ((dom = RSA_get_app_data(rsa)) == NULL)
		fatal("RSA key has no domain attached");
	if (strlen(dom->domain) >= KORE_DOMAINNAME_LEN - 1)
		fatal("domain name too long");

	memset(keymgr_buf, 0, sizeof(keymgr_buf));

	req = (struct kore_keyreq *)keymgr_buf;
	req->data_len = flen;
	req->padding = padding;
	req->domain_len = strlen(dom->domain);

	memcpy(&req->data[0], from, req->data_len);
	memcpy(req->domain, dom->domain, req->domain_len);

	kore_msg_send(KORE_WORKER_KEYMGR, KORE_MSG_KEYMGR_REQ, keymgr_buf, len);
	keymgr_await_data();

	ret = -1;
	if (keymgr_response) {
		if (keymgr_buflen < INT_MAX &&
		    (int)keymgr_buflen == RSA_size(rsa)) {
			ret = RSA_size(rsa);
			memcpy(to, keymgr_buf, RSA_size(rsa));
		}
	}

	keymgr_buflen = 0;
	keymgr_response = 0;
	kore_platform_event_all(worker->msg[1]->fd, worker->msg[1]);

	return (ret);
}

static int
keymgr_rsa_finish(RSA *rsa)
{
	return (1);
}

static ECDSA_SIG *
keymgr_ecdsa_sign(const unsigned char *dgst, int dgst_len,
    const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
	size_t				len;
	ECDSA_SIG			*sig;
	const u_int8_t			*ptr;
	struct kore_domain		*dom;
	struct kore_keyreq		*req;

	if (in_kinv != NULL || in_r != NULL)
		return (NULL);

	len = sizeof(*req) + dgst_len;
	if (len > sizeof(keymgr_buf))
		fatal("keymgr_buf too small");

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if ((dom = EC_KEY_get_ex_data(eckey, 0)) == NULL)
		fatal("EC_KEY has no domain");
#else
	if ((dom = ECDSA_get_ex_data(eckey, 0)) == NULL)
		fatal("EC_KEY has no domain");
#endif

	memset(keymgr_buf, 0, sizeof(keymgr_buf));

	req = (struct kore_keyreq *)keymgr_buf;
	req->data_len = dgst_len;
	req->domain_len = strlen(dom->domain);

	memcpy(&req->data[0], dgst, req->data_len);
	memcpy(req->domain, dom->domain, req->domain_len);

	kore_msg_send(KORE_WORKER_KEYMGR, KORE_MSG_KEYMGR_REQ, keymgr_buf, len);
	keymgr_await_data();

	if (keymgr_response) {
		ptr = keymgr_buf;
		sig = d2i_ECDSA_SIG(NULL, &ptr, keymgr_buflen);
	} else {
		sig = NULL;
	}

	keymgr_buflen = 0;
	keymgr_response = 0;
	kore_platform_event_all(worker->msg[1]->fd, worker->msg[1]);

	return (sig);
}

static void
keymgr_await_data(void)
{
	int			ret;
	struct pollfd		pfd[1];
	u_int64_t		start, cur;
#if !defined(KORE_NO_HTTP)
	int			process_requests;
#endif

	/*
	 * We need to wait until the keymgr responds to us, so keep doing
	 * net_recv_flush() until our callback for KORE_MSG_KEYMGR_RESP
	 * tells us that we have obtained the response.
	 *
	 * This means other internal messages can still be delivered by
	 * this worker process to the appropriate callbacks but we do not
	 * drop out until we've either received an answer from the keymgr
	 * or until the timeout has been reached (1 second currently).
	 *
	 * If we end up waiting for the keymgr process we will call
	 * http_process (if not built with NOHTTP=1) to further existing
	 * requests so those do not block too much.
	 *
	 * This means that all incoming data will stop being processed
	 * while existing requests will get processed until we return
	 * from this call.
	 */
	start = kore_time_ms();
	kore_platform_disable_read(worker->msg[1]->fd);

	keymgr_response = 0;
	memset(keymgr_buf, 0, sizeof(keymgr_buf));

#if !defined(KORE_NO_HTTP)
	process_requests = 0;
#endif

	for (;;) {
#if !defined(KORE_NO_HTTP)
		if (process_requests) {
			http_process();
			process_requests = 0;
		}
#endif
		pfd[0].fd = worker->msg[1]->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;

		ret = poll(pfd, 1, 100);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		cur = kore_time_ms();
		if ((cur - start) > 1000)
			break;

		if (ret == 0) {
#if !defined(KORE_NO_HTTP)
			/* No activity on channel, process HTTP requests. */
			process_requests = 1;
#endif
			continue;
		}

		if (pfd[0].revents & (POLLERR | POLLHUP))
			break;
		if (!(pfd[0].revents & POLLIN))
			break;

		worker->msg[1]->flags |= CONN_READ_POSSIBLE;
		if (!net_recv_flush(worker->msg[1]))
			break;

		if (keymgr_response)
			break;

#if !defined(KORE_NO_HTTP)
		/* If we've spent 100ms already, process HTTP requests. */
		if ((cur - start) > 100) {
			process_requests = 1;
		}
#endif
	}
}

static void
keymgr_msg_response(struct kore_msg *msg, const void *data)
{
	keymgr_response = 1;
	keymgr_buflen = msg->length;

	if (keymgr_buflen > sizeof(keymgr_buf))
		return;

	memcpy(keymgr_buf, data, keymgr_buflen);
}

static int
domain_x509_verify(int ok, X509_STORE_CTX *ctx)
{
	X509		*cert;
	const char	*text;
	int		error, depth;

	error = X509_STORE_CTX_get_error(ctx);
	cert = X509_STORE_CTX_get_current_cert(ctx);

	if (ok == 0 && cert != NULL) {
		text = X509_verify_cert_error_string(error);
		depth = X509_STORE_CTX_get_error_depth(ctx);

		kore_log(LOG_WARNING, "X509 verification error depth:%d - %s",
		    depth, text);

		/* Continue on CRL validity errors. */
		switch (error) {
		case X509_V_ERR_CRL_HAS_EXPIRED:
		case X509_V_ERR_CRL_NOT_YET_VALID:
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			ok = 1;
			break;
		}
	}

	return (ok);
}

void
kore_domain_reload_certificates(void)
{
#if !defined(KORE_NO_TLS)
	kore_domain_callback(load_certificate);
#endif
}
#endif
