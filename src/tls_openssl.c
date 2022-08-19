/*
 * Copyright (c) 2022 Joris Vink <joris@coders.se>
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
 * This TLS backend is the original TLS code used in Kore.
 */

#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <poll.h>

#include "kore.h"
#include "http.h"

#define TLS_SESSION_ID		"kore_tls_sessionid"

static int	tls_domain_x509_verify(int, X509_STORE_CTX *);
static X509	*tls_domain_load_certificate_chain(SSL_CTX *,
		    const void *, size_t);

static int	tls_sni_cb(SSL *, int *, void *);
static void	tls_info_callback(const SSL *, int, int);

#if defined(KORE_USE_ACME)
static void	tls_acme_challenge_set_cert(SSL *, struct kore_domain *);
static int	tls_acme_alpn(SSL *, const unsigned char **, unsigned char *,
		    const unsigned char *, unsigned int, void *);
#endif

static void	tls_keymgr_await_data(void);
static void	tls_keymgr_msg_response(struct kore_msg *, const void *);

static int	tls_keymgr_rsa_init(RSA *);
static int	tls_keymgr_rsa_finish(RSA *);
static int	tls_keymgr_rsa_privenc(int, const unsigned char *,
		    unsigned char *, RSA *, int);

static ECDSA_SIG *tls_keymgr_ecdsa_sign(const unsigned char *, int,
		    const BIGNUM *, const BIGNUM *, EC_KEY *);

static RSA_METHOD	*keymgr_rsa_meth = NULL;
static EC_KEY_METHOD	*keymgr_ec_meth = NULL;

static DH		*dh_params = NULL;
static int		tls_version = KORE_TLS_VERSION_BOTH;
static char		*tls_cipher_list = KORE_DEFAULT_CIPHER_LIST;

static u_int8_t		keymgr_buf[2048];
static size_t		keymgr_buflen = 0;
static int		keymgr_response = 0;

#if defined(KORE_USE_ACME)
static u_int8_t acme_alpn_name[] =
    { 0xa, 'a', 'c', 'm', 'e', '-', 't', 'l', 's', '/', '1' };
#endif

struct kore_privsep	keymgr_privsep;
int			kore_keymgr_active = 0;

int
kore_tls_supported(void)
{
	return (KORE_RESULT_OK);
}

void
kore_tls_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	if ((keymgr_rsa_meth = RSA_meth_new("kore RSA keymgr method",
	    RSA_METHOD_FLAG_NO_CHECK)) == NULL)
		fatal("failed to setup RSA method");

	RSA_meth_set_init(keymgr_rsa_meth, tls_keymgr_rsa_init);
	RSA_meth_set_finish(keymgr_rsa_meth, tls_keymgr_rsa_finish);
	RSA_meth_set_priv_enc(keymgr_rsa_meth, tls_keymgr_rsa_privenc);

	if ((keymgr_ec_meth = EC_KEY_METHOD_new(NULL)) == NULL)
		fatal("failed to allocate EC KEY method");

	EC_KEY_METHOD_set_sign(keymgr_ec_meth,
	    NULL, NULL, tls_keymgr_ecdsa_sign);

	kore_log(LOG_NOTICE, "TLS backend %s", OPENSSL_VERSION_TEXT);
#if !defined(TLS1_3_VERSION)
	if (!kore_quiet) {
		kore_log(LOG_NOTICE,
		    "%s has no TLS 1.3 - will only use TLS 1.2",
		    OPENSSL_VERSION_TEXT);
	}
#endif
}

void
kore_tls_cleanup(void)
{
	RSA_meth_free(keymgr_rsa_meth);
	EC_KEY_METHOD_free(keymgr_ec_meth);
}

void
kore_tls_version_set(int version)
{
	tls_version = version;
}

void
kore_tls_dh_check(void)
{
	if (dh_params != NULL)
		return;

	if (!kore_tls_dh_load(KORE_DHPARAM_PATH))
		fatal("failed to load default DH parameters");
}

int
kore_tls_dh_load(const char *path)
{
	BIO	*bio;

	if (dh_params != NULL) {
		kore_log(LOG_ERR, "tls_dhparam already specified");
		return (KORE_RESULT_ERROR);
	}

	if ((bio = BIO_new_file(path, "r")) == NULL) {
		kore_log(LOG_ERR, "tls_dhparam file '%s' not accessible", path);
		return (KORE_RESULT_ERROR);
	}

	dh_params = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (dh_params == NULL) {
		kore_log(LOG_ERR, "PEM_read_bio_DHparams(): %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

int
kore_tls_ciphersuite_set(const char *list)
{
	if (strcmp(tls_cipher_list, KORE_DEFAULT_CIPHER_LIST)) {
		kore_log(LOG_ERR, "tls_cipher specified twice");
		return (KORE_RESULT_ERROR);
	}

	tls_cipher_list = kore_strdup(list);

	return (KORE_RESULT_OK);
}

void
kore_tls_keymgr_init(void)
{
	const RSA_METHOD	*meth;

	if ((meth = RSA_get_default_method()) == NULL)
		fatal("failed to obtain RSA method");

	RSA_meth_set_pub_enc(keymgr_rsa_meth, RSA_meth_get_pub_enc(meth));
	RSA_meth_set_pub_dec(keymgr_rsa_meth, RSA_meth_get_pub_dec(meth));
	RSA_meth_set_bn_mod_exp(keymgr_rsa_meth, RSA_meth_get_bn_mod_exp(meth));

	kore_msg_register(KORE_MSG_KEYMGR_RESP, tls_keymgr_msg_response);
}

void
kore_tls_domain_setup(struct kore_domain *dom, int type,
    const void *data, size_t datalen)
{
	const u_int8_t		*ptr;
	RSA			*rsa;
	X509			*x509;
	EVP_PKEY		*pkey;
	STACK_OF(X509_NAME)	*certs;
	EC_KEY			*eckey;
	const SSL_METHOD	*method;

	if (dom->tls_ctx != NULL)
		SSL_CTX_free(dom->tls_ctx);

	if ((method = TLS_method()) == NULL)
		fatalx("TLS_method(): %s", ssl_errno_s);

	if ((dom->tls_ctx = SSL_CTX_new(method)) == NULL)
		fatalx("SSL_ctx_new(): %s", ssl_errno_s);

	if (!SSL_CTX_set_min_proto_version(dom->tls_ctx, TLS1_2_VERSION))
		fatalx("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);

#if defined(TLS1_3_VERSION)
	if (!SSL_CTX_set_max_proto_version(dom->tls_ctx, TLS1_3_VERSION))
		fatalx("SSL_CTX_set_max_proto_version: %s", ssl_errno_s);
#else
	if (!SSL_CTX_set_max_proto_version(dom->tls_ctx, TLS1_2_VERSION))
		fatalx("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
#endif

	switch (tls_version) {
	case KORE_TLS_VERSION_1_3:
#if defined(TLS1_3_VERSION)
		if (!SSL_CTX_set_min_proto_version(dom->tls_ctx,
		    TLS1_3_VERSION)) {
			fatalx("SSL_CTX_set_min_proto_version: %s",
			    ssl_errno_s);
		}
		break;
#endif
	case KORE_TLS_VERSION_1_2:
		if (!SSL_CTX_set_max_proto_version(dom->tls_ctx,
		    TLS1_2_VERSION)) {
			fatalx("SSL_CTX_set_min_proto_version: %s",
			    ssl_errno_s);
		}
		break;
	case KORE_TLS_VERSION_BOTH:
		break;
	default:
		fatalx("unknown tls_version: %d", tls_version);
		return;
	}

	switch (type) {
	case KORE_PEM_CERT_CHAIN:
		x509 = tls_domain_load_certificate_chain(dom->tls_ctx,
		    data, datalen);
		break;
	case KORE_DER_CERT_DATA:
		ptr = data;
		if ((x509 = d2i_X509(NULL, &ptr, datalen)) == NULL)
			fatalx("d2i_X509: %s", ssl_errno_s);
		if (SSL_CTX_use_certificate(dom->tls_ctx, x509) == 0)
			fatalx("SSL_CTX_use_certificate: %s", ssl_errno_s);
		break;
	default:
		fatalx("%s: unknown type %d", __func__, type);
	}

	if (x509 == NULL) {
		kore_log(LOG_NOTICE, "failed to load certificate for '%s': %s",
		    dom->domain, ssl_errno_s);
		SSL_CTX_free(dom->tls_ctx);
		dom->tls_ctx = NULL;
		return;
	}

	if ((pkey = X509_get_pubkey(x509)) == NULL)
		fatalx("certificate has no public key");

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if ((rsa = EVP_PKEY_get1_RSA(pkey)) == NULL)
			fatalx("no RSA public key present");
		RSA_set_app_data(rsa, dom);
		RSA_set_method(rsa, keymgr_rsa_meth);
		break;
	case EVP_PKEY_EC:
		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) == NULL)
			fatalx("no EC public key present");
		EC_KEY_set_ex_data(eckey, 0, dom);
		EC_KEY_set_method(eckey, keymgr_ec_meth);
		break;
	default:
		fatalx("unknown public key in certificate");
	}

	if (!SSL_CTX_use_PrivateKey(dom->tls_ctx, pkey))
		fatalx("SSL_CTX_use_PrivateKey(): %s", ssl_errno_s);

	if (!SSL_CTX_check_private_key(dom->tls_ctx)) {
		fatalx("Public/Private key for %s do not match (%s)",
		    dom->domain, ssl_errno_s);
	}

	if (dh_params == NULL)
		fatal("no DH parameters specified");

	SSL_CTX_set_tmp_dh(dom->tls_ctx, dh_params);
	SSL_CTX_set_options(dom->tls_ctx, SSL_OP_SINGLE_DH_USE);

	if (!SSL_CTX_set_ecdh_auto(dom->tls_ctx, 1))
		fatalx("SSL_CTX_set_ecdh_auto: %s", ssl_errno_s);

	SSL_CTX_set_options(dom->tls_ctx, SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_options(dom->tls_ctx, SSL_OP_NO_COMPRESSION);

	if (dom->cafile != NULL) {
		if ((certs = SSL_load_client_CA_file(dom->cafile)) == NULL) {
			fatalx("SSL_load_client_CA_file(%s): %s",
			    dom->cafile, ssl_errno_s);
		}

		SSL_CTX_load_verify_locations(dom->tls_ctx, dom->cafile, NULL);
		SSL_CTX_set_verify_depth(dom->tls_ctx, dom->x509_verify_depth);
		SSL_CTX_set_client_CA_list(dom->tls_ctx, certs);
		SSL_CTX_set_verify(dom->tls_ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_domain_x509_verify);
	}

	SSL_CTX_set_session_id_context(dom->tls_ctx,
	    (unsigned char *)TLS_SESSION_ID, strlen(TLS_SESSION_ID));
	SSL_CTX_set_mode(dom->tls_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	if (tls_version == KORE_TLS_VERSION_BOTH) {
		SSL_CTX_set_options(dom->tls_ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_options(dom->tls_ctx, SSL_OP_NO_SSLv3);
		SSL_CTX_set_options(dom->tls_ctx, SSL_OP_NO_TLSv1);
		SSL_CTX_set_options(dom->tls_ctx, SSL_OP_NO_TLSv1_1);
	}

	SSL_CTX_set_options(dom->tls_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_cipher_list(dom->tls_ctx, tls_cipher_list);

	SSL_CTX_set_info_callback(dom->tls_ctx, tls_info_callback);
	SSL_CTX_set_tlsext_servername_callback(dom->tls_ctx, tls_sni_cb);

#if defined(KORE_USE_ACME)
	SSL_CTX_set_alpn_select_cb(dom->tls_ctx, tls_acme_alpn, dom);
#endif

	X509_free(x509);
}

void
kore_tls_domain_crl(struct kore_domain *dom, const void *pem, size_t pemlen)
{
	int			err;
	BIO			*in;
	X509_CRL		*crl;
	X509_STORE		*store;

	ERR_clear_error();
	in = BIO_new_mem_buf(pem, pemlen);

	if ((store = SSL_CTX_get_cert_store(dom->tls_ctx)) == NULL) {
		BIO_free(in);
		kore_log(LOG_ERR, "SSL_CTX_get_cert_store(): %s", ssl_errno_s);
		return;
	}

	for (;;) {
		crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
		if (crl == NULL) {
			err = ERR_GET_REASON(ERR_peek_last_error());
			if (err == PEM_R_NO_START_LINE) {
				ERR_clear_error();
				break;
			}

			kore_log(LOG_WARNING, "failed to read CRL %s: %s",
			    dom->crlfile, ssl_errno_s);
			continue;
		}

		if (!X509_STORE_add_crl(store, crl)) {
			err = ERR_GET_REASON(ERR_peek_last_error());
			if (err == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				X509_CRL_free(crl);
				continue;
			}

			kore_log(LOG_WARNING, "failed to add CRL %s: %s",
			    dom->crlfile, ssl_errno_s);
			X509_CRL_free(crl);
			continue;
		}
	}

	BIO_free(in);

	X509_STORE_set_flags(store,
	    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}

void
kore_tls_domain_cleanup(struct kore_domain *dom)
{
	if (dom->tls_ctx != NULL)
		SSL_CTX_free(dom->tls_ctx);
}

int
kore_tls_connection_accept(struct connection *c)
{
	int		r;

	if (primary_dom == NULL) {
		kore_log(LOG_NOTICE,
		    "TLS handshake but no TLS configured on server");
		return (KORE_RESULT_ERROR);
	}

	if (primary_dom->tls_ctx == NULL) {
		kore_log(LOG_NOTICE,
		    "TLS configuration for %s not yet complete",
		    primary_dom->domain);
		return (KORE_RESULT_ERROR);
	}

	if (c->tls == NULL) {
		c->tls = SSL_new(primary_dom->tls_ctx);
		if (c->tls == NULL)
			return (KORE_RESULT_ERROR);

		SSL_set_fd(c->tls, c->fd);
		SSL_set_accept_state(c->tls);

		if (!SSL_set_ex_data(c->tls, 0, c))
			return (KORE_RESULT_ERROR);

		if (primary_dom->cafile != NULL)
			c->flags |= CONN_LOG_TLS_FAILURE;
	}

	ERR_clear_error();
	r = SSL_accept(c->tls);
	if (r <= 0) {
		r = SSL_get_error(c->tls, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			kore_connection_start_idletimer(c);
			return (KORE_RESULT_RETRY);
		default:
			if (c->flags & CONN_LOG_TLS_FAILURE) {
				kore_log(LOG_NOTICE,
				    "SSL_accept: %s", ssl_errno_s);
			}
			return (KORE_RESULT_ERROR);
		}
	}

#if defined(KORE_USE_ACME)
	if (c->proto == CONN_PROTO_ACME_ALPN) {
		kore_log(LOG_INFO, "disconnecting acme client");
		kore_connection_disconnect(c);
		return (KORE_RESULT_ERROR);
	}
#endif

	if (SSL_get_verify_mode(c->tls) & SSL_VERIFY_PEER) {
		c->tls_cert = SSL_get_peer_certificate(c->tls);
		if (c->tls_cert == NULL) {
			kore_log(LOG_NOTICE, "no peer certificate");
			return (KORE_RESULT_ERROR);
		}
	} else {
		c->tls_cert = NULL;
	}

	return (KORE_RESULT_OK);
}

int
kore_tls_read(struct connection *c, size_t *bytes)
{
	int		r;

	ERR_clear_error();
	r = SSL_read(c->tls, (c->rnb->buf + c->rnb->s_off),
	    (c->rnb->b_len - c->rnb->s_off));

	if (c->tls_reneg > 1)
		return (KORE_RESULT_ERROR);

	if (r <= 0) {
		r = SSL_get_error(c->tls, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			c->evt.flags &= ~KORE_EVENT_READ;
			return (KORE_RESULT_OK);
		case SSL_ERROR_ZERO_RETURN:
			return (KORE_RESULT_ERROR);
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case EINTR:
				*bytes = 0;
				return (KORE_RESULT_OK);
			case EAGAIN:
				c->evt.flags &= ~KORE_EVENT_READ;
				c->snb->flags |= NETBUF_MUST_RESEND;
				return (KORE_RESULT_OK);
			default:
				break;
			}
			/* FALLTHROUGH */
		default:
			if (c->flags & CONN_LOG_TLS_FAILURE) {
				kore_log(LOG_NOTICE,
				    "SSL_read(): %s", ssl_errno_s);
			}
			return (KORE_RESULT_ERROR);
		}
	}

	*bytes = (size_t)r;

	return (KORE_RESULT_OK);
}

int
kore_tls_write(struct connection *c, size_t len, size_t *written)
{
	int		r;

	if (len > INT_MAX)
		return (KORE_RESULT_ERROR);

	ERR_clear_error();
	r = SSL_write(c->tls, (c->snb->buf + c->snb->s_off), len);
	if (c->tls_reneg > 1)
		return (KORE_RESULT_ERROR);

	if (r <= 0) {
		r = SSL_get_error(c->tls, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			c->evt.flags &= ~KORE_EVENT_WRITE;
			c->snb->flags |= NETBUF_MUST_RESEND;
			return (KORE_RESULT_OK);
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case EINTR:
				*written = 0;
				return (KORE_RESULT_OK);
			case EAGAIN:
				c->evt.flags &= ~KORE_EVENT_WRITE;
				c->snb->flags |= NETBUF_MUST_RESEND;
				return (KORE_RESULT_OK);
			default:
				break;
			}
			/* FALLTHROUGH */
		default:
			if (c->flags & CONN_LOG_TLS_FAILURE) {
				kore_log(LOG_NOTICE,
				    "SSL_write(): %s", ssl_errno_s);
			}
			return (KORE_RESULT_ERROR);
		}
	}

	*written = (size_t)r;

	return (KORE_RESULT_OK);
}

void
kore_tls_connection_cleanup(struct connection *c)
{
	if (c->tls != NULL) {
		SSL_shutdown(c->tls);
		SSL_free(c->tls);
	}

	if (c->tls_cert != NULL)
		X509_free(c->tls_cert);

	if (c->tls_sni != NULL)
		kore_free(c->tls_sni);
}


KORE_PRIVATE_KEY *
kore_tls_rsakey_load(const char *path)
{
	FILE			*fp;
	KORE_PRIVATE_KEY	*pkey;

	if (access(path, R_OK) == -1)
		return (NULL);

	if ((fp = fopen(path, "r")) == NULL)
		fatalx("%s(%s): %s", __func__, path, errno_s);

	if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL)
		fatalx("PEM_read_PrivateKey: %s", ssl_errno_s);

	fclose(fp);

	return (pkey);
}

KORE_PRIVATE_KEY *
kore_tls_rsakey_generate(const char *path)
{
	FILE			*fp;
	EVP_PKEY_CTX		*ctx;
	KORE_PRIVATE_KEY	*pkey;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
		fatalx("EVP_PKEY_CTX_new_id: %s", ssl_errno_s);

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		fatalx("EVP_PKEY_keygen_init: %s", ssl_errno_s);

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KORE_RSAKEY_BITS) <= 0)
		fatalx("EVP_PKEY_CTX_set_rsa_keygen_bits: %s", ssl_errno_s);

	pkey = NULL;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		fatalx("EVP_PKEY_keygen: %s", ssl_errno_s);

	if (path != NULL) {
		if ((fp = fopen(path, "w")) == NULL)
			fatalx("fopen(%s): %s", path, errno_s);

		if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
			fatalx("PEM_write_PrivateKey: %s", ssl_errno_s);

		fclose(fp);
	}

	return (pkey);
}

KORE_X509_NAMES *
kore_tls_x509_subject_name(struct connection *c)
{
	X509_NAME	*name;

	if ((name = X509_get_subject_name(c->tls_cert)) == NULL)
		kore_log(LOG_NOTICE, "X509_get_subject_name: %s", ssl_errno_s);

	return (name);
}

KORE_X509_NAMES *
kore_tls_x509_issuer_name(struct connection *c)
{
	X509_NAME	*name;

	if ((name = X509_get_issuer_name(c->tls_cert)) == NULL)
		kore_log(LOG_NOTICE, "X509_get_issuer_name: %s", ssl_errno_s);

	return (name);
}

int
kore_tls_x509name_foreach(KORE_X509_NAMES *name, int flags, void *udata,
    int (*cb)(void *, int, int, const char *, const void *, size_t, int))
{
	u_int8_t		*data;
	ASN1_STRING		*astr;
	X509_NAME_ENTRY		*entry;
	const char		*field;
	int			islast, ret, idx, namelen, nid, len;

	data = NULL;
	ret = KORE_RESULT_ERROR;

	if ((namelen = X509_NAME_entry_count(name)) == 0)
		goto cleanup;

	for (idx = 0; idx < namelen; idx++) {
		if ((entry = X509_NAME_get_entry(name, idx)) == NULL)
			goto cleanup;

		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
		if ((field = OBJ_nid2sn(nid)) == NULL)
			goto cleanup;

		switch (nid) {
		case NID_commonName:
			nid = KORE_X509_NAME_COMMON_NAME;
			break;
		default:
			nid = -1;
			break;
		}

		if ((astr = X509_NAME_ENTRY_get_data(entry)) == NULL)
			goto cleanup;

		data = NULL;
		if ((len = ASN1_STRING_to_UTF8(&data, astr)) < 0)
			goto cleanup;

		if (idx != (namelen - 1))
			islast = 0;
		else
			islast = 1;

		if (!cb(udata, islast, nid, field, data, len, flags))
			goto cleanup;

		OPENSSL_free(data);
		data = NULL;
	}

	ret = KORE_RESULT_OK;

cleanup:
	if (data != NULL)
		OPENSSL_free(data);

	return (ret);
}

int
kore_tls_x509_data(struct connection *c, u_int8_t **ptr, size_t *olen)
{
	int		len;
	u_int8_t	*der, *pp;

	if ((len = i2d_X509(c->tls_cert, NULL)) <= 0) {
		kore_log(LOG_NOTICE, "i2d_X509: %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	der = kore_calloc(1, len);
	pp = der;

	if (i2d_X509(c->tls_cert, &pp) <= 0) {
		kore_free(der);
		kore_log(LOG_NOTICE, "i2d_X509: %s", ssl_errno_s);
		return (KORE_RESULT_ERROR);
	}

	*ptr = der;
	*olen = len;

	return (KORE_RESULT_OK);
}

void
kore_tls_seed(const void *data, size_t len)
{
	RAND_poll();
	RAND_seed(data, len);
}

static void
tls_info_callback(const SSL *ssl, int flags, int ret)
{
	struct connection	*c;

	if (flags & SSL_CB_HANDSHAKE_START) {
		if ((c = SSL_get_app_data(ssl)) == NULL)
			fatal("no SSL_get_app_data");

#if defined(TLS1_3_VERSION)
		if (SSL_version(ssl) != TLS1_3_VERSION)
#endif
			c->tls_reneg++;
	}
}

static int
tls_sni_cb(SSL *ssl, int *ad, void *arg)
{
	struct connection	*c;
	struct kore_domain	*dom;
	const char		*sname;

	if ((c = SSL_get_ex_data(ssl, 0)) == NULL)
		fatal("no connection data in %s", __func__);

	sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	if (sname != NULL)
		c->tls_sni = kore_strdup(sname);

	if (sname != NULL &&
	    (dom = kore_domain_lookup(c->owner->server, sname)) != NULL) {
		if (dom->tls_ctx == NULL) {
			kore_log(LOG_NOTICE,
			    "TLS configuration for %s not complete",
			    dom->domain);
			return (SSL_TLSEXT_ERR_NOACK);
		}

		SSL_set_SSL_CTX(ssl, dom->tls_ctx);

		if (dom->cafile != NULL) {
			SSL_set_verify(ssl, SSL_VERIFY_PEER |
			    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
			c->flags |= CONN_LOG_TLS_FAILURE;
		} else {
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
		}

#if defined(KORE_USE_ACME)
		/*
		 * If ALPN callback was called before SNI was parsed we
		 * must make sure we swap to the correct certificate now.
		 */
		if (c->flags & CONN_TLS_ALPN_ACME_SEEN)
			tls_acme_challenge_set_cert(ssl, dom);

		c->flags |= CONN_TLS_SNI_SEEN;
#endif
		return (SSL_TLSEXT_ERR_OK);
	}

	return (SSL_TLSEXT_ERR_NOACK);
}

static int
tls_keymgr_rsa_init(RSA *rsa)
{
	if (rsa != NULL) {
		RSA_set_flags(rsa, RSA_flags(rsa) |
		    RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK);
		return (1);
	}

	return (0);
}

static int
tls_keymgr_rsa_privenc(int flen, const unsigned char *from, unsigned char *to,
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

	memset(keymgr_buf, 0, sizeof(keymgr_buf));

	req = (struct kore_keyreq *)keymgr_buf;

	if (kore_strlcpy(req->domain, dom->domain, sizeof(req->domain)) >=
	    sizeof(req->domain))
		fatal("%s: domain truncated", __func__);

	req->data_len = flen;
	req->padding = padding;
	memcpy(&req->data[0], from, req->data_len);

	kore_msg_send(KORE_WORKER_KEYMGR, KORE_MSG_KEYMGR_REQ, keymgr_buf, len);
	tls_keymgr_await_data();

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
tls_keymgr_rsa_finish(RSA *rsa)
{
	return (1);
}

static ECDSA_SIG *
tls_keymgr_ecdsa_sign(const unsigned char *dgst, int dgst_len,
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

	if ((dom = EC_KEY_get_ex_data(eckey, 0)) == NULL)
		fatal("EC_KEY has no domain");

	memset(keymgr_buf, 0, sizeof(keymgr_buf));
	req = (struct kore_keyreq *)keymgr_buf;

	if (kore_strlcpy(req->domain, dom->domain, sizeof(req->domain)) >=
	    sizeof(req->domain))
		fatal("%s: domain truncated", __func__);

	req->data_len = dgst_len;
	memcpy(&req->data[0], dgst, req->data_len);

	kore_msg_send(KORE_WORKER_KEYMGR, KORE_MSG_KEYMGR_REQ, keymgr_buf, len);
	tls_keymgr_await_data();

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
tls_keymgr_await_data(void)
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

		worker->msg[1]->evt.flags |= KORE_EVENT_READ;
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
tls_keymgr_msg_response(struct kore_msg *msg, const void *data)
{
	keymgr_response = 1;
	keymgr_buflen = msg->length;

	if (keymgr_buflen > sizeof(keymgr_buf))
		return;

	memcpy(keymgr_buf, data, keymgr_buflen);
}

static int
tls_domain_x509_verify(int ok, X509_STORE_CTX *ctx)
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

/*
 * What follows is basically a reimplementation of
 * SSL_CTX_use_certificate_chain_file() from OpenSSL but with our
 * BIO set to the pem data that we received.
 */
static X509 *
tls_domain_load_certificate_chain(SSL_CTX *ctx, const void *data, size_t len)
{
	unsigned long	err;
	BIO		*in;
	X509		*x, *ca;

	ERR_clear_error();
	in = BIO_new_mem_buf(data, len);

	if ((x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL)) == NULL)
		return (NULL);

	/* refcount for x509 will go up one. */
	if (SSL_CTX_use_certificate(ctx, x) == 0)
		return (NULL);

	SSL_CTX_clear_chain_certs(ctx);

	ERR_clear_error();
	while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
		/* ca its reference count won't be increased. */
		if (SSL_CTX_add0_chain_cert(ctx, ca) == 0)
			return (NULL);
	}

	err = ERR_peek_last_error();

	if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
	    ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
		return (NULL);

	BIO_free(in);

	return (x);
}

#if defined(KORE_USE_ACME)
static int
tls_acme_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *udata)
{
	struct connection	*c;

	if ((c = SSL_get_ex_data(ssl, 0)) == NULL)
		fatal("%s: no connection data present", __func__);

	if (inlen != sizeof(acme_alpn_name))
		return (SSL_TLSEXT_ERR_NOACK);

	if (memcmp(acme_alpn_name, in, sizeof(acme_alpn_name)))
		return (SSL_TLSEXT_ERR_NOACK);

	*out = in + 1;
	*outlen = inlen - 1;

	c->flags |= CONN_TLS_ALPN_ACME_SEEN;

	/*
	 * If SNI was already done, we can continue, otherwise we mark
	 * that we saw the right ALPN negotiation on this connection
	 * and wait for the SNI extension to be parsed.
	 */
	if (c->flags & CONN_TLS_SNI_SEEN) {
		/* SNI was seen, we are on the right domain. */
		tls_acme_challenge_set_cert(ssl, udata);
	}

	return (SSL_TLSEXT_ERR_OK);
}

static void
tls_acme_challenge_set_cert(SSL *ssl, struct kore_domain *dom)
{
	struct connection	*c;
	const unsigned char	*ptr;
	X509			*x509;

	if (dom->acme == 0) {
		kore_log(LOG_NOTICE, "[%s] ACME not active", dom->domain);
		return;
	}

	if (dom->acme_challenge == 0) {
		kore_log(LOG_NOTICE,
		    "[%s] ACME auth challenge not active", dom->domain);
		return;
	}

	kore_log(LOG_INFO, "[%s] acme-tls/1 challenge requested",
	    dom->domain);

	if ((c = SSL_get_ex_data(ssl, 0)) == NULL)
		fatal("%s: no connection data present", __func__);

	ptr = dom->acme_cert;
	if ((x509 = d2i_X509(NULL, &ptr, dom->acme_cert_len)) == NULL)
		fatal("d2i_X509: %s", ssl_errno_s);

	if (SSL_use_certificate(ssl, x509) == 0)
		fatal("SSL_use_certificate: %s", ssl_errno_s);

	SSL_clear_chain_certs(ssl);
	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

	c->proto = CONN_PROTO_ACME_ALPN;
}
#endif /* KORE_USE_ACME */
