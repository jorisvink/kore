/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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

#include <fnmatch.h>

#include "kore.h"

#define SSL_SESSION_ID		"kore_ssl_sessionid"

struct kore_domain_h		domains;
struct kore_domain		*primary_dom = NULL;
DH				*tls_dhparam = NULL;
int				tls_version = KORE_TLS_VERSION_1_2;

static void	domain_load_crl(struct kore_domain *);

#if !defined(KORE_NO_TLS)
static int	domain_x509_verify(int, X509_STORE_CTX *);
#endif

void
kore_domain_init(void)
{
	TAILQ_INIT(&domains);
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
	dom->cafile = NULL;
	dom->certkey = NULL;
	dom->ssl_ctx = NULL;
	dom->certfile = NULL;
	dom->crlfile = NULL;
	dom->domain = kore_strdup(domain);
	TAILQ_INIT(&(dom->handlers));
	TAILQ_INSERT_TAIL(&domains, dom, list);

	if (primary_dom == NULL)
		primary_dom = dom;

	return (KORE_RESULT_OK);
}

void
kore_domain_sslstart(struct kore_domain *dom)
{
#if !defined(KORE_NO_TLS)
	STACK_OF(X509_NAME)	*certs;
	X509_STORE		*store;
	const SSL_METHOD	*method;
#if !defined(OPENSSL_NO_EC)
	EC_KEY		*ecdh;
#endif

	kore_debug("kore_domain_sslstart(%s)", dom->domain);

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

	dom->ssl_ctx = SSL_CTX_new(method);
	if (dom->ssl_ctx == NULL)
		fatal("kore_domain_sslstart(): SSL_ctx_new(): %s", ssl_errno_s);
	if (!SSL_CTX_use_certificate_chain_file(dom->ssl_ctx, dom->certfile)) {
		fatal("SSL_CTX_use_certificate_chain_file(%s): %s",
		    dom->certfile, ssl_errno_s);
	}

	if (!SSL_CTX_use_PrivateKey_file(dom->ssl_ctx, dom->certkey,
	    SSL_FILETYPE_PEM)) {
		fatal("SSL_CTX_use_PrivateKey_file(%s): %s",
		    dom->certkey, ssl_errno_s);
	}

	if (!SSL_CTX_check_private_key(dom->ssl_ctx))
		fatal("Public/Private key for %s do not match", dom->domain);

	if (tls_dhparam == NULL)
		fatal("No DH parameters given");

	SSL_CTX_set_tmp_dh(dom->ssl_ctx, tls_dhparam);
	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_DH_USE);

#if !defined(OPENSSL_NO_EC)
	if ((ecdh = EC_KEY_new_by_curve_name(NID_secp384r1)) != NULL) {
		SSL_CTX_set_tmp_ecdh(dom->ssl_ctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif

	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_COMPRESSION);

	if (dom->cafile != NULL) {
		if ((certs = SSL_load_client_CA_file(dom->cafile)) == NULL) {
			fatal("SSL_load_client_CA_file(%s): %s",
			    dom->cafile, ssl_errno_s);
		}

		SSL_CTX_load_verify_locations(dom->ssl_ctx, dom->cafile, NULL);
		SSL_CTX_set_verify_depth(dom->ssl_ctx, 1);
		SSL_CTX_set_client_CA_list(dom->ssl_ctx, certs);
		SSL_CTX_set_verify(dom->ssl_ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		if ((store = SSL_CTX_get_cert_store(dom->ssl_ctx)) == NULL)
			fatal("SSL_CTX_get_cert_store(): %s", ssl_errno_s);

		X509_STORE_set_verify_cb(store, domain_x509_verify);
	}

	SSL_CTX_set_session_id_context(dom->ssl_ctx,
	    (unsigned char *)SSL_SESSION_ID, strlen(SSL_SESSION_ID));

	/*
	 * Force OpenSSL to not use its freelists. Even without using
	 * SSL_MODE_RELEASE_BUFFERS there are times it will use the
	 * freelists. So forcefully putting its max length to 0 is the
	 * only we choice we seem to have.
	 *
	 * Note that OpenBSD has since heartbleed removed freelists
	 * from its OpenSSL in base so we don't need to care about it.
	 */
#if !defined(OpenBSD) || (OpenBSD < 201405)
	dom->ssl_ctx->freelist_max_len = 0;
#endif
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

	kore_mem_free(dom->certfile);
	kore_mem_free(dom->certkey);
#endif
}

struct kore_domain *
kore_domain_lookup(const char *domain)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list) {
		if (!fnmatch(dom->domain, domain, FNM_CASEFOLD))
			return (dom);
	}

	return (NULL);
}

void
kore_domain_closelogs(void)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list)
		close(dom->accesslog);
}

void
kore_domain_load_crl(void)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list)
		domain_load_crl(dom);
}

static void
domain_load_crl(struct kore_domain *dom)
{
#if !defined(KORE_NO_TLS)
	X509_STORE		*store;

	ERR_clear_error();

	if (dom->cafile == NULL)
		return;

	if (dom->crlfile == NULL) {
		kore_log(LOG_WARNING, "WARNING: Running without CRL");
		return;
	}

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
#endif
}

#if !defined(KORE_NO_TLS)
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
#endif
