/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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

#include "kore.h"

struct kore_domain_h		domains;
struct kore_domain		*primary_dom = NULL;
DH				*ssl_dhparam = NULL;
int				ssl_no_compression = 0;

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
	dom->certfile = NULL;
	dom->certkey = NULL;
	dom->ssl_ctx = NULL;
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
	kore_debug("kore_domain_sslstart(%s)", dom->domain);

	dom->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
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

	if (ssl_dhparam != NULL) {
		SSL_CTX_set_tmp_dh(dom->ssl_ctx, ssl_dhparam);
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_DH_USE);
	}

	if (ssl_no_compression)
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_COMPRESSION);

	SSL_CTX_set_mode(dom->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_cipher_list(dom->ssl_ctx, kore_ssl_cipher_list);
	SSL_CTX_set_mode(dom->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_tlsext_servername_callback(dom->ssl_ctx, kore_ssl_sni_cb);
	SSL_CTX_set_next_protos_advertised_cb(dom->ssl_ctx,
	    kore_ssl_npn_cb, NULL);

	kore_mem_free(dom->certfile);
	kore_mem_free(dom->certkey);
}

struct kore_domain *
kore_domain_lookup(const char *domain)
{
	struct kore_domain	*dom;

	TAILQ_FOREACH(dom, &domains, list) {
		if (!strcmp(dom->domain, domain))
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
