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
 * An empty TLS backend that does nothing, useful if you do
 * not require any TLS stuff in Kore.
 */

#include <sys/types.h>

#include "kore.h"

struct kore_privsep	keymgr_privsep;
char			*kore_rand_file = NULL;
int			kore_keymgr_active = 0;

int
kore_tls_supported(void)
{
	return (KORE_RESULT_ERROR);
}

void
kore_keymgr_cleanup(int final)
{
}

void
kore_tls_init(void)
{
	kore_log(LOG_ERR, "No compiled in TLS backend");
}

void
kore_tls_cleanup(void)
{
}

void
kore_tls_dh_check(void)
{
}

void
kore_tls_keymgr_init(void)
{
}

void
kore_tls_connection_cleanup(struct connection *c)
{
}

void
kore_tls_domain_cleanup(struct kore_domain *dom)
{
}

void
kore_tls_seed(const void *data, size_t len)
{
}

void
kore_keymgr_run(void)
{
	fatal("%s: not supported", __func__);
}

void
kore_tls_version_set(int version)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_dh_load(const char *path)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_ciphersuite_set(const char *list)
{
	fatal("%s: not supported", __func__);
}

void
kore_tls_domain_setup(struct kore_domain *dom, int type,
    const void *data, size_t datalen)
{
	fatal("%s: not supported", __func__);
}

void
kore_tls_domain_crl(struct kore_domain *dom, const void *pem, size_t pemlen)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_connection_accept(struct connection *c)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_read(struct connection *c, size_t *bytes)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_write(struct connection *c, size_t len, size_t *written)
{
	fatal("%s: not supported", __func__);
}

KORE_PRIVATE_KEY *
kore_tls_rsakey_load(const char *path)
{
	fatal("%s: not supported", __func__);
}

KORE_PRIVATE_KEY *
kore_tls_rsakey_generate(const char *path)
{
	fatal("%s: not supported", __func__);
}

KORE_X509_NAMES *
kore_tls_x509_subject_name(struct connection *c)
{
	fatal("%s: not supported", __func__);
}

KORE_X509_NAMES *
kore_tls_x509_issuer_name(struct connection *c)
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_x509name_foreach(KORE_X509_NAMES *name, int flags, void *udata,
    int (*cb)(void *, int, int, const char *, const void *, size_t, int))
{
	fatal("%s: not supported", __func__);
}

int
kore_tls_x509_data(struct connection *c, u_int8_t **ptr, size_t *olen)
{
	fatal("%s: not supported", __func__);
}
