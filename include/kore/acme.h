/*
 * Copyright (c) 2019-2022 Joris Vink <joris@coders.se>
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

#ifndef __H_ACME_H
#define __H_ACME_H

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * All acme paths are relative to the keymgr_root directory.
 */
#define KORE_ACME_ACCOUNT_KEY	"account-key.pem"
#define KORE_ACME_CERTDIR	"certificates"

#define KORE_ACME_RSAKEY_E		(KORE_MSG_ACME_BASE + 1)
#define KORE_ACME_RSAKEY_N		(KORE_MSG_ACME_BASE + 2)
#define KORE_ACME_SIGN			(KORE_MSG_ACME_BASE + 3)
#define KORE_ACME_SIGN_RESULT		(KORE_MSG_ACME_BASE + 4)
#define KORE_ACME_PROC_READY		(KORE_MSG_ACME_BASE + 5)
#define KORE_ACME_ACCOUNT_CREATE	(KORE_MSG_ACME_BASE + 10)
#define KORE_ACME_ACCOUNT_RESOLVE	(KORE_MSG_ACME_BASE + 11)
#define KORE_ACME_ORDER_CREATE		(KORE_MSG_ACME_BASE + 12)
#define KORE_ACME_CSR_REQUEST		(KORE_MSG_ACME_BASE + 13)
#define KORE_ACME_CSR_RESPONSE		(KORE_MSG_ACME_BASE + 14)
#define KORE_ACME_INSTALL_CERT		(KORE_MSG_ACME_BASE + 15)
#define KORE_ACME_ORDER_FAILED		(KORE_MSG_ACME_BASE + 16)

#define KORE_ACME_CHALLENGE_CERT	(KORE_MSG_ACME_BASE + 20)
#define KORE_ACME_CHALLENGE_SET_CERT	(KORE_MSG_ACME_BASE + 21)
#define KORE_ACME_CHALLENGE_CLEAR_CERT	(KORE_MSG_ACME_BASE + 22)

void	kore_acme_init(void);
void	kore_acme_run(void);
void	kore_acme_setup(void);
void	kore_acme_get_paths(const char *, char **, char **);

extern char	*acme_email;
extern int	acme_domains;
extern char	*acme_provider;

#if defined(__cplusplus)
}
#endif

#endif
