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

#ifndef __H_HOOKS_H
#define __H_HOOKS_H

#define KORE_CONFIG_HOOK	"kore_parent_configure"
#define KORE_TEARDOWN_HOOK	"kore_parent_teardown"
#define KORE_DAEMONIZED_HOOK	"kore_parent_daemonized"

void	kore_seccomp_hook(void);
void	kore_worker_signal(int);
void	kore_worker_teardown(void);
void	kore_parent_teardown(void);
void	kore_worker_configure(void);
void	kore_parent_daemonized(void);
void	kore_parent_configure(int, char **);

#endif
