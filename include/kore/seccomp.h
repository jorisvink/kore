/*
 * Copyright (c) 2019 Joris Vink <joris@coders.se>
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

#ifndef __H_SECCOMP_H
#define __H_SECCOMP_H

#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/*
 * Allow a system call by comparing the accumulator value (which will contain
 * the system call value) with the value of SYS_##name.
 *
 * If the value is equal the true branch (first) is taken, otherwise the
 * false branch (second) is taken.
 *
 * When the program is constructed the true branch jump destination is
 * resolved automatically.
 */
#define KORE_SYSCALL_ALLOW(_name)	\
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##_name, 0, 0)

/* The length of a filter. */
#define KORE_FILTER_LEN(x)		(sizeof(x) / sizeof(x[0]))

void	kore_seccomp_init(void);
void	kore_seccomp_drop(void);
void	kore_seccomp_enable(void);
int	kore_seccomp_filter(const char *, void *, size_t);

#endif
