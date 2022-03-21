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

#ifndef __H_SECCOMP_H
#define __H_SECCOMP_H

#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <stddef.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ARGS_LO_OFFSET		0
#define ARGS_HI_OFFSET		sizeof(u_int32_t)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ARGS_LO_OFFSET		sizeof(u_int32_t)
#define ARGS_HI_OFFSET		0
#else
#error "__BYTE_ORDER unknown"
#endif

/* Do something with a syscall with a user-supplied action. */
#define KORE_SYSCALL_FILTER(_name, _action)		\
    KORE_BPF_CMP(SYS_##_name, 0, 1),			\
    KORE_BPF_RET(_action)

/*
 * Check if a system call is called with the supplied value as argument.
 *
 * This is checked in 2 steps due to args being 64-bit and the accumulator
 * only being a 32-bit register.
 *
 * If true we return the given action, otherwise nothing happens.
 */
#define KORE_SYSCALL_ARG(_name, _arg, _val, _action)	\
    KORE_BPF_CMP(SYS_##_name, 0, 6),			\
    KORE_BPF_LOAD(args[(_arg)], ARGS_LO_OFFSET),	\
    KORE_BPF_CMP(((_val) & 0xffffffff), 0, 3),		\
    KORE_BPF_LOAD(args[(_arg)], ARGS_HI_OFFSET),	\
    KORE_BPF_CMP((((uint32_t)((uint64_t)(_val) >> 32)) & 0xffffffff), 0, 1),  \
    KORE_BPF_RET(_action),				\
    KORE_BPF_LOAD(nr, 0)

/*
 * Check if a system call is called with the supplied mask as argument.
 *
 * As KORE_SYSCALL_ARG() this is done in 2 steps.
 */
#define KORE_SYSCALL_MASK(_name, _arg, _mask, _action)	\
    KORE_BPF_CMP(SYS_##_name, 0, 8),			\
    KORE_BPF_LOAD(args[(_arg)], ARGS_LO_OFFSET),	\
    KORE_BPF_AND(~((_mask) & 0xffffffff)),		\
    KORE_BPF_CMP(0, 0, 4),				\
    KORE_BPF_LOAD(args[(_arg)], ARGS_HI_OFFSET),	\
    KORE_BPF_AND(~(((uint32_t)((uint64_t)(_mask) >> 32)) & 0xffffffff)),  \
    KORE_BPF_CMP(0, 0, 1),				\
    KORE_BPF_RET(_action),				\
    KORE_BPF_LOAD(nr, 0)

/*
 * Check if the system call is called with the given value in the argument
 * contains the given flag.
 */
#define KORE_SYSCALL_WITH_FLAG(_name, _arg, _flag, _action)	\
    KORE_BPF_CMP(SYS_##_name, 0, 8),			\
    KORE_BPF_LOAD(args[(_arg)], ARGS_LO_OFFSET),	\
    KORE_BPF_AND(((_flag) & 0xffffffff)),		\
    KORE_BPF_CMP(((_flag) & 0xffffffff), 0, 4),		\
    KORE_BPF_LOAD(args[(_arg)], ARGS_HI_OFFSET),	\
    KORE_BPF_AND((((uint32_t)((uint64_t)(_flag) >> 32)) & 0xffffffff)),        \
    KORE_BPF_CMP((((uint32_t)((uint64_t)(_flag) >> 32)) & 0xffffffff), 0, 1),  \
    KORE_BPF_RET(_action),				\
    KORE_BPF_LOAD(nr, 0)

/* Denying of system calls macros (with an errno). */
#define KORE_SYSCALL_DENY(_name, _errno)		\
    KORE_SYSCALL_FILTER(_name, SECCOMP_RET_ERRNO|(_errno))

#define KORE_SYSCALL_DENY_ARG(_name, _arg, _val, _errno)	\
    KORE_SYSCALL_ARG(_name, _arg, _val, SECCOMP_RET_ERRNO|(_errno))

#define KORE_SYSCALL_DENY_MASK(_name, _arg, _val, _errno)	\
    KORE_SYSCALL_MASK(_name, _arg, _val, SECCOMP_RET_ERRNO|(_errno))

#define KORE_SYSCALL_DENY_WITH_FLAG(_name, _arg, _flag, _errno)	\
    KORE_SYSCALL_WITH_FLAG(_name, _arg, _flag, SECCOMP_RET_ERRNO|(_errno))

/* Allowing of system call macros. */
#define KORE_SYSCALL_ALLOW(_name)			\
    KORE_SYSCALL_FILTER(_name, SECCOMP_RET_ALLOW)

#define KORE_SYSCALL_ALLOW_LOG(_name)			\
    KORE_SYSCALL_FILTER(_name, SECCOMP_RET_LOG)

#define KORE_SYSCALL_ALLOW_ARG(_name, _arg, _val)	\
    KORE_SYSCALL_ARG(_name, _arg, _val, SECCOMP_RET_ALLOW)

#define KORE_SYSCALL_ALLOW_MASK(_name, _arg, _mask)	\
    KORE_SYSCALL_MASK(_name, _arg, _mask, SECCOMP_RET_ALLOW)

#define KORE_SYSCALL_ALLOW_WITH_FLAG(_name, _arg, _flag)	\
    KORE_SYSCALL_WITH_FLAG(_name, _arg, _flag, SECCOMP_RET_ALLOW)

/* Load field of seccomp_data into accumulator. */
#define KORE_BPF_LOAD(_field, _off)				\
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, _field) + _off)

/* Return a constant from a BPF program. */
#define KORE_BPF_RET(_retval)				\
    BPF_STMT(BPF_RET+BPF_K, _retval)

/* Compare the accumulator against a constant (==). */
#define KORE_BPF_CMP(_k, _jt, _jf)			\
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, _k, _jt, _jf)

/* AND operation on the accumulator. */
#define KORE_BPF_AND(_k)				\
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, _k)

/* The length of a filter. */
#define KORE_FILTER_LEN(x)		(sizeof(x) / sizeof(x[0]))

/* Used to mark the end of a BPF program. */
#define KORE_BPF_GUARD		{ USHRT_MAX, UCHAR_MAX, UCHAR_MAX, UINT_MAX }

/*
 * Macro for applications to make easily define custom filter.
 *
 * eg:
 * KORE_SECCOMP_FILTER("filter",
 *	KORE_SYSCALL_DENY_ERRNO(socket, EACCESS),
 *	KORE_SYSCALL_DENY_ERRNO(ioctl, EACCESS),
 *	KORE_SYSCALL_ALLOW(poll),
 * )
 */
#define KORE_SECCOMP_FILTER(name, ...)				\
	struct sock_filter _scfilt[] = {			\
		__VA_ARGS__					\
	};							\
	void							\
	kore_seccomp_hook(void)					\
	{							\
		kore_seccomp_filter(name, _scfilt,		\
		    KORE_FILTER_LEN(_scfilt));			\
	}

extern int	kore_seccomp_tracing;

void	kore_seccomp_init(void);
void	kore_seccomp_drop(void);
void	kore_seccomp_enable(void);
void	kore_seccomp_traceme(void);
int	kore_seccomp_trace(pid_t, int);
int	kore_seccomp_syscall_resolve(const char *);
int	kore_seccomp_filter(const char *, void *, size_t);

const char		*kore_seccomp_syscall_name(long);
struct sock_filter	*kore_seccomp_syscall_filter(const char *, int);
struct sock_filter	*kore_seccomp_syscall_arg(const char *, int, int, int);
struct sock_filter	*kore_seccomp_syscall_flag(const char *, int, int, int);
struct sock_filter	*kore_seccomp_syscall_mask(const char *, int, int, int);

#endif
