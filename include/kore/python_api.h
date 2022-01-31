/*
 * Copyright (c) 2016 Stanislav Yudin <stan@endlessinsomnia.com>
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

#ifndef __H_PYTHON_H
#define __H_PYTHON_H

#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#define PY_SSIZE_T_CLEAN	1

#include <Python.h>
#include <frameobject.h>

void		kore_python_init(void);
void		kore_python_preinit(void);
void		kore_python_cleanup(void);
void		kore_python_coro_run(void);
void		kore_python_proc_reap(void);
int		kore_python_coro_pending(void);
void		kore_python_path(const char *);
void		kore_python_coro_delete(void *);
void		kore_python_routes_resolve(void);
void		kore_python_log_error(const char *);

PyObject	*kore_python_callable(PyObject *, const char *);

#if defined(__linux__)
void	kore_python_seccomp_cleanup(void);
void	kore_python_seccomp_hook(const char *);
#endif

#if !defined(KORE_SINGLE_BINARY)
extern const char			*kore_pymodule;
#endif

extern struct kore_module_functions	kore_python_module;
extern struct kore_runtime		kore_python_runtime;

#define KORE_PYTHON_SIGNAL_HOOK		"koreapp.signal"
#define KORE_PYTHON_TEARDOWN_HOOK	"koreapp.cleanup"
#define KORE_PYTHON_CONFIG_HOOK		"koreapp.configure"
#define KORE_PYTHON_DAEMONIZED_HOOK	"koreapp.daemonized"
#define KORE_PYTHON_WORKER_STOP_HOOK	"koreapp.workerstop"
#define KORE_PYTHON_WORKER_START_HOOK	"koreapp.workerstart"

#endif
