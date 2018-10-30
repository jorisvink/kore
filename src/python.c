/*
 * Copyright (c) 2016 Stanislav Yudin <stan@endlessinsomnia.com>
 * Copyright (c) 2017-2018 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <libgen.h>
#include <signal.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#include "python_api.h"
#include "python_methods.h"

static PyMODINIT_FUNC	python_module_init(void);
static PyObject		*python_import(const char *);
static PyObject		*pyconnection_alloc(struct connection *);
static PyObject		*python_callable(PyObject *, const char *);

static PyObject		*pyhttp_file_alloc(struct http_file *);
static PyObject		*pyhttp_request_alloc(const struct http_request *);

static struct python_coro	*python_coro_create(PyObject *,
				    struct http_request *);
static int			python_coro_run(struct python_coro *);
static void			python_coro_wakeup(struct python_coro *);

static void		pysocket_evt_handle(void *, int);
static PyObject		*pysocket_op_create(struct pysocket *,
			    int, const void *, size_t);

static struct pysocket	*pysocket_alloc(void);
static PyObject		*pysocket_async_recv(struct pysocket_op *);
static PyObject		*pysocket_async_send(struct pysocket_op *);
static PyObject		*pysocket_async_accept(struct pysocket_op *);
static PyObject		*pysocket_async_connect(struct pysocket_op *);

static void		pylock_do_release(struct pylock *);

static void		pytimer_run(void *, u_int64_t);
static void		pyproc_timeout(void *, u_int64_t);
static void		pysuspend_wakeup(void *, u_int64_t);

static void		pygather_reap_coro(struct pygather_op *,
			    struct python_coro *);

#if defined(KORE_USE_PGSQL)
static PyObject		*pykore_pgsql_alloc(struct http_request *,
			    const char *, const char *);
#endif

static void	python_append_path(const char *);
static void	python_push_integer(PyObject *, const char *, long);
static void	python_push_type(const char *, PyObject *, PyTypeObject *);

static int	python_runtime_http_request(void *, struct http_request *);
static int	python_runtime_validator(void *, struct http_request *,
		    const void *);
static void	python_runtime_wsmessage(void *, struct connection *,
		    u_int8_t, const void *, size_t);
static void	python_runtime_execute(void *);
static int	python_runtime_onload(void *, int);
static void	python_runtime_configure(void *, int, char **);
static void	python_runtime_connect(void *, struct connection *);

static void	python_module_load(struct kore_module *);
static void	python_module_free(struct kore_module *);
static void	python_module_reload(struct kore_module *);
static void	*python_module_getsym(struct kore_module *, const char *);

static void	*python_malloc(void *, size_t);
static void	*python_calloc(void *, size_t, size_t);
static void	*python_realloc(void *, void *, size_t);
static void	python_free(void *, void *);

struct kore_module_functions kore_python_module = {
	.free = python_module_free,
	.load = python_module_load,
	.getsym = python_module_getsym,
	.reload = python_module_reload
};

struct kore_runtime kore_python_runtime = {
	KORE_RUNTIME_PYTHON,
	.http_request = python_runtime_http_request,
	.validator = python_runtime_validator,
	.wsconnect = python_runtime_connect,
	.wsmessage = python_runtime_wsmessage,
	.wsdisconnect = python_runtime_connect,
	.onload = python_runtime_onload,
	.connect = python_runtime_connect,
	.execute = python_runtime_execute,
	.configure = python_runtime_configure,
};

static struct {
	const char		*symbol;
	int			value;
} python_integers[] = {
	{ "LOG_ERR", LOG_ERR },
	{ "LOG_INFO", LOG_INFO },
	{ "LOG_NOTICE", LOG_NOTICE },
	{ "RESULT_OK", KORE_RESULT_OK },
	{ "RESULT_RETRY", KORE_RESULT_RETRY },
	{ "RESULT_ERROR", KORE_RESULT_ERROR },
	{ "MODULE_LOAD", KORE_MODULE_LOAD },
	{ "MODULE_UNLOAD", KORE_MODULE_UNLOAD },
	{ "TIMER_ONESHOT", KORE_TIMER_ONESHOT },
	{ "CONN_PROTO_HTTP", CONN_PROTO_HTTP },
	{ "CONN_PROTO_UNKNOWN", CONN_PROTO_UNKNOWN },
	{ "CONN_PROTO_WEBSOCKET", CONN_PROTO_WEBSOCKET },
	{ "CONN_STATE_ESTABLISHED", CONN_STATE_ESTABLISHED },
	{ "HTTP_METHOD_GET", HTTP_METHOD_GET },
	{ "HTTP_METHOD_PUT", HTTP_METHOD_PUT },
	{ "HTTP_METHOD_HEAD", HTTP_METHOD_HEAD },
	{ "HTTP_METHOD_POST", HTTP_METHOD_POST },
	{ "HTTP_METHOD_DELETE", HTTP_METHOD_DELETE },
	{ "HTTP_METHOD_OPTIONS", HTTP_METHOD_OPTIONS },
	{ "HTTP_METHOD_PATCH", HTTP_METHOD_PATCH },
	{ "WEBSOCKET_OP_TEXT", WEBSOCKET_OP_TEXT },
	{ "WEBSOCKET_OP_BINARY", WEBSOCKET_OP_BINARY },
	{ "WEBSOCKET_BROADCAST_LOCAL", WEBSOCKET_BROADCAST_LOCAL },
	{ "WEBSOCKET_BROADCAST_GLOBAL", WEBSOCKET_BROADCAST_GLOBAL },
	{ NULL, -1 }
};

static PyMemAllocatorEx allocator = {
	.ctx = NULL,
	.malloc = python_malloc,
	.calloc = python_calloc,
	.realloc = python_realloc,
	.free = python_free
};

static TAILQ_HEAD(, pyproc)		procs;

static struct kore_pool			coro_pool;
static struct kore_pool			queue_wait_pool;
static struct kore_pool			gather_coro_pool;
static struct kore_pool			queue_object_pool;
static struct kore_pool			gather_result_pool;

static u_int64_t			coro_id;
static int				coro_count;
static struct coro_list			coro_runnable;
static struct coro_list			coro_suspended;

extern const char *__progname;

/* XXX */
static struct python_coro		*coro_running = NULL;

void
kore_python_init(void)
{
	coro_id = 0;
	coro_count = 0;

	TAILQ_INIT(&procs);
	TAILQ_INIT(&coro_runnable);
	TAILQ_INIT(&coro_suspended);

	kore_pool_init(&coro_pool, "coropool", sizeof(struct python_coro), 100);

	kore_pool_init(&queue_wait_pool, "queue_wait_pool",
	    sizeof(struct pyqueue_waiting), 100);
	kore_pool_init(&gather_coro_pool, "gather_coro_pool",
	    sizeof(struct pygather_coro), 100);
	kore_pool_init(&queue_object_pool, "queue_object_pool",
	    sizeof(struct pyqueue_object), 100);
	kore_pool_init(&gather_result_pool, "gather_result_pool",
	    sizeof(struct pygather_result), 100);

	PyMem_SetAllocator(PYMEM_DOMAIN_OBJ, &allocator);
	PyMem_SetAllocator(PYMEM_DOMAIN_MEM, &allocator);
	PyMem_SetAllocator(PYMEM_DOMAIN_RAW, &allocator);
	PyMem_SetupDebugHooks();

	if (PyImport_AppendInittab("kore", &python_module_init) == -1)
		fatal("kore_python_init: failed to add new module");

	Py_Initialize();
}

void
kore_python_cleanup(void)
{
	if (Py_IsInitialized()) {
		PyErr_Clear();
		Py_Finalize();
	}
}

void
kore_python_path(const char *path)
{
	python_append_path(path);
}

void
kore_python_coro_run(void)
{
	struct pygather_op	*op;
	struct python_coro	*coro, *next;

	for (coro = TAILQ_FIRST(&coro_runnable); coro != NULL; coro = next) {
		next = TAILQ_NEXT(coro, list);

		if (coro->state != CORO_STATE_RUNNABLE)
			fatal("non-runnable coro on coro_runnable");

		if (python_coro_run(coro) == KORE_RESULT_OK) {
			if (coro->gatherop != NULL) {
				op = coro->gatherop;
				if (op->coro->request != NULL)
					http_request_wakeup(op->coro->request);
				else
					python_coro_wakeup(op->coro);
				pygather_reap_coro(op, coro);
			} else {
				kore_python_coro_delete(coro);
			}
		}
	}

	/*
	 * Let Kore do HTTP processing so awoken coroutines run asap without
	 * having to wait for a tick from the event loop.
	 *
	 * Maybe it is more beneficial that we track if something related
	 * to HTTP requests was awoken and only run if true?
	 */
	http_process();
}

void
kore_python_coro_delete(void *obj)
{
	struct python_coro	*coro;

	coro = obj;
	coro_count--;

	coro_running = coro;
	Py_DECREF(coro->obj);
	coro_running = NULL;

	if (coro->state == CORO_STATE_RUNNABLE)
		TAILQ_REMOVE(&coro_runnable, coro, list);
	else
		TAILQ_REMOVE(&coro_suspended, coro, list);

	kore_pool_put(&coro_pool, coro);
}

void
kore_python_log_error(const char *function)
{
	const char	*sval;
	PyObject	*repr, *type, *value, *traceback;

	if (!PyErr_Occurred() || PyErr_ExceptionMatches(PyExc_StopIteration))
		return;

	PyErr_Fetch(&type, &value, &traceback);

	if (type == NULL || value == NULL) {
		kore_log(LOG_ERR, "unknown python exception in '%s'", function);
		return;
	}

	if (value == NULL || !PyObject_IsInstance(value, type))
		PyErr_NormalizeException(&type, &value, &traceback);

	/*
	 * If we're in an active coroutine and it was tied to a gather
	 * operation we have to make sure we can use the Exception that
	 * was thrown as the result value so we can propagate it via the
	 * return list of kore.gather().
	 */
	if (coro_running != NULL && coro_running->gatherop != NULL) {
		PyErr_SetObject(PyExc_StopIteration, value);
	} else {
		if ((repr = PyObject_Repr(value)) == NULL)
			sval = "unknown";
		else
			sval = PyUnicode_AsUTF8(repr);

		kore_log(LOG_ERR,
		    "uncaught exception %s in '%s'", sval, function);

		Py_XDECREF(repr);
	}

	Py_DECREF(type);
	Py_DECREF(value);
	Py_XDECREF(traceback);
}

void
kore_python_proc_reap(void)
{
	struct pyproc		*proc;
	pid_t			child;
	int			status;

	if ((child = waitpid(-1, &status, 0)) == -1) {
		if (errno == ECHILD)
			return;
		kore_log(LOG_NOTICE, "waitpid: %s", errno_s);
		return;
	}

	proc = NULL;

	TAILQ_FOREACH(proc, &procs, list) {
		if (proc->pid == child)
			break;
	}

	if (proc == NULL) {
		kore_log(LOG_NOTICE, "SIGCHLD for unknown proc (%d)", child);
		return;
	}

	proc->pid = -1;
	proc->reaped = 1;
	proc->status = status;

	if (proc->coro->request != NULL)
		http_request_wakeup(proc->coro->request);
	else
		python_coro_wakeup(proc->coro);
}

static void *
python_malloc(void *ctx, size_t len)
{
	return (kore_malloc(len));
}

static void *
python_calloc(void *ctx, size_t memb, size_t len)
{
	return (kore_calloc(memb, len));
}

static void *
python_realloc(void *ctx, void *ptr, size_t len)
{
	return (kore_realloc(ptr, len));
}

static void
python_free(void *ctx, void *ptr)
{
	kore_free(ptr);
}

static void
python_module_free(struct kore_module *module)
{
	kore_free(module->path);
	Py_DECREF(module->handle);
	kore_free(module);
}

static void
python_module_reload(struct kore_module *module)
{
	PyObject	*handle;

	PyErr_Clear();
	if ((handle = PyImport_ReloadModule(module->handle)) == NULL) {
		kore_python_log_error("python_module_reload");
		return;
	}

	Py_DECREF(module->handle);
	module->handle = handle;
}

static void
python_module_load(struct kore_module *module)
{
	module->handle = python_import(module->path);
	if (module->handle == NULL)
		fatal("%s: failed to import module", module->path);
}

static void *
python_module_getsym(struct kore_module *module, const char *symbol)
{
	return (python_callable(module->handle, symbol));
}

static struct python_coro *
python_coro_create(PyObject *obj, struct http_request *req)
{
	struct python_coro	*coro;

	if (!PyCoro_CheckExact(obj))
		fatal("%s: object is not a coroutine", __func__);

	coro = kore_pool_get(&coro_pool);
	coro_count++;

	coro->sockop = NULL;
	coro->gatherop = NULL;
	coro->exception = NULL;
	coro->exception_msg = NULL;

	coro->obj = obj;
	coro->request = req;
	coro->id = coro_id++;
	coro->state = CORO_STATE_RUNNABLE;

	TAILQ_INSERT_HEAD(&coro_runnable, coro, list);

	if (coro->request != NULL)
		http_request_sleep(coro->request);

	return (coro);
}

static int
python_coro_run(struct python_coro *coro)
{
	PyObject	*item;

	if (coro->state != CORO_STATE_RUNNABLE)
		fatal("non-runnable coro attempted to run");

	coro_running = coro;

	for (;;) {
		PyErr_Clear();

		item = _PyGen_Send((PyGenObject *)coro->obj, NULL);
		if (item == NULL) {
			kore_python_log_error("coroutine");
			coro_running = NULL;
			return (KORE_RESULT_OK);
		}

		if (item == Py_None) {
			Py_DECREF(item);
			break;
		}

		Py_DECREF(item);
	}

	coro->state = CORO_STATE_SUSPENDED;
	TAILQ_REMOVE(&coro_runnable, coro, list);
	TAILQ_INSERT_HEAD(&coro_suspended, coro, list);

	coro_running = NULL;

	if (coro->request != NULL)
		http_request_sleep(coro->request);

	return (KORE_RESULT_RETRY);
}

static void
python_coro_wakeup(struct python_coro *coro)
{
	if (coro->state != CORO_STATE_SUSPENDED)
		return;

	coro->state = CORO_STATE_RUNNABLE;
	TAILQ_REMOVE(&coro_suspended, coro, list);
	TAILQ_INSERT_HEAD(&coro_runnable, coro, list);
}

static void
pyconnection_dealloc(struct pyconnection *pyc)
{
	PyObject_Del((PyObject *)pyc);
}

static void
pyhttp_dealloc(struct pyhttp_request *pyreq)
{
	Py_XDECREF(pyreq->data);
	PyObject_Del((PyObject *)pyreq);
}

static void
pyhttp_file_dealloc(struct pyhttp_file *pyfile)
{
	PyObject_Del((PyObject *)pyfile);
}

static int
python_runtime_http_request(void *addr, struct http_request *req)
{
	PyObject	*pyret, *pyreq, *args, *callable;

	if (req->py_coro != NULL) {
		python_coro_wakeup(req->py_coro);
		if (python_coro_run(req->py_coro) == KORE_RESULT_OK) {
			kore_python_coro_delete(req->py_coro);
			req->py_coro = NULL;
			return (KORE_RESULT_OK);
		}
		return (KORE_RESULT_RETRY);
	}

	callable = (PyObject *)addr;

	if ((pyreq = pyhttp_request_alloc(req)) == NULL)
		fatal("python_runtime_http_request: pyreq alloc failed");

	if ((args = PyTuple_New(1)) == NULL)
		fatal("python_runtime_http_request: PyTuple_New failed");

	if (PyTuple_SetItem(args, 0, pyreq) != 0)
		fatal("python_runtime_http_request: PyTuple_SetItem failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_http_request");
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (KORE_RESULT_OK);
	}

	if (PyCoro_CheckExact(pyret)) {
		req->py_coro = python_coro_create(pyret, req);
		if (python_coro_run(req->py_coro) == KORE_RESULT_OK) {
			kore_python_coro_delete(req->py_coro);
			req->py_coro = NULL;
			return (KORE_RESULT_OK);
		}
		http_request_sleep(req);
		return (KORE_RESULT_RETRY);
	}

	if (pyret != Py_None)
		fatal("python_runtime_http_request: unexpected return type");

	Py_DECREF(pyret);

	return (KORE_RESULT_OK);
}

static int
python_runtime_validator(void *addr, struct http_request *req, const void *data)
{
	int		ret;
	PyObject	*pyret, *pyreq, *args, *callable, *arg;

	callable = (PyObject *)addr;

	if ((pyreq = pyhttp_request_alloc(req)) == NULL)
		fatal("python_runtime_validator: pyreq alloc failed");

	if (req->flags & HTTP_VALIDATOR_IS_REQUEST) {
		if ((arg = pyhttp_request_alloc(data)) == NULL)
			fatal("python_runtime_validator: pyreq failed");
	} else {
		if ((arg = PyUnicode_FromString(data)) == NULL)
			fatal("python_runtime_validator: PyUnicode failed");
	}

	if ((args = PyTuple_New(2)) == NULL)
		fatal("python_runtime_validator: PyTuple_New failed");

	if (PyTuple_SetItem(args, 0, pyreq) != 0 ||
	    PyTuple_SetItem(args, 1, arg) != 0)
		fatal("python_runtime_vaildator: PyTuple_SetItem failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_validator");
		fatal("failed to execute python call");
	}

	if (!PyLong_Check(pyret))
		fatal("python_runtime_validator: unexpected return type");

	ret = (int)PyLong_AsLong(pyret);
	Py_DECREF(pyret);

	return (ret);
}

static void
python_runtime_wsmessage(void *addr, struct connection *c, u_int8_t op,
    const void *data, size_t len)
{
	PyObject	*callable, *args, *pyret, *pyc, *pyop, *pydata;

	callable = (PyObject *)addr;

	if ((pyc = pyconnection_alloc(c)) == NULL)
		fatal("python_runtime_wsmessage: pyc alloc failed");

	if ((pyop = PyLong_FromLong((long)op)) == NULL)
		fatal("python_runtime_wsmessage: PyLong_FromLong failed");

	switch (op) {
	case WEBSOCKET_OP_TEXT:
		if ((pydata = PyUnicode_FromStringAndSize(data, len)) == NULL)
			fatal("wsmessage: PyUnicode_AsUTF8AndSize failed");
		break;
	case WEBSOCKET_OP_BINARY:
		if ((pydata = PyBytes_FromStringAndSize(data, len)) == NULL)
			fatal("wsmessage: PyBytes_FromString failed");
		break;
	default:
		fatal("python_runtime_wsmessage: invalid op");
	}

	if ((args = PyTuple_New(3)) == NULL)
		fatal("python_runtime_wsmessage: PyTuple_New failed");

	if (PyTuple_SetItem(args, 0, pyc) != 0 ||
	    PyTuple_SetItem(args, 1, pyop) != 0 ||
	    PyTuple_SetItem(args, 2, pydata) != 0)
		fatal("python_runtime_wsmessage: PyTuple_SetItem failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_wsconnect");
		fatal("failed to execute python call");
	}

	Py_DECREF(pyret);
}

static void
python_runtime_execute(void *addr)
{
	PyObject	*callable, *args, *pyret;

	callable = (PyObject *)addr;

	if ((args = PyTuple_New(0)) == NULL)
		fatal("python_runtime_execute: PyTuple_New failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_execute");
		fatal("failed to execute python call");
	}

	Py_DECREF(pyret);
}

static void
python_runtime_configure(void *addr, int argc, char **argv)
{
	int		i;
	PyObject	*callable, *args, *pyret, *pyarg, *list;

	callable = (PyObject *)addr;

	if ((args = PyTuple_New(1)) == NULL)
		fatal("python_runtime_configure: PyTuple_New failed");

	if ((list = PyList_New(argc + 1)) == NULL)
		fatal("python_runtime_configure: PyList_New failed");

	if ((pyarg = PyUnicode_FromString(__progname)) == NULL)
		fatal("python_runtime_configure: PyUnicode_FromString");

	if (PyList_SetItem(list, 0, pyarg) == -1)
		fatal("python_runtime_configure: PyList_SetItem");

	for (i = 0; i < argc; i++) {
		if ((pyarg = PyUnicode_FromString(argv[i])) == NULL)
			fatal("python_runtime_configure: PyUnicode_FromString");

		if (PyList_SetItem(list, i + 1, pyarg) == -1)
			fatal("python_runtime_configure: PyList_SetItem");
	}

	if (PyTuple_SetItem(args, 0, list) != 0)
		fatal("python_runtime_configure: PyTuple_SetItem");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);
	Py_DECREF(list);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_configure");
		fatal("failed to call configure method: wrong args?");
	}

	Py_DECREF(pyret);
}

static int
python_runtime_onload(void *addr, int action)
{
	int		ret;
	PyObject	*pyret, *args, *pyact, *callable;

	callable = (PyObject *)addr;

	if ((pyact = PyLong_FromLong(action)) == NULL)
		fatal("python_runtime_onload: PyLong_FromLong failed");

	if ((args = PyTuple_New(1)) == NULL)
		fatal("python_runtime_onload: PyTuple_New failed");

	if (PyTuple_SetItem(args, 0, pyact) != 0)
		fatal("python_runtime_onload: PyTuple_SetItem failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_onload");
		return (KORE_RESULT_ERROR);
	}

	if (!PyLong_Check(pyret))
		fatal("python_runtime_onload: unexpected return type");

	ret = (int)PyLong_AsLong(pyret);
	Py_DECREF(pyret);

	return (ret);
}

static void
python_runtime_connect(void *addr, struct connection *c)
{
	PyObject	*pyc, *pyret, *args, *callable;

	callable = (PyObject *)addr;

	if ((pyc = pyconnection_alloc(c)) == NULL)
		fatal("python_runtime_connect: pyc alloc failed");

	if ((args = PyTuple_New(1)) == NULL)
		fatal("python_runtime_connect: PyTuple_New failed");

	if (PyTuple_SetItem(args, 0, pyc) != 0)
		fatal("python_runtime_connect: PyTuple_SetItem failed");

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_connect");
		kore_connection_disconnect(c);
	}

	Py_DECREF(pyret);
}

static PyMODINIT_FUNC
python_module_init(void)
{
	int		i;
	PyObject	*pykore;

	if ((pykore = PyModule_Create(&pykore_module)) == NULL)
		fatal("python_module_init: failed to setup pykore module");

	python_push_type("pyproc", pykore, &pyproc_type);
	python_push_type("pylock", pykore, &pylock_type);
	python_push_type("pytimer", pykore, &pytimer_type);
	python_push_type("pyqueue", pykore, &pyqueue_type);
	python_push_type("pysocket", pykore, &pysocket_type);
	python_push_type("pyconnection", pykore, &pyconnection_type);

	python_push_type("pyhttp_file", pykore, &pyhttp_file_type);
	python_push_type("pyhttp_request", pykore, &pyhttp_request_type);

	for (i = 0; python_integers[i].symbol != NULL; i++) {
		python_push_integer(pykore, python_integers[i].symbol,
		    python_integers[i].value);
	}

	return (pykore);
}

static void
python_append_path(const char *path)
{
	PyObject	*mpath, *spath;

	if ((mpath = PyUnicode_FromString(path)) == NULL)
		fatal("python_append_path: PyUnicode_FromString failed");

	if ((spath = PySys_GetObject("path")) == NULL)
		fatal("python_append_path: PySys_GetObject failed");

	PyList_Append(spath, mpath);
	Py_DECREF(mpath);
}

static void
python_push_type(const char *name, PyObject *module, PyTypeObject *type)
{
	if (PyType_Ready(type) == -1)
		fatal("python_push_type: failed to ready %s", name);

	Py_INCREF(type);

	if (PyModule_AddObject(module, name, (PyObject *)type) == -1)
		fatal("python_push_type: failed to push %s", name);
}

static void
python_push_integer(PyObject *module, const char *name, long value)
{
	int		ret;

	if ((ret = PyModule_AddIntConstant(module, name, value)) == -1)
		fatal("python_push_integer: failed to add %s", name);
}

#if defined(KORE_USE_PGSQL)
static PyObject *
python_kore_pgsql_register(PyObject *self, PyObject *args)
{
	const char	*db, *conninfo;

	if (!PyArg_ParseTuple(args, "ss", &db, &conninfo))
		return (NULL);

	(void)kore_pgsql_register(db, conninfo);

	Py_RETURN_TRUE;
}
#endif

static PyObject *
python_kore_log(PyObject *self, PyObject *args)
{
	int		prio;
	const char	*message;

	if (!PyArg_ParseTuple(args, "is", &prio, &message))
		return (NULL);

	kore_log(prio, "%s", message);

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_bind(PyObject *self, PyObject *args)
{
	const char	*ip, *port;

	if (!PyArg_ParseTuple(args, "ss", &ip, &port))
		return (NULL);

	if (!kore_server_bind(ip, port, NULL)) {
		PyErr_SetString(PyExc_RuntimeError, "failed to listen");
		return (NULL);
	}

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_bind_unix(PyObject *self, PyObject *args)
{
	const char	*path;

	if (!PyArg_ParseTuple(args, "s", &path))
		return (NULL);

	if (!kore_server_bind_unix(path, NULL)) {
		PyErr_SetString(PyExc_RuntimeError, "failed bind to path");
		return (NULL);
	}

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_task_create(PyObject *self, PyObject *args)
{
	PyObject		*obj;

	if (!PyArg_ParseTuple(args, "O", &obj))
		return (NULL);

	if (!PyCoro_CheckExact(obj))
		fatal("%s: object is not a coroutine", __func__);

	python_coro_create(obj, NULL);
	Py_INCREF(obj);

	Py_RETURN_NONE;
}

static PyObject *
python_kore_socket_wrap(PyObject *self, PyObject *args)
{
	struct pysocket		*sock;
	PyObject		*pysock, *pyfd, *pyfam, *pyproto;

	sock = NULL;
	pyfd = NULL;
	pyfam = NULL;
	pyproto = NULL;

	if (!PyArg_ParseTuple(args, "O", &pysock))
		return (NULL);

	if ((pyfd = PyObject_CallMethod(pysock, "fileno", NULL)) == NULL)
		return (NULL);

	if ((pyfam = PyObject_GetAttrString(pysock, "family")) == NULL)
		goto out;

	if ((pyproto = PyObject_GetAttrString(pysock, "proto")) == NULL)
		goto out;

	if ((sock = pysocket_alloc()) == NULL)
		goto out;

	sock->socket = pysock;
	Py_INCREF(sock->socket);

	sock->fd = (int)PyLong_AsLong(pyfd);
	sock->family = (int)PyLong_AsLong(pyfam);
	sock->protocol = (int)PyLong_AsLong(pyproto);

	memset(&sock->addr, 0, sizeof(sock->addr));

	switch (sock->family) {
	case AF_INET:
	case AF_UNIX:
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "unsupported family");
		Py_DECREF((PyObject *)sock);
		sock = NULL;
		goto out;
	}

out:
	Py_XDECREF(pyfd);
	Py_XDECREF(pyfam);
	Py_XDECREF(pyproto);

	return ((PyObject *)sock);
}

static PyObject *
python_kore_queue(PyObject *self, PyObject *args)
{
	struct pyqueue		*queue;

	if ((queue = PyObject_New(struct pyqueue, &pyqueue_type)) == NULL)
		return (NULL);

	TAILQ_INIT(&queue->objects);
	TAILQ_INIT(&queue->waiting);

	return ((PyObject *)queue);
}

static PyObject *
python_kore_gather(PyObject *self, PyObject *args)
{
	struct pygather_op	*op;
	PyObject		*obj;
	struct pygather_coro	*coro;
	Py_ssize_t		sz, idx;

	if (coro_running == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
		    "kore.gather only available in coroutines");
		return (NULL);
	}

	sz = PyTuple_Size(args);

	if (sz > INT_MAX) {
		PyErr_SetString(PyExc_TypeError, "too many arguments");
		return (NULL);
	}

	op = PyObject_New(struct pygather_op, &pygather_op_type);
	if (op == NULL)
		return (NULL);

	op->count = (int)sz;
	op->coro = coro_running;

	TAILQ_INIT(&op->results);
	TAILQ_INIT(&op->coroutines);

	for (idx = 0; idx < sz; idx++) {
		if ((obj = PyTuple_GetItem(args, idx)) == NULL) {
			Py_DECREF((PyObject *)op);
			return (NULL);
		}

		if (!PyCoro_CheckExact(obj)) {
			Py_DECREF((PyObject *)op);
			PyErr_SetString(PyExc_TypeError, "not a coroutine");
			return (NULL);
		}

		Py_INCREF(obj);

		coro = kore_pool_get(&gather_coro_pool);

		coro->coro = python_coro_create(obj, NULL);
		coro->coro->gatherop = op;

		TAILQ_INSERT_TAIL(&op->coroutines, coro, list);
	}

	return ((PyObject *)op);
}

static PyObject *
python_kore_lock(PyObject *self, PyObject *args)
{
	struct pylock		*lock;

	if ((lock = PyObject_New(struct pylock, &pylock_type)) == NULL)
		return (NULL);

	lock->owner = NULL;
	TAILQ_INIT(&lock->ops);

	return ((PyObject *)lock);
}

static PyObject *
python_kore_fatal(PyObject *self, PyObject *args)
{
	const char	*reason;

	if (!PyArg_ParseTuple(args, "s", &reason))
		reason = "python_kore_fatal: PyArg_ParseTuple failed";

	fatal("%s", reason);

	/* not reached */
	Py_RETURN_TRUE;
}

static PyObject *
python_kore_fatalx(PyObject *self, PyObject *args)
{
	const char	*reason;

	if (!PyArg_ParseTuple(args, "s", &reason))
		reason = "python_kore_fatalx: PyArg_ParseTuple failed";

	fatalx("%s", reason);

	/* not reached */
	Py_RETURN_TRUE;
}

static PyObject *
python_kore_suspend(PyObject *self, PyObject *args)
{
	struct pysuspend_op	*op;
	int			delay;

	if (!PyArg_ParseTuple(args, "i", &delay))
		return (NULL);

	op = PyObject_New(struct pysuspend_op, &pysuspend_op_type);
	if (op == NULL)
		return (NULL);

	op->timer = NULL;
	op->delay = delay;
	op->coro = coro_running;
	op->state = PYSUSPEND_OP_INIT;

	return ((PyObject *)op);
}

static PyObject *
python_kore_shutdown(PyObject *self, PyObject *args)
{
	kore_shutdown();

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_timer(PyObject *self, PyObject *args)
{
	u_int64_t		ms;
	PyObject		*obj;
	int			flags;
	struct pytimer		*timer;

	if (!PyArg_ParseTuple(args, "OKi", &obj, &ms, &flags))
		return (NULL);

	if (flags & ~(KORE_TIMER_FLAGS)) {
		PyErr_SetString(PyExc_RuntimeError, "invalid flags");
		return (NULL);
	}

	if ((timer = PyObject_New(struct pytimer, &pytimer_type)) == NULL)
		return (NULL);

	timer->flags = flags;
	timer->callable = obj;
	timer->run = kore_timer_add(pytimer_run, ms, timer, flags);

	Py_INCREF((PyObject *)timer);
	Py_INCREF(timer->callable);

	return ((PyObject *)timer);
}

static PyObject *
python_kore_proc(PyObject *self, PyObject *args)
{
	const char		*cmd;
	struct pyproc		*proc;
	char			*copy, *argv[30];
	int			timeo, in_pipe[2], out_pipe[2];

	timeo = -1;

	if (coro_running == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
		    "kore.proc only available in coroutines");
		return (NULL);
	}

	if (!PyArg_ParseTuple(args, "s|i", &cmd, &timeo))
		return (NULL);

	if (pipe(in_pipe) == -1) {
		PyErr_SetString(PyExc_RuntimeError, errno_s);
		return (NULL);
	}

	if (pipe(out_pipe) == -1) {
		close(in_pipe[0]);
		close(in_pipe[1]);
		PyErr_SetString(PyExc_RuntimeError, errno_s);
		return (NULL);
	}

	if ((proc = PyObject_New(struct pyproc, &pyproc_type)) == NULL) {
		close(in_pipe[0]);
		close(in_pipe[1]);
		close(out_pipe[0]);
		close(out_pipe[1]);
		return (NULL);
	}

	proc->pid = -1;
	proc->reaped = 0;
	proc->status = 0;
	proc->timer = NULL;
	proc->coro = coro_running;
	proc->in = pysocket_alloc();
	proc->out = pysocket_alloc();

	if (proc->in == NULL || proc->out == NULL) {
		Py_DECREF((PyObject *)proc);
		return (NULL);
	}

	TAILQ_INSERT_TAIL(&procs, proc, list);

	proc->pid = fork();
	if (proc->pid == -1) {
		if (errno == ENOSYS) {
			Py_DECREF((PyObject *)proc);
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}
		fatal("python_kore_proc: fork(): %s", errno_s);
	}

	if (proc->pid == 0) {
		close(in_pipe[1]);
		close(out_pipe[0]);

		if (dup2(out_pipe[1], STDOUT_FILENO) == -1 ||
		    dup2(out_pipe[1], STDERR_FILENO) == -1 ||
		    dup2(in_pipe[0], STDIN_FILENO) == -1)
			fatal("dup2: %s", errno_s);

		copy = kore_strdup(cmd);
		kore_split_string(copy, " ", argv, 30);
		(void)execve(argv[0], argv, NULL);
		printf("kore.proc failed to execute %s (%s)\n",
		    argv[0], errno_s);
		exit(1);
	}

	close(in_pipe[0]);
	close(out_pipe[1]);

	if (!kore_connection_nonblock(in_pipe[1], 0) ||
	    !kore_connection_nonblock(out_pipe[0], 0)) {
		Py_DECREF((PyObject *)proc);
		PyErr_SetString(PyExc_RuntimeError, errno_s);
		return (NULL);
	}

	proc->in->fd = in_pipe[1];
	proc->out->fd = out_pipe[0];

	if (timeo != -1) {
		proc->timer = kore_timer_add(pyproc_timeout,
		    timeo, proc, KORE_TIMER_ONESHOT);
	}

	return ((PyObject *)proc);
}

static PyObject *
python_import(const char *path)
{
	PyObject	*module;
	char		*dir, *file, *copy, *p;

	copy = kore_strdup(path);

	if ((file = basename(copy)) == NULL)
		fatal("basename: %s: %s", path, errno_s);
	if ((dir = dirname(copy)) == NULL)
		fatal("dirname: %s: %s", path, errno_s);

	if ((p = strrchr(file, '.')) != NULL)
		*p = '\0';

	python_append_path(dir);
	module = PyImport_ImportModule(file);
	if (module == NULL)
		PyErr_Print();

	kore_free(copy);

	return (module);
}

static PyObject *
python_callable(PyObject *module, const char *symbol)
{
	PyObject	*obj;

	if ((obj = PyObject_GetAttrString(module, symbol)) == NULL)
		return (NULL);

	if (!PyCallable_Check(obj)) {
		Py_DECREF(obj);
		return (NULL);
	}

	return (obj);
}

static PyObject *
pyconnection_alloc(struct connection *c)
{
	struct pyconnection		*pyc;

	pyc = PyObject_New(struct pyconnection, &pyconnection_type);
	if (pyc == NULL)
		return (NULL);

	pyc->c = c;

	return ((PyObject *)pyc);
}

static PyObject *
pyconnection_disconnect(struct pyconnection *pyc, PyObject *args)
{
	kore_connection_disconnect(pyc->c);

	Py_RETURN_TRUE;
}

static PyObject *
pyconnection_get_fd(struct pyconnection *pyc, void *closure)
{
	PyObject	*fd;

	if ((fd = PyLong_FromLong(pyc->c->fd)) == NULL)
		return (PyErr_NoMemory());

	return (fd);
}

static PyObject *
pyconnection_get_addr(struct pyconnection *pyc, void *closure)
{
	void		*ptr;
	PyObject	*result;
	char		addr[INET6_ADDRSTRLEN];

	switch (pyc->c->family) {
	case AF_INET:
		ptr = &pyc->c->addr.ipv4.sin_addr;
		break;
	case AF_INET6:
		ptr = &pyc->c->addr.ipv6.sin6_addr;
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "invalid family");
		return (NULL);
	}

	if (inet_ntop(pyc->c->family, ptr, addr, sizeof(addr)) == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "inet_ntop failed");
		return (NULL);
	}

	if ((result = PyUnicode_FromString(addr)) == NULL)
		return (PyErr_NoMemory());

	return (result);
}

static void
pytimer_run(void *arg, u_int64_t now)
{
	PyObject	*ret;
	struct pytimer	*timer = arg;

	PyErr_Clear();
	ret = PyObject_CallObject(timer->callable, NULL);
	Py_DECREF(ret);

	if (timer->flags & KORE_TIMER_ONESHOT) {
		timer->run = NULL;
		Py_DECREF((PyObject *)timer);
	}
}

static void
pytimer_dealloc(struct pytimer *timer)
{
	if (timer->run != NULL) {
		kore_timer_remove(timer->run);
		timer->run = NULL;
	}

	if (timer->callable != NULL) {
		Py_DECREF(timer->callable);
		timer->callable = NULL;
	}

	PyObject_Del((PyObject *)timer);
}

static PyObject *
pytimer_close(struct pytimer *timer, PyObject *args)
{
	if (timer->run != NULL) {
		kore_timer_remove(timer->run);
		timer->run = NULL;
	}

	if (timer->callable != NULL) {
		Py_DECREF(timer->callable);
		timer->callable = NULL;
	}

	Py_INCREF((PyObject *)timer);
	Py_RETURN_TRUE;
}

static void
pysuspend_op_dealloc(struct pysuspend_op *op)
{
	if (op->timer != NULL) {
		kore_timer_remove(op->timer);
		op->timer = NULL;
	}

	PyObject_Del((PyObject *)op);
}

static PyObject *
pysuspend_op_await(PyObject *sop)
{
	Py_INCREF(sop);
	return (sop);
}

static PyObject *
pysuspend_op_iternext(struct pysuspend_op *op)
{
	switch (op->state) {
	case PYSUSPEND_OP_INIT:
		op->timer = kore_timer_add(pysuspend_wakeup, op->delay,
		    op, KORE_TIMER_ONESHOT);
		op->state = PYSUSPEND_OP_WAIT;
		break;
	case PYSUSPEND_OP_WAIT:
		break;
	case PYSUSPEND_OP_CONTINUE:
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	default:
		fatal("unknown state %d for pysuspend_op", op->state);
	}

	Py_RETURN_NONE;
}

static void
pysuspend_wakeup(void *arg, u_int64_t now)
{
	struct pysuspend_op	*op = arg;

	op->timer = NULL;
	op->state = PYSUSPEND_OP_CONTINUE;

	if (op->coro->request != NULL)
		http_request_wakeup(op->coro->request);
	else
		python_coro_wakeup(op->coro);
}

static struct pysocket *
pysocket_alloc(void)
{
	struct pysocket		*sock;

	if ((sock = PyObject_New(struct pysocket, &pysocket_type)) == NULL)
		return (NULL);

	sock->fd = -1;
	sock->family = -1;
	sock->protocol = -1;
	sock->socket = NULL;

	return (sock);
}

static void
pysocket_dealloc(struct pysocket *sock)
{
	if (sock->socket != NULL) {
		(void)PyObject_CallMethod(sock->socket, "close", NULL);
		Py_DECREF(sock->socket);
	} else if (sock->fd != -1) {
		(void)close(sock->fd);
	}

	PyObject_Del((PyObject *)sock);
}

static PyObject *
pysocket_send(struct pysocket *sock, PyObject *args)
{
	Py_buffer	buf;

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	return (pysocket_op_create(sock, PYSOCKET_TYPE_SEND, buf.buf, buf.len));
}

static PyObject *
pysocket_recv(struct pysocket *sock, PyObject *args)
{
	Py_ssize_t	len;

	if (!PyArg_ParseTuple(args, "n", &len))
		return (NULL);

	return (pysocket_op_create(sock, PYSOCKET_TYPE_RECV, NULL, len));
}

static PyObject *
pysocket_accept(struct pysocket *sock, PyObject *args)
{
	return (pysocket_op_create(sock, PYSOCKET_TYPE_ACCEPT, NULL, 0));
}

static PyObject *
pysocket_connect(struct pysocket *sock, PyObject *args)
{
	const char		*host;
	int			port, len;

	port = 0;

	if (!PyArg_ParseTuple(args, "s|i", &host, &port))
		return (NULL);

	if (port < 0 || port > USHRT_MAX) {
		PyErr_SetString(PyExc_RuntimeError, "invalid port number");
		return (NULL);
	}

	switch (sock->family) {
	case AF_INET:
		sock->addr.ipv4.sin_family = AF_INET;
		sock->addr.ipv4.sin_port = htons(port);
		if (inet_pton(sock->family, host,
		    &sock->addr.ipv4.sin_addr) == -1) {
			PyErr_SetString(PyExc_RuntimeError, "invalid host");
			return (NULL);
		}
		sock->addr_len = sizeof(sock->addr.ipv4);
		break;
	case AF_UNIX:
		sock->addr.sun.sun_family = AF_UNIX;
		len = snprintf(sock->addr.sun.sun_path,
		    sizeof(sock->addr.sun.sun_path), "%s", host);
		if (len == -1 ||
		    (size_t)len >= sizeof(sock->addr.sun.sun_path)) {
			PyErr_SetString(PyExc_RuntimeError, "path too long");
			return (NULL);
		}
#if defined(__linux__)
		/* Assume abstract socket if prefixed with '@'. */
		if (sock->addr.sun.sun_path[0] == '@')
			sock->addr.sun.sun_path[0] = '\0';
#endif
		sock->addr_len = sizeof(sock->addr.sun.sun_family) + len;
		break;
	default:
		fatal("unsupported socket family %d", sock->family);
	}

	return (pysocket_op_create(sock, PYSOCKET_TYPE_CONNECT, NULL, 0));
}

static PyObject *
pysocket_close(struct pysocket *sock, PyObject *args)
{
	if (sock->socket != NULL) {
		(void)PyObject_CallMethod(sock->socket, "close", NULL);
		Py_DECREF(sock->socket);
		sock->socket = NULL;
	} else if (sock->fd != -1) {
		(void)close(sock->fd);
		sock->fd = -1;
	}

	Py_RETURN_TRUE;
}

static void
pysocket_op_dealloc(struct pysocket_op *op)
{
#if defined(__linux__)
	kore_platform_disable_read(op->data.fd);
	close(op->data.fd);
#else
	switch (op->data.type) {
	case PYSOCKET_TYPE_RECV:
	case PYSOCKET_TYPE_ACCEPT:
		kore_platform_disable_read(op->data.fd);
		break;
	case PYSOCKET_TYPE_SEND:
	case PYSOCKET_TYPE_CONNECT:
		kore_platform_disable_write(op->data.fd);
		break;
	default:
		fatal("unknown pysocket_op type %u", op->data.type);
	}
#endif

	if (op->data.type == PYSOCKET_TYPE_RECV ||
	    op->data.type == PYSOCKET_TYPE_SEND)
		kore_buf_cleanup(&op->data.buffer);

	op->data.coro->sockop = NULL;
	Py_DECREF(op->data.socket);

	PyObject_Del((PyObject *)op);
}

static PyObject *
pysocket_op_create(struct pysocket *sock, int type, const void *ptr, size_t len)
{
	struct pysocket_op	*op;

	if (coro_running->sockop != NULL)
		fatal("pysocket_op_create: coro has active socketop");

	op = PyObject_New(struct pysocket_op, &pysocket_op_type);
	if (op == NULL)
		return (NULL);

#if defined(__linux__)
	/*
	 * Duplicate the socket so each pysocket_op gets its own unique
	 * descriptor for epoll. This is so we can easily call EPOLL_CTL_DEL
	 * on the fd when the pysocket_op is finished as our event code
	 * does not track queued events.
	 */
	if ((op->data.fd = dup(sock->fd)) == -1)
		fatal("dup: %s", errno_s);
#else
	op->data.fd = sock->fd;
#endif

	op->data.eof = 0;
	op->data.self = op;
	op->data.type = type;
	op->data.socket = sock;
	op->data.evt.flags = 0;
	op->data.coro = coro_running;
	op->data.evt.type = KORE_TYPE_PYSOCKET;
	op->data.evt.handle = pysocket_evt_handle;

	coro_running->sockop = op;
	Py_INCREF(op->data.socket);

	switch (type) {
	case PYSOCKET_TYPE_RECV:
		op->data.evt.flags |= KORE_EVENT_READ;
		kore_buf_init(&op->data.buffer, len);
		kore_platform_schedule_read(op->data.fd, &op->data);
		break;
	case PYSOCKET_TYPE_SEND:
		op->data.evt.flags |= KORE_EVENT_WRITE;
		kore_buf_init(&op->data.buffer, len);
		kore_buf_append(&op->data.buffer, ptr, len);
		kore_buf_reset(&op->data.buffer);
		kore_platform_schedule_write(op->data.fd, &op->data);
		break;
	case PYSOCKET_TYPE_ACCEPT:
		op->data.evt.flags |= KORE_EVENT_READ;
		kore_platform_schedule_read(op->data.fd, &op->data);
		break;
	case PYSOCKET_TYPE_CONNECT:
		op->data.evt.flags |= KORE_EVENT_WRITE;
		kore_platform_schedule_write(op->data.fd, &op->data);
		break;
	default:
		fatal("unknown pysocket_op type %u", type);
	}

	return ((PyObject *)op);
}

static PyObject *
pysocket_op_await(PyObject *obj)
{
	Py_INCREF(obj);
	return (obj);
}

static PyObject *
pysocket_op_iternext(struct pysocket_op *op)
{
	PyObject		*ret;

	if (op->data.eof) {
		if (op->data.coro->exception != NULL) {
			PyErr_SetString(op->data.coro->exception,
			    op->data.coro->exception_msg);
			op->data.coro->exception = NULL;
			return (NULL);
		}

		if (op->data.type != PYSOCKET_TYPE_RECV) {
			PyErr_SetString(PyExc_RuntimeError, "socket EOF");
			return (NULL);
		}

		PyErr_SetNone(PyExc_StopIteration);

		return (NULL);
	}

	switch (op->data.type) {
	case PYSOCKET_TYPE_CONNECT:
		ret = pysocket_async_connect(op);
		break;
	case PYSOCKET_TYPE_ACCEPT:
		ret = pysocket_async_accept(op);
		break;
	case PYSOCKET_TYPE_RECV:
		ret = pysocket_async_recv(op);
		break;
	case PYSOCKET_TYPE_SEND:
		ret = pysocket_async_send(op);
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "invalid op type");
		return (NULL);
	}

	return (ret);
}

static PyObject *
pysocket_async_connect(struct pysocket_op *op)
{
	if (connect(op->data.fd, (struct sockaddr *)&op->data.socket->addr,
	    op->data.socket->addr_len) == -1) {
		if (errno != EALREADY && errno != EINPROGRESS &&
		    errno != EISCONN) {
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}

		if (errno != EISCONN) {
			Py_RETURN_NONE;
		}
	}

	PyErr_SetNone(PyExc_StopIteration);
	return (NULL);
}

static PyObject *
pysocket_async_accept(struct pysocket_op *op)
{
	int			fd;
	struct pysocket		*sock;

	if ((sock = pysocket_alloc() ) == NULL)
		return (NULL);

	sock->addr_len = sizeof(sock->addr);

	if ((fd = accept(op->data.fd,
	    (struct sockaddr *)&sock->addr, &sock->addr_len)) == -1) {
		Py_DECREF((PyObject *)sock);
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			Py_RETURN_NONE;
		}
		PyErr_SetString(PyExc_RuntimeError, errno_s);
		return (NULL);
	}

	if (!kore_connection_nonblock(fd, 0)) {
		Py_DECREF((PyObject *)sock);
		PyErr_SetString(PyExc_RuntimeError, errno_s);
		return (NULL);
	}

	sock->fd = fd;
	sock->socket = NULL;
	sock->family = op->data.socket->family;
	sock->protocol = op->data.socket->protocol;

	PyErr_SetObject(PyExc_StopIteration, (PyObject *)sock);
	Py_DECREF((PyObject *)sock);

	return (NULL);
}

static PyObject *
pysocket_async_recv(struct pysocket_op *op)
{
	ssize_t		ret;
	const char	*ptr;
	PyObject	*bytes;

	if (!(op->data.evt.flags & KORE_EVENT_READ)) {
		Py_RETURN_NONE;
	}

	for (;;) {
		ret = read(op->data.fd, op->data.buffer.data,
		    op->data.buffer.length);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				op->data.evt.flags &= ~KORE_EVENT_READ;
				Py_RETURN_NONE;
			}
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}

		break;
	}

	if (ret == 0) {
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	}

	ptr = (const char *)op->data.buffer.data;

	bytes = PyBytes_FromStringAndSize(ptr, ret);
	if (bytes != NULL) {
		PyErr_SetObject(PyExc_StopIteration, bytes);
		Py_DECREF(bytes);
	}

	return (NULL);
}

static PyObject *
pysocket_async_send(struct pysocket_op *op)
{
	ssize_t		ret;

	if (!(op->data.evt.flags & KORE_EVENT_WRITE)) {
		Py_RETURN_NONE;
	}

	for (;;) {
		ret = write(op->data.fd,
		    op->data.buffer.data + op->data.buffer.offset,
		    op->data.buffer.length - op->data.buffer.offset);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				op->data.evt.flags &= ~KORE_EVENT_WRITE;
				Py_RETURN_NONE;
			}
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}
		break;
	}

	op->data.buffer.offset += (size_t)ret;

	if (op->data.buffer.offset == op->data.buffer.length) {
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	}

	Py_RETURN_NONE;
}

static void
pysocket_evt_handle(void *arg, int eof)
{
	struct pysocket_data		*data = arg;
	struct python_coro		*coro = data->coro;

	if (coro->sockop == NULL)
		fatal("pysocket_evt_handle: sockop == NULL");

	/*
	 * If we are a coroutine tied to an HTTP request wake-up the
	 * HTTP request instead. That in turn will wakeup the coro and
	 * continue it.
	 *
	 * Otherwise just wakeup the coroutine so it will run next tick.
	 */
	if (coro->request != NULL)
		http_request_wakeup(coro->request);
	else
		python_coro_wakeup(coro);

	coro->sockop->data.eof = eof;
}

static void
pyqueue_dealloc(struct pyqueue *queue)
{
	struct pyqueue_object	*object;
	struct pyqueue_waiting	*waiting;

	while ((object = TAILQ_FIRST(&queue->objects)) != NULL) {
		TAILQ_REMOVE(&queue->objects, object, list);
		Py_DECREF(object->obj);
		kore_pool_put(&queue_object_pool, object);
	}

	while ((waiting = TAILQ_FIRST(&queue->waiting)) != NULL) {
		TAILQ_REMOVE(&queue->waiting, waiting, list);
		if (waiting->op != NULL)
			waiting->op->waiting = NULL;
		kore_pool_put(&queue_wait_pool, waiting);
	}

	PyObject_Del((PyObject *)queue);
}

static PyObject *
pyqueue_pop(struct pyqueue *queue, PyObject *args)
{
	struct pyqueue_op	*op;

	if ((op = PyObject_New(struct pyqueue_op, &pyqueue_op_type)) == NULL)
		return (NULL);

	op->queue = queue;
	op->waiting = kore_pool_get(&queue_wait_pool);
	op->waiting->op = op;

	op->waiting->coro = coro_running;
	TAILQ_INSERT_TAIL(&queue->waiting, op->waiting, list);

	Py_INCREF((PyObject *)queue);

	return ((PyObject *)op);
}

static PyObject *
pyqueue_popnow(struct pyqueue *queue, PyObject *args)
{
	PyObject		*obj;
	struct pyqueue_object	*object;

	if ((object = TAILQ_FIRST(&queue->objects)) == NULL) {
		Py_RETURN_NONE;
	}

	TAILQ_REMOVE(&queue->objects, object, list);

	obj = object->obj;
	kore_pool_put(&queue_object_pool, object);

	return (obj);
}

static PyObject *
pyqueue_push(struct pyqueue *queue, PyObject *args)
{
	PyObject		*obj;
	struct pyqueue_object	*object;
	struct pyqueue_waiting	*waiting;

	if (!PyArg_ParseTuple(args, "O", &obj))
		return (NULL);

	Py_INCREF(obj);

	object = kore_pool_get(&queue_object_pool);
	object->obj = obj;

	TAILQ_INSERT_TAIL(&queue->objects, object, list);

	/* Wakeup first in line if any. */
	if ((waiting = TAILQ_FIRST(&queue->waiting)) != NULL) {
		TAILQ_REMOVE(&queue->waiting, waiting, list);

		/* wakeup HTTP request if one is tied. */
		if (waiting->coro->request != NULL)
			http_request_wakeup(waiting->coro->request);
		else
			python_coro_wakeup(waiting->coro);

		waiting->op->waiting = NULL;
		kore_pool_put(&queue_wait_pool, waiting);
	}

	Py_RETURN_TRUE;
}

static void
pyqueue_op_dealloc(struct pyqueue_op *op)
{
	if (op->waiting != NULL) {
		TAILQ_REMOVE(&op->queue->waiting, op->waiting, list);
		kore_pool_put(&queue_wait_pool, op->waiting);
		op->waiting = NULL;
	}

	Py_DECREF((PyObject *)op->queue);
	PyObject_Del((PyObject *)op);
}

static PyObject *
pyqueue_op_await(PyObject *obj)
{
	Py_INCREF(obj);
	return (obj);
}

static PyObject *
pyqueue_op_iternext(struct pyqueue_op *op)
{
	PyObject		*obj;
	struct pyqueue_object	*object;
	struct pyqueue_waiting	*waiting;

	if ((object = TAILQ_FIRST(&op->queue->objects)) == NULL) {
		Py_RETURN_NONE;
	}

	TAILQ_REMOVE(&op->queue->objects, object, list);

	obj = object->obj;
	kore_pool_put(&queue_object_pool, object);

	TAILQ_FOREACH(waiting, &op->queue->waiting, list) {
		if (waiting->coro == coro_running) {
			TAILQ_REMOVE(&op->queue->waiting, waiting, list);
			kore_pool_put(&queue_wait_pool, waiting);
			break;
		}
	}

	PyErr_SetObject(PyExc_StopIteration, obj);
	Py_DECREF(obj);

	return (NULL);
}

static void
pylock_dealloc(struct pylock *lock)
{
	struct pylock_op	*op;

	while ((op = TAILQ_FIRST(&lock->ops)) != NULL) {
		TAILQ_REMOVE(&lock->ops, op, list);
		op->active = 0;
		Py_DECREF((PyObject *)op);
	}

	PyObject_Del((PyObject *)op);
}

static PyObject *
pylock_aenter(struct pylock *lock, PyObject *args)
{
	struct pylock_op	*op;

	if (lock->owner != NULL && lock->owner->id == coro_running->id) {
		PyErr_SetString(PyExc_RuntimeError, "recursive lock detected");
		return (NULL);
	}

	if ((op = PyObject_New(struct pylock_op, &pylock_op_type)) == NULL)
		return (NULL);

	op->active = 1;
	op->lock = lock;
	op->locking = 1;
	op->coro = coro_running;

	Py_INCREF((PyObject *)op);
	Py_INCREF((PyObject *)lock);

	TAILQ_INSERT_TAIL(&lock->ops, op, list);

	return ((PyObject *)op);
}

static PyObject *
pylock_aexit(struct pylock *lock, PyObject *args)
{
	struct pylock_op	*op;

	if (lock->owner == NULL || lock->owner->id != coro_running->id) {
		PyErr_SetString(PyExc_RuntimeError, "invalid lock owner");
		return (NULL);
	}

	if ((op = PyObject_New(struct pylock_op, &pylock_op_type)) == NULL)
		return (NULL);

	op->active = 1;
	op->lock = lock;
	op->locking = 0;
	op->coro = coro_running;

	Py_INCREF((PyObject *)op);
	Py_INCREF((PyObject *)lock);

	TAILQ_INSERT_TAIL(&lock->ops, op, list);

	return ((PyObject *)op);
}

static void
pylock_do_release(struct pylock *lock)
{
	struct pylock_op	*op;

	lock->owner = NULL;

	TAILQ_FOREACH(op, &lock->ops, list) {
		if (op->locking == 0)
			continue;

		TAILQ_REMOVE(&op->lock->ops, op, list);

		if (op->coro->request != NULL)
			http_request_wakeup(op->coro->request);
		else
			python_coro_wakeup(op->coro);

		op->active = 0;
		Py_DECREF((PyObject *)op);
		break;
	}
}

static void
pylock_op_dealloc(struct pylock_op *op)
{
	if (op->active) {
		TAILQ_REMOVE(&op->lock->ops, op, list);
		op->active = 0;
	}

	Py_DECREF((PyObject *)op->lock);
	PyObject_Del((PyObject *)op);
}

static PyObject *
pylock_op_await(PyObject *obj)
{
	Py_INCREF(obj);
	return (obj);
}

static PyObject *
pylock_op_iternext(struct pylock_op *op)
{
	if (op->locking == 0) {
		if (op->lock->owner == NULL) {
			PyErr_SetString(PyExc_RuntimeError,
			    "no lock owner set");
			return (NULL);
		}

		if (op->lock->owner->id != coro_running->id) {
			PyErr_SetString(PyExc_RuntimeError,
			    "lock not owned by caller");
			return (NULL);
		}

		pylock_do_release(op->lock);
	} else {
		if (op->lock->owner != NULL) {
			Py_RETURN_NONE;
		}

		op->lock->owner = coro_running;
	}

	op->active = 0;
	TAILQ_REMOVE(&op->lock->ops, op, list);
	PyErr_SetNone(PyExc_StopIteration);

	Py_DECREF((PyObject *)op);

	return (NULL);
}

static void
pyproc_timeout(void *arg, u_int64_t now)
{
	struct pyproc	*proc = arg;

	proc->timer = NULL;

	if (proc->coro->sockop != NULL)
		proc->coro->sockop->data.eof = 1;

	proc->coro->exception = PyExc_TimeoutError;
	proc->coro->exception_msg = "timeout before process exited";

	if (proc->coro->request != NULL)
		http_request_wakeup(proc->coro->request);
	else
		python_coro_wakeup(proc->coro);
}

static void
pyproc_dealloc(struct pyproc *proc)
{
	int	status;

	TAILQ_REMOVE(&procs, proc, list);

	if (proc->timer != NULL) {
		kore_timer_remove(proc->timer);
		proc->timer = NULL;
	}

	if (proc->pid != -1) {
		if (kill(proc->pid, SIGKILL) == -1) {
			kore_log(LOG_NOTICE,
			    "kore.proc failed to send SIGKILL %d (%s)",
			    proc->pid, errno_s);
		}

		for (;;) {
			if (waitpid(proc->pid, &status, 0) == -1) {
				if (errno == EINTR)
					continue;
				kore_log(LOG_NOTICE,
				    "kore.proc failed to wait for %d (%s)",
				    proc->pid, errno_s);
			}
			break;
		}
	}

	if (proc->in != NULL) {
		Py_DECREF((PyObject *)proc->in);
		proc->in = NULL;
	}

	if (proc->out != NULL) {
		Py_DECREF((PyObject *)proc->out);
		proc->out = NULL;
	}

	PyObject_Del((PyObject *)proc);
}

static PyObject *
pyproc_kill(struct pyproc *proc, PyObject *args)
{
	if (proc->pid != -1 && kill(proc->pid, SIGKILL) == -1)
		kore_log(LOG_NOTICE, "kill(%d): %s", proc->pid, errno_s);

	Py_RETURN_TRUE;
}

static PyObject *
pyproc_reap(struct pyproc *proc, PyObject *args)
{
	struct pyproc_op	*op;

	if (proc->timer != NULL) {
		kore_timer_remove(proc->timer);
		proc->timer = NULL;
	}

	if ((op = PyObject_New(struct pyproc_op, &pyproc_op_type)) == NULL)
		return (NULL);

	op->proc = proc;

	Py_INCREF((PyObject *)proc);

	return ((PyObject *)op);
}

static PyObject *
pyproc_recv(struct pyproc *proc, PyObject *args)
{
	Py_ssize_t	len;

	if (proc->out == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "stdout closed");
		return (NULL);
	}

	if (!PyArg_ParseTuple(args, "n", &len))
		return (NULL);

	return (pysocket_op_create(proc->out, PYSOCKET_TYPE_RECV, NULL, len));
}

static PyObject *
pyproc_send(struct pyproc *proc, PyObject *args)
{
	Py_buffer	buf;
	PyObject	*ret;

	if (proc->in == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "stdin closed");
		return (NULL);
	}

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ret = pysocket_op_create(proc->in,
	    PYSOCKET_TYPE_SEND, buf.buf, buf.len);

	return (ret);
}

static PyObject *
pyproc_close_stdin(struct pyproc *proc, PyObject *args)
{
	if (proc->in != NULL) {
		Py_DECREF((PyObject *)proc->in);
		proc->in = NULL;
	}

	Py_RETURN_TRUE;
}

static void
pyproc_op_dealloc(struct pyproc_op *op)
{
	Py_DECREF((PyObject *)op->proc);
	PyObject_Del((PyObject *)op);
}

static PyObject *
pyproc_op_await(PyObject *sop)
{
	Py_INCREF(sop);
	return (sop);
}

static PyObject *
pyproc_op_iternext(struct pyproc_op *op)
{
	int		ret;
	PyObject	*res;

	if (op->proc->coro->exception != NULL) {
		PyErr_SetString(op->proc->coro->exception,
		    op->proc->coro->exception_msg);
		op->proc->coro->exception = NULL;
		return (NULL);
	}

	if (op->proc->reaped == 0)
		Py_RETURN_NONE;

	if (WIFSTOPPED(op->proc->status)) {
		op->proc->reaped = 0;
		Py_RETURN_NONE;
	}

	if (WIFEXITED(op->proc->status)) {
		ret = WEXITSTATUS(op->proc->status);
	} else {
		ret = op->proc->status;
	}

	if ((res = PyLong_FromLong(ret)) == NULL)
		return (NULL);

	PyErr_SetObject(PyExc_StopIteration, res);
	Py_DECREF(res);

	return (NULL);
}

static void
pygather_reap_coro(struct pygather_op *op, struct python_coro *reap)
{
	struct pygather_coro	*coro;
	struct pygather_result	*result;

	TAILQ_FOREACH(coro, &op->coroutines, list) {
		if (coro->coro->id == reap->id)
			break;
	}

	if (coro == NULL)
		fatal("coroutine %" PRIu64 " not found in gather", reap->id);

	result = kore_pool_get(&gather_result_pool);
	result->obj = NULL;

	if (_PyGen_FetchStopIterationValue(&result->obj) == -1) {
		result->obj = Py_None;
		Py_INCREF(Py_None);
	}

	TAILQ_INSERT_TAIL(&op->results, result, list);

	TAILQ_REMOVE(&op->coroutines, coro, list);
	kore_pool_put(&gather_coro_pool, coro);

	kore_python_coro_delete(reap);
}

static void
pygather_op_dealloc(struct pygather_op *op)
{
	struct python_coro		*old;
	struct pygather_coro		*coro, *next;
	struct pygather_result		*res, *rnext;

	/*
	 * Since we are calling kore_python_coro_delete() on all the
	 * remaining coroutines in this gather op we must remember the
	 * original coroutine that is running as the removal will end
	 * up setting coro_running to NULL.
	 */
	old = coro_running;

	for (coro = TAILQ_FIRST(&op->coroutines); coro != NULL; coro = next) {
		next = TAILQ_NEXT(coro, list);
		TAILQ_REMOVE(&op->coroutines, coro, list);

		/* Make sure we don't end up in pygather_reap_coro(). */
		coro->coro->gatherop = NULL;

		kore_python_coro_delete(coro->coro);
		kore_pool_put(&gather_coro_pool, coro);
	}

	coro_running = old;

	for (res = TAILQ_FIRST(&op->results); res != NULL; res = rnext) {
		rnext = TAILQ_NEXT(res, list);
		TAILQ_REMOVE(&op->results, res, list);

		Py_DECREF(res->obj);
		kore_pool_put(&gather_result_pool, res);
	}

	PyObject_Del((PyObject *)op);
}

static PyObject *
pygather_op_await(PyObject *obj)
{
	Py_INCREF(obj);
	return (obj);
}

static PyObject *
pygather_op_iternext(struct pygather_op *op)
{
	int				idx;
	struct pygather_result		*res, *next;
	PyObject			*list, *obj;

	if (!TAILQ_EMPTY(&op->coroutines)) {
		Py_RETURN_NONE;
	}

	if ((list = PyList_New(op->count)) == NULL)
		return (NULL);

	idx = 0;

	for (res = TAILQ_FIRST(&op->results); res != NULL; res = next) {
		next = TAILQ_NEXT(res, list);
		TAILQ_REMOVE(&op->results, res, list);

		obj = res->obj;
		res->obj = NULL;
		kore_pool_put(&gather_result_pool, res);

		if (PyList_SetItem(list, idx++, obj) != 0) {
			Py_DECREF(list);
			return (NULL);
		}
	}

	PyErr_SetObject(PyExc_StopIteration, list);
	Py_DECREF(list);

	return (NULL);
}

static PyObject *
pyhttp_request_alloc(const struct http_request *req)
{
	union { const void *cp; void *p; }	ptr;
	struct pyhttp_request			*pyreq;

	pyreq = PyObject_New(struct pyhttp_request, &pyhttp_request_type);
	if (pyreq == NULL)
		return (NULL);

	/*
	 * Hack around all http apis taking a non-const pointer and us having
	 * a const pointer for the req data structure. This is because we
	 * could potentially be called from a validator where the argument
	 * is a http_request pointer.
	 */
	ptr.cp = req;
	pyreq->req = ptr.p;
	pyreq->data = NULL;

	return ((PyObject *)pyreq);
}

static PyObject *
pyhttp_file_alloc(struct http_file *file)
{
	struct pyhttp_file		*pyfile;

	pyfile = PyObject_New(struct pyhttp_file, &pyhttp_file_type);
	if (pyfile == NULL)
		return (NULL);

	pyfile->file = file;

	return ((PyObject *)pyfile);
}

static PyObject *
pyhttp_response(struct pyhttp_request *pyreq, PyObject *args)
{
	const char		*body;
	int			status, len;

	len = -1;

	if (!PyArg_ParseTuple(args, "iy#", &status, &body, &len))
		return (NULL);

	if (len < 0) {
		PyErr_SetString(PyExc_TypeError, "invalid length");
		return (NULL);
	}

	http_response(pyreq->req, status, body, len);

	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_response_header(struct pyhttp_request *pyreq, PyObject *args)
{
	const char		*header, *value;

	if (!PyArg_ParseTuple(args, "ss", &header, &value))
		return (NULL);

	http_response_header(pyreq->req, header, value);

	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_request_header(struct pyhttp_request *pyreq, PyObject *args)
{
	const char		*value;
	const char		*header;
	PyObject		*result;

	if (!PyArg_ParseTuple(args, "s", &header))
		return (NULL);

	if (!http_request_header(pyreq->req, header, &value)) {
		Py_RETURN_NONE;
	}

	if ((result = PyUnicode_FromString(value)) == NULL)
		return (PyErr_NoMemory());

	return (result);
}

static PyObject *
pyhttp_body_read(struct pyhttp_request *pyreq, PyObject *args)
{
	ssize_t			ret;
	size_t			len;
	Py_ssize_t		pylen;
	PyObject		*result;
	u_int8_t		buf[1024];

	if (!PyArg_ParseTuple(args, "n", &pylen) || pylen < 0)
		return (NULL);

	len = (size_t)pylen;
	if (len > sizeof(buf)) {
		PyErr_SetString(PyExc_RuntimeError, "len > sizeof(buf)");
		return (NULL);
	}

	ret = http_body_read(pyreq->req, buf, len);
	if (ret == -1) {
		PyErr_SetString(PyExc_RuntimeError, "http_body_read() failed");
		return (NULL);
	}

	if (ret > INT_MAX) {
		PyErr_SetString(PyExc_RuntimeError, "ret > INT_MAX");
		return (NULL);
	}

	result = Py_BuildValue("ny#", ret, buf, (int)ret);
	if (result == NULL)
		return (PyErr_NoMemory());

	return (result);
}

static PyObject *
pyhttp_populate_get(struct pyhttp_request *pyreq, PyObject *args)
{
	http_populate_get(pyreq->req);
	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_populate_post(struct pyhttp_request *pyreq, PyObject *args)
{
	http_populate_post(pyreq->req);
	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_populate_multi(struct pyhttp_request *pyreq, PyObject *args)
{
	http_populate_multipart_form(pyreq->req);
	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_populate_cookies(struct pyhttp_request *pyreq, PyObject *args)
{
	http_populate_cookies(pyreq->req);
	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_argument(struct pyhttp_request *pyreq, PyObject *args)
{
	const char	*name;
	PyObject	*value;
	char		*string;

	if (!PyArg_ParseTuple(args, "s", &name))
		return (NULL);

	if (!http_argument_get_string(pyreq->req, name, &string)) {
		Py_RETURN_NONE;
	}

	if ((value = PyUnicode_FromString(string)) == NULL)
		return (PyErr_NoMemory());

	return (value);
}

static PyObject *
pyhttp_cookie(struct pyhttp_request *pyreq, PyObject *args)
{
	const char	*name;
	PyObject	*value;
	char		*string;

	if (!PyArg_ParseTuple(args, "s", &name))
		return (NULL);

	if (!http_request_cookie(pyreq->req, name, &string)) {
		Py_RETURN_NONE;
	}

	if ((value = PyUnicode_FromString(string)) == NULL)
		return (PyErr_NoMemory());

	return (value);
}

static PyObject *
pyhttp_file_lookup(struct pyhttp_request *pyreq, PyObject *args)
{
	const char		*name;
	struct http_file	*file;
	PyObject		*pyfile;

	if (!PyArg_ParseTuple(args, "s", &name))
		return (NULL);

	if ((file = http_file_lookup(pyreq->req, name)) == NULL) {
		Py_RETURN_NONE;
	}

	if ((pyfile = pyhttp_file_alloc(file)) == NULL)
		return (PyErr_NoMemory());

	return (pyfile);
}

static PyObject *
pyhttp_file_read(struct pyhttp_file *pyfile, PyObject *args)
{
	ssize_t			ret;
	size_t			len;
	Py_ssize_t		pylen;
	PyObject		*result;
	u_int8_t		buf[1024];

	if (!PyArg_ParseTuple(args, "n", &pylen) || pylen < 0)
		return (NULL);

	len = (size_t)pylen;
	if (len > sizeof(buf)) {
		PyErr_SetString(PyExc_RuntimeError, "len > sizeof(buf)");
		return (NULL);
	}

	ret = http_file_read(pyfile->file, buf, len);
	if (ret == -1) {
		PyErr_SetString(PyExc_RuntimeError, "http_file_read() failed");
		return (NULL);
	}

	if (ret > INT_MAX) {
		PyErr_SetString(PyExc_RuntimeError, "ret > INT_MAX");
		return (NULL);
	}

	result = Py_BuildValue("ny#", ret, buf, (int)ret);
	if (result == NULL)
		return (PyErr_NoMemory());

	return (result);
}

static PyObject *
pyhttp_websocket_handshake(struct pyhttp_request *pyreq, PyObject *args)
{
	const char	*onconnect, *onmsg, *ondisconnect;

	if (!PyArg_ParseTuple(args, "sss", &onconnect, &onmsg, &ondisconnect))
		return (NULL);

	kore_websocket_handshake(pyreq->req, onconnect, onmsg, ondisconnect);

	Py_RETURN_TRUE;
}

static PyObject *
pyconnection_websocket_send(struct pyconnection *pyc, PyObject *args)
{
	const char	*data;
	int		op, len;

	if (pyc->c->proto != CONN_PROTO_WEBSOCKET) {
		PyErr_SetString(PyExc_TypeError, "not a websocket connection");
		return (NULL);
	}

	len = -1;

	if (!PyArg_ParseTuple(args, "iy#", &op, &data, &len))
		return (NULL);

	if (len < 0) {
		PyErr_SetString(PyExc_TypeError, "invalid length");
		return (NULL);
	}

	switch (op) {
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
		break;
	default:
		PyErr_SetString(PyExc_TypeError, "invalid op parameter");
		return (NULL);
	}

	kore_websocket_send(pyc->c, op, data, len);

	Py_RETURN_TRUE;
}

static PyObject *
python_websocket_broadcast(PyObject *self, PyObject *args)
{
	struct connection	*c;
	struct pyconnection	*pyc;
	const char		*data;
	PyObject		*pysrc;
	int			op, broadcast, len;

	len = -1;

	if (!PyArg_ParseTuple(args, "Oiy#i", &pysrc, &op, &data, &len,
	    &broadcast))
		return (NULL);

	if (len < 0) {
		PyErr_SetString(PyExc_TypeError, "invalid length");
		return (NULL);
	}

	switch (op) {
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
		break;
	default:
		PyErr_SetString(PyExc_TypeError, "invalid op parameter");
		return (NULL);
	}

	if (pysrc == Py_None) {
		c = NULL;
	} else {
		if (!PyObject_TypeCheck(pysrc, &pyconnection_type))
			return (NULL);
		pyc = (struct pyconnection *)pysrc;
		c = pyc->c;
	}

	kore_websocket_broadcast(c, op, data, len, broadcast);

	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_get_host(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*host;

	if ((host = PyUnicode_FromString(pyreq->req->host)) == NULL)
		return (PyErr_NoMemory());

	return (host);
}

static PyObject *
pyhttp_get_path(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*path;

	if ((path = PyUnicode_FromString(pyreq->req->path)) == NULL)
		return (PyErr_NoMemory());

	return (path);
}

static PyObject *
pyhttp_get_body(struct pyhttp_request *pyreq, void *closure)
{
	ssize_t			ret;
	struct kore_buf		buf;
	PyObject		*body;
	u_int8_t		data[BUFSIZ];

	kore_buf_init(&buf, 1024);
	if (!http_body_rewind(pyreq->req)) {
		PyErr_SetString(PyExc_RuntimeError,
		    "http_body_rewind() failed");
		return (NULL);
	}

	for (;;) {
		ret = http_body_read(pyreq->req, data, sizeof(data));
		if (ret == -1) {
			kore_buf_cleanup(&buf);
			PyErr_SetString(PyExc_RuntimeError,
			    "http_body_read() failed");
			return (NULL);
		}

		if (ret == 0)
			break;

		kore_buf_append(&buf, data, (size_t)ret);
	}

	body = PyBytes_FromStringAndSize((char *)buf.data, buf.offset);
	kore_buf_free(&buf);

	if (body == NULL)
		return (PyErr_NoMemory());

	return (body);
}

static PyObject *
pyhttp_get_agent(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*agent;

	if (pyreq->req->agent == NULL) {
		Py_RETURN_NONE;
	}

	if ((agent = PyUnicode_FromString(pyreq->req->path)) == NULL)
		return (PyErr_NoMemory());

	return (agent);
}

static PyObject *
pyhttp_get_method(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*method;

	if ((method = PyLong_FromUnsignedLong(pyreq->req->method)) == NULL)
		return (PyErr_NoMemory());

	return (method);
}

static PyObject *
pyhttp_get_body_path(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*path;

	if (pyreq->req->http_body_path == NULL) {
		Py_RETURN_NONE;
	}

	if ((path = PyUnicode_FromString(pyreq->req->http_body_path)) == NULL)
		return (PyErr_NoMemory());

	return (path);
}

static PyObject *
pyhttp_get_connection(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*pyc;

	if (pyreq->req->owner == NULL) {
		Py_RETURN_NONE;
	}

	if ((pyc = pyconnection_alloc(pyreq->req->owner)) == NULL)
		return (PyErr_NoMemory());

	return (pyc);
}

static PyObject *
pyhttp_file_get_name(struct pyhttp_file *pyfile, void *closure)
{
	PyObject	*name;

	if ((name = PyUnicode_FromString(pyfile->file->name)) == NULL)
		return (PyErr_NoMemory());

	return (name);
}

static PyObject *
pyhttp_file_get_filename(struct pyhttp_file *pyfile, void *closure)
{
	PyObject	*name;

	if ((name = PyUnicode_FromString(pyfile->file->filename)) == NULL)
		return (PyErr_NoMemory());

	return (name);
}

#if defined(KORE_USE_PGSQL)
static void
pykore_pgsql_dealloc(struct pykore_pgsql *pysql)
{
	kore_free(pysql->db);
	kore_free(pysql->query);
	kore_pgsql_cleanup(&pysql->sql);

	if (pysql->result != NULL)
		Py_DECREF(pysql->result);

	PyObject_Del((PyObject *)pysql);
}

static PyObject *
pykore_pgsql_alloc(struct http_request *req, const char *db, const char *query)
{
	struct pykore_pgsql	*pysql;

	pysql = PyObject_New(struct pykore_pgsql, &pykore_pgsql_type);
	if (pysql == NULL)
		return (NULL);

	pysql->req = req;
	pysql->result = NULL;
	pysql->db = kore_strdup(db);
	pysql->query = kore_strdup(query);
	pysql->state = PYKORE_PGSQL_PREINIT;

	memset(&pysql->sql, 0, sizeof(pysql->sql));

	return ((PyObject *)pysql);
}

static PyObject *
pykore_pgsql_iternext(struct pykore_pgsql *pysql)
{
	switch (pysql->state) {
	case PYKORE_PGSQL_PREINIT:
		kore_pgsql_init(&pysql->sql);
		kore_pgsql_bind_request(&pysql->sql, pysql->req);
		pysql->state = PYKORE_PGSQL_INITIALIZE;
		/* fallthrough */
	case PYKORE_PGSQL_INITIALIZE:
		if (!kore_pgsql_setup(&pysql->sql, pysql->db,
		    KORE_PGSQL_ASYNC)) {
			if (pysql->sql.state == KORE_PGSQL_STATE_INIT)
				break;
			kore_pgsql_logerror(&pysql->sql);
			PyErr_SetString(PyExc_RuntimeError, "pgsql error");
			return (NULL);
		}
		/* fallthrough */
	case PYKORE_PGSQL_QUERY:
		if (!kore_pgsql_query(&pysql->sql, pysql->query)) {
			kore_pgsql_logerror(&pysql->sql);
			PyErr_SetString(PyExc_RuntimeError, "pgsql error");
			return (NULL);
		}
		pysql->state = PYKORE_PGSQL_WAIT;
		break;
wait_again:
	case PYKORE_PGSQL_WAIT:
		switch (pysql->sql.state) {
		case KORE_PGSQL_STATE_WAIT:
			break;
		case KORE_PGSQL_STATE_COMPLETE:
			PyErr_SetNone(PyExc_StopIteration);
			if (pysql->result != NULL) {
				PyErr_SetObject(PyExc_StopIteration,
				    pysql->result);
				Py_DECREF(pysql->result);
			} else {
				PyErr_SetObject(PyExc_StopIteration, Py_None);
			}
			return (NULL);
		case KORE_PGSQL_STATE_ERROR:
			kore_pgsql_logerror(&pysql->sql);
			PyErr_SetString(PyExc_RuntimeError,
			    "failed to perform query");
			return (NULL);
		case KORE_PGSQL_STATE_RESULT:
			if (!pykore_pgsql_result(pysql))
				return (NULL);
			goto wait_again;
		default:
			kore_pgsql_continue(&pysql->sql);
			goto wait_again;
		}
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "bad pykore_pgsql state");
		return (NULL);
	}

	/* tell caller to wait. */
	Py_RETURN_NONE;
}

static PyObject *
pykore_pgsql_await(PyObject *obj)
{
	Py_INCREF(obj);
	return (obj);
}

int
pykore_pgsql_result(struct pykore_pgsql *pysql)
{
	const char	*val;
	char		key[64];
	PyObject	*list, *pyrow, *pyval;
	int		rows, row, field, fields;

	if ((list = PyList_New(0)) == NULL) {
		PyErr_SetNone(PyExc_MemoryError);
		return (KORE_RESULT_ERROR);
	}

	rows = kore_pgsql_ntuples(&pysql->sql);
	fields = kore_pgsql_nfields(&pysql->sql);

	for (row = 0; row < rows; row++) {
		if ((pyrow = PyDict_New()) == NULL) {
			Py_DECREF(list);
			PyErr_SetNone(PyExc_MemoryError);
			return (KORE_RESULT_ERROR);
		}

		for (field = 0; field < fields; field++) {
			val = kore_pgsql_getvalue(&pysql->sql, row, field);

			pyval = PyUnicode_FromString(val);
			if (pyval == NULL) {
				Py_DECREF(pyrow);
				Py_DECREF(list);
				PyErr_SetNone(PyExc_MemoryError);
				return (KORE_RESULT_ERROR);
			}

			(void)snprintf(key, sizeof(key), "%s",
			    kore_pgsql_fieldname(&pysql->sql, field));

			if (PyDict_SetItemString(pyrow, key, pyval) == -1) {
				Py_DECREF(pyval);
				Py_DECREF(pyrow);
				Py_DECREF(list);
				PyErr_SetString(PyExc_RuntimeError,
				    "failed to add new value to row");
				return (KORE_RESULT_ERROR);
			}

			Py_DECREF(pyval);
		}

		if (PyList_Insert(list, row, pyrow) == -1) {
			Py_DECREF(pyrow);
			Py_DECREF(list);
			PyErr_SetString(PyExc_RuntimeError,
			    "failed to add new row to list");
			return (KORE_RESULT_ERROR);
		}

		Py_DECREF(pyrow);
	}

	pysql->result = list;
	kore_pgsql_continue(&pysql->sql);

	return (KORE_RESULT_OK);
}

static PyObject *
pyhttp_pgsql(struct pyhttp_request *pyreq, PyObject *args)
{
	PyObject			*obj;
	const char			*db, *query;

	if (!PyArg_ParseTuple(args, "ss", &db, &query))
		return (NULL);

	if ((obj = pykore_pgsql_alloc(pyreq->req, db, query)) == NULL)
		return (PyErr_NoMemory());

	Py_INCREF(obj);
	pyreq->data = obj;

	return ((PyObject *)obj);
}
#endif
