/*
 * Copyright (c) 2016 Stanislav Yudin <stan@endlessinsomnia.com>
 * Copyright (c) 2017-2019 Joris Vink <joris@coders.se>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <ctype.h>
#include <libgen.h>
#include <signal.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_CURL)
#include "curl.h"
#endif

#include "python_api.h"
#include "python_methods.h"

static PyMODINIT_FUNC	python_module_init(void);
static PyObject		*python_import(const char *);
static PyObject		*pyconnection_alloc(struct connection *);
static PyObject		*python_callable(PyObject *, const char *);
static void		python_split_arguments(char *, char **, size_t);

static int		pyhttp_response_sent(struct netbuf *);
static PyObject		*pyhttp_file_alloc(struct http_file *);
static PyObject		*pyhttp_request_alloc(const struct http_request *);

static struct python_coro	*python_coro_create(PyObject *,
				    struct http_request *);
static int			python_coro_run(struct python_coro *);
static void			python_coro_wakeup(struct python_coro *);
static void			python_coro_suspend(struct python_coro *);

static void		pysocket_evt_handle(void *, int);
static void		pysocket_op_timeout(void *, u_int64_t);
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

static int		pyhttp_iterobj_chunk_sent(struct netbuf *);
static int		pyhttp_iterobj_next(struct pyhttp_iterobj *);
static void		pyhttp_iterobj_disconnect(struct connection *);

#if defined(KORE_USE_PGSQL)
static PyObject		*pykore_pgsql_alloc(struct http_request *,
			    const char *, const char *, PyObject *);
static int		pykore_pgsql_params(struct pykore_pgsql *, PyObject *);
#endif

#if defined(KORE_USE_CURL)
static void		python_curl_callback(struct kore_curl *, void *);
static PyObject		*pyhttp_client_request(struct pyhttp_client *, int,
			    PyObject *);
#endif

static void	python_append_path(const char *);
static void	python_push_integer(PyObject *, const char *, long);
static void	python_push_type(const char *, PyObject *, PyTypeObject *);

static int	python_validator_check(PyObject *);
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
static struct kore_pool			iterobj_pool;
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
static PyObject				*python_tracer = NULL;

void
kore_python_init(void)
{
	struct kore_runtime_call	*rcall;

	coro_id = 0;
	coro_count = 0;

	TAILQ_INIT(&procs);
	TAILQ_INIT(&coro_runnable);
	TAILQ_INIT(&coro_suspended);

	kore_pool_init(&coro_pool, "coropool", sizeof(struct python_coro), 100);

	kore_pool_init(&iterobj_pool, "iterobj_pool",
	    sizeof(struct pyhttp_iterobj), 100);
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

	rcall = kore_runtime_getcall("kore_python_preinit");
	if (rcall != NULL) {
		kore_runtime_execute(rcall);
		kore_free(rcall);
	}

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
	struct python_coro	*coro;

	while ((coro = TAILQ_FIRST(&coro_runnable)) != NULL) {
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

	Py_XDECREF(coro->result);
	kore_pool_put(&coro_pool, coro);
}

void
kore_python_log_error(const char *function)
{
	const char	*sval;
	PyObject	*ret, *repr, *type, *value, *traceback;

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
	} else if (python_tracer != NULL) {
		/*
		 * Call the user-supplied tracer callback.
		 */
		ret = PyObject_CallFunctionObjArgs(python_tracer,
		    type, value, traceback, NULL);
		Py_XDECREF(ret);
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

	for (;;) {
		if ((child = waitpid(-1, &status, WNOHANG)) == -1) {
			if (errno == ECHILD)
				return;
			if (errno == EINTR)
				continue;
			kore_log(LOG_NOTICE, "waitpid: %s", errno_s);
			return;
		}

		if (child == 0)
			return;

		proc = NULL;

		TAILQ_FOREACH(proc, &procs, list) {
			if (proc->pid == child)
				break;
		}

		if (proc == NULL)
			continue;

		proc->pid = -1;
		proc->reaped = 1;
		proc->status = status;

		if (proc->timer != NULL) {
			kore_timer_remove(proc->timer);
			proc->timer = NULL;
		}

		if (proc->coro->request != NULL)
			http_request_wakeup(proc->coro->request);
		else
			python_coro_wakeup(proc->coro);
	}
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
python_split_arguments(char *args, char **argv, size_t elm)
{
	size_t		idx;
	char		*p, *line, *end;

	if (elm <= 1)
		fatal("not enough elements (%zu)", elm);

	idx = 0;
	line = args;

	for (p = line; *p != '\0'; p++) {
		if (idx >= elm - 1)
			break;

		if (*p == ' ') {
			*p = '\0';
			if (*line != '\0')
				argv[idx++] = line;
			line = p + 1;
			continue;
		}

		if (*p != '"')
			continue;

		line = p + 1;
		if ((end = strchr(line, '"')) == NULL)
			break;

		*end = '\0';
		argv[idx++] = line;
		line = end + 1;

		while (isspace(*(unsigned char *)line))
			line++;

		p = line;
	}

	if (idx < elm - 1 && *line != '\0')
		argv[idx++] = line;

	argv[idx] = NULL;
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

	coro->result = NULL;
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
	PyObject	*type, *traceback;

	if (coro->state != CORO_STATE_RUNNABLE)
		fatal("non-runnable coro attempted to run");

	coro_running = coro;

	for (;;) {
		PyErr_Clear();

		item = _PyGen_Send((PyGenObject *)coro->obj, NULL);
		if (item == NULL) {
			if (coro->gatherop == NULL && PyErr_Occurred() &&
			    PyErr_ExceptionMatches(PyExc_StopIteration)) {
				PyErr_Fetch(&type, &coro->result, &traceback);
				Py_DECREF(type);
				Py_XDECREF(traceback);
			} else {
				kore_python_log_error("coroutine");
			}

			coro_running = NULL;
			return (KORE_RESULT_OK);
		}

		if (item == Py_None) {
			Py_DECREF(item);
			break;
		}

		Py_DECREF(item);
	}

	python_coro_suspend(coro);
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
python_coro_suspend(struct python_coro *coro)
{
	if (coro->state != CORO_STATE_RUNNABLE)
		return;

	coro->state = CORO_STATE_SUSPENDED;
	TAILQ_REMOVE(&coro_runnable, coro, list);
	TAILQ_INSERT_HEAD(&coro_suspended, coro, list);
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
	int			ret;
	struct python_coro	*coro;
	PyObject		*pyret, *pyreq, *args, *callable, *arg;

	if (req->py_coro != NULL) {
		coro = req->py_coro;
		python_coro_wakeup(coro);
		if (python_coro_run(coro) == KORE_RESULT_OK) {
			ret = python_validator_check(coro->result);
			kore_python_coro_delete(coro);
			req->py_coro = NULL;
			return (ret);
		}

		return (KORE_RESULT_RETRY);
	}

	callable = (PyObject *)addr;

	if (req->flags & HTTP_VALIDATOR_IS_REQUEST) {
		if ((arg = pyhttp_request_alloc(data)) == NULL)
			fatal("%s: pyreq failed", __func__);

		if ((args = PyTuple_New(1)) == NULL)
			fatal("%s: PyTuple_New failed", __func__);

		if (PyTuple_SetItem(args, 0, arg) != 0)
			fatal("%s: PyTuple_SetItem failed", __func__);
	} else {
		if ((pyreq = pyhttp_request_alloc(req)) == NULL)
			fatal("%s: pyreq alloc failed", __func__);

		if ((arg = PyUnicode_FromString(data)) == NULL)
			fatal("python_runtime_validator: PyUnicode failed");

		if ((args = PyTuple_New(2)) == NULL)
			fatal("%s: PyTuple_New failed", __func__);

		if (PyTuple_SetItem(args, 0, pyreq) != 0 ||
		    PyTuple_SetItem(args, 1, arg) != 0)
			fatal("%s: PyTuple_SetItem failed", __func__);
	}

	PyErr_Clear();
	pyret = PyObject_Call(callable, args, NULL);
	Py_DECREF(args);

	if (pyret == NULL) {
		kore_python_log_error("python_runtime_validator");
		fatal("failed to execute python call");
	}

	if (PyCoro_CheckExact(pyret)) {
		coro = python_coro_create(pyret, req);
		req->py_coro = coro;
		if (python_coro_run(coro) == KORE_RESULT_OK) {
			ret = python_validator_check(coro->result);
			kore_python_coro_delete(coro);
			req->py_coro = NULL;
			return (ret);
		}
		http_request_sleep(req);
		return (KORE_RESULT_RETRY);
	}

	ret = python_validator_check(pyret);
	Py_DECREF(pyret);

	return (ret);
}

static int
python_validator_check(PyObject *obj)
{
	int	ret;

	if (obj == NULL)
		return (KORE_RESULT_ERROR);

	if (!PyLong_Check(obj)) {
		kore_log(LOG_WARNING,
		    "invalid return value from authenticator (not an int)");
		ret = KORE_RESULT_ERROR;
	} else {
		ret = (int)PyLong_AsLong(obj);
	}

	switch (ret) {
	case KORE_RESULT_OK:
	case KORE_RESULT_ERROR:
		break;
	default:
		kore_log(LOG_WARNING,
		    "unsupported authenticator return value '%d'", ret);
		ret = KORE_RESULT_ERROR;
		break;
	}

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

#if defined(KORE_USE_CURL)
	python_push_type("pyhttpclient", pykore, &pyhttp_client_type);
#endif

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
python_kore_time(PyObject *self, PyObject *args)
{
	u_int64_t	now;

	now = kore_time_ms();

	return (PyLong_FromUnsignedLongLong(now));
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
python_kore_tracer(PyObject *self, PyObject *args)
{
	PyObject		*obj;

	if (python_tracer != NULL) {
		PyErr_SetString(PyExc_RuntimeError, "tracer already set");
		return (NULL);
	}

	if (!PyArg_ParseTuple(args, "O", &obj))
		return (NULL);

	if (!PyCallable_Check(obj)) {
		PyErr_SetString(PyExc_RuntimeError, "object not callable");
		Py_DECREF(obj);
		return (NULL);
	}

	Py_INCREF(obj);
	python_tracer = obj;

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_gather(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct pygather_op	*op;
	PyObject		*obj;
	struct pygather_coro	*coro;
	Py_ssize_t		sz, idx;
	int			concurrency;

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

	if (kwargs != NULL &&
	    (obj = PyDict_GetItemString(kwargs, "concurrency")) != NULL) {
		if (!PyLong_Check(obj)) {
			PyErr_SetString(PyExc_TypeError,
			    "concurrency level must be an integer");
			return (NULL);
		}

		PyErr_Clear();
		concurrency = (int)PyLong_AsLong(obj);
		if (concurrency == -1 && PyErr_Occurred())
			return (NULL);

		if (concurrency == 0)
			concurrency = sz;
	} else {
		concurrency = sz;
	}

	op = PyObject_New(struct pygather_op, &pygather_op_type);
	if (op == NULL)
		return (NULL);

	op->running = 0;
	op->count = (int)sz;
	op->coro = coro_running;
	op->concurrency = concurrency;

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

		if (idx > concurrency - 1)
			python_coro_suspend(coro->coro);
		else
			op->running++;
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
	char			*copy, *argv[32];
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
		python_split_arguments(copy, argv, 32);
		(void)execve(argv[0], argv, NULL);
		kore_log(LOG_ERR, "kore.proc failed to execute %s (%s)",
		    argv[0], errno_s);
		exit(1);
	}

	close(in_pipe[0]);
	close(out_pipe[1]);

	if (!kore_connection_nonblock(in_pipe[1], 0) ||
	    !kore_connection_nonblock(out_pipe[0], 0))
		fatal("failed to mark kore.proc pipes are non-blocking");

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
	struct stat	st;
	PyObject	*module;
	char		*dir, *file, *copy, *p;

	if (stat(path, &st) == -1)
		fatal("python_import: stat(%s): %s", path, errno_s);

	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
		fatal("python_import: '%s' is not a file or directory", path);

	copy = kore_strdup(path);

	if ((file = basename(copy)) == NULL)
		fatal("basename: %s: %s", path, errno_s);
	if ((dir = dirname(copy)) == NULL)
		fatal("dirname: %s: %s", path, errno_s);

	if ((p = strrchr(file, '.')) != NULL)
		*p = '\0';

	python_append_path(dir);

	if (S_ISDIR(st.st_mode))
		python_append_path(path);

	module = PyImport_ImportModule(file);
	if (module == NULL)
		PyErr_Print();

	kore_free(copy);

	return (module);
}

static PyObject *
python_callable(PyObject *module, const char *symbol)
{
	char		*base, *method;
	PyObject	*res, *obj, *meth;

	res = NULL;
	obj = NULL;
	base = kore_strdup(symbol);

	if ((method = strchr(base, '.')) != NULL)
		*(method)++ = '\0';

	if ((obj = PyObject_GetAttrString(module, base)) == NULL)
		goto out;

	if (method != NULL) {
		if ((meth = PyObject_GetAttrString(obj, method)) == NULL)
			goto out;

		Py_DECREF(obj);
		obj = meth;
	}

	if (!PyCallable_Check(obj))
		goto out;

	res = obj;
	obj = NULL;

out:
	if (obj != NULL)
		Py_DECREF(obj);

	kore_free(base);

	return (res);
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

#if !defined(KORE_NO_TLS)
static PyObject *
pyconnection_get_peer_x509(struct pyconnection *pyc, void *closure)
{
	int			len;
	PyObject		*bytes;
	u_int8_t		*der, *pp;

	if (pyc->c->cert == NULL) {
		Py_RETURN_NONE;
	}

	if ((len = i2d_X509(pyc->c->cert, NULL)) <= 0) {
		PyErr_SetString(PyExc_RuntimeError, "i2d_X509 failed");
		return (NULL);
	}

	der = kore_calloc(1, len);
	pp = der;

	if (i2d_X509(pyc->c->cert, &pp) <= 0) {
		kore_free(der);
		PyErr_SetString(PyExc_RuntimeError, "i2d_X509 failed");
		return (NULL);
	}

	bytes = PyBytes_FromStringAndSize((char *)der, len);
	kore_free(der);

	return (bytes);
}
#endif

static void
pytimer_run(void *arg, u_int64_t now)
{
	PyObject	*ret;
	struct pytimer	*timer = arg;

	PyErr_Clear();
	ret = PyObject_CallObject(timer->callable, NULL);
	Py_XDECREF(ret);

	kore_python_log_error("pytimer_run");

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
	sock->scheduled = 0;

	sock->socket = NULL;
	sock->recvop = NULL;
	sock->sendop = NULL;

	sock->event.s = sock;
	sock->event.evt.flags = 0;
	sock->event.evt.type = KORE_TYPE_PYSOCKET;
	sock->event.evt.handle = pysocket_evt_handle;

	return (sock);
}

static void
pysocket_dealloc(struct pysocket *sock)
{
	if (sock->scheduled && sock->fd != -1) {
		kore_platform_disable_read(sock->fd);
#if !defined(__linux__)
		kore_platform_disable_write(sock->fd);
#endif
	}

	if (sock->socket != NULL) {
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
pysocket_sendto(struct pysocket *sock, PyObject *args)
{
	Py_buffer		buf;
	struct pysocket_op	*op;
	PyObject		*ret;
	int			port;
	const char		*ip, *sockaddr;

	switch (sock->family) {
	case AF_INET:
		if (!PyArg_ParseTuple(args, "siy*", &ip, &port, &buf))
			return (NULL);
		if (port <= 0 || port >= USHRT_MAX) {
			PyErr_SetString(PyExc_RuntimeError, "invalid port");
			return (NULL);
		}
		break;
	case AF_UNIX:
		if (!PyArg_ParseTuple(args, "sy*", &sockaddr, &buf))
			return (NULL);
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "unsupported family");
		return (NULL);
	}

	ret = pysocket_op_create(sock, PYSOCKET_TYPE_SENDTO, buf.buf, buf.len);

	op = (struct pysocket_op *)ret;

	switch (sock->family) {
	case AF_INET:
		op->sendaddr.ipv4.sin_family = AF_INET;
		op->sendaddr.ipv4.sin_port = htons(port);
		op->sendaddr.ipv4.sin_addr.s_addr = inet_addr(ip);
		break;
	case AF_UNIX:
		op->sendaddr.sun.sun_family = AF_UNIX;
		if (kore_strlcpy(op->sendaddr.sun.sun_path, sockaddr,
		    sizeof(op->sendaddr.sun.sun_path)) >=
		    sizeof(op->sendaddr.sun.sun_path)) {
			Py_DECREF(ret);
			PyErr_SetString(PyExc_RuntimeError,
			    "unix socket path too long");
			return (NULL);
		}
		break;
	default:
		Py_DECREF(ret);
		PyErr_SetString(PyExc_RuntimeError, "unsupported family");
		return (NULL);
	}

	return (ret);
}

static PyObject *
pysocket_recv(struct pysocket *sock, PyObject *args)
{
	Py_ssize_t		len;
	struct pysocket_op	*op;
	PyObject		*obj;
	int			timeo;

	timeo = -1;

	if (!PyArg_ParseTuple(args, "n|i", &len, &timeo))
		return (NULL);

	obj = pysocket_op_create(sock, PYSOCKET_TYPE_RECV, NULL, len);
	if (obj == NULL)
		return (NULL);

	op = (struct pysocket_op *)obj;

	if (timeo != -1) {
		op->timer = kore_timer_add(pysocket_op_timeout,
		    timeo, op, KORE_TIMER_ONESHOT);
	}

	return (obj);
}

static PyObject *
pysocket_recvfrom(struct pysocket *sock, PyObject *args)
{
	Py_ssize_t	len;

	if (!PyArg_ParseTuple(args, "n", &len))
		return (NULL);

	return (pysocket_op_create(sock, PYSOCKET_TYPE_RECVFROM, NULL, len));
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
	if (sock->scheduled) {
		sock->scheduled = 0;
		kore_platform_disable_read(sock->fd);
#if !defined(__linux__)
		kore_platform_disable_write(sock->fd);
#endif
	}

	if (sock->socket != NULL) {
		Py_DECREF(sock->socket);
		sock->socket = NULL;
	} else if (sock->fd != -1) {
		(void)close(sock->fd);
	}

	sock->fd = -1;

	Py_RETURN_TRUE;
}

static void
pysocket_op_dealloc(struct pysocket_op *op)
{
	if (op->type == PYSOCKET_TYPE_RECV ||
	    op->type == PYSOCKET_TYPE_RECVFROM ||
	    op->type == PYSOCKET_TYPE_SEND)
		kore_buf_cleanup(&op->buffer);

	switch (op->type) {
	case PYSOCKET_TYPE_RECV:
	case PYSOCKET_TYPE_ACCEPT:
	case PYSOCKET_TYPE_RECVFROM:
		if (op->socket->recvop != op)
			fatal("recvop mismatch");
		op->socket->recvop = NULL;
		break;
	case PYSOCKET_TYPE_SEND:
	case PYSOCKET_TYPE_SENDTO:
	case PYSOCKET_TYPE_CONNECT:
		if (op->socket->sendop != op)
			fatal("sendop mismatch");
		op->socket->sendop = NULL;
		break;
	}

	if (op->timer != NULL) {
		kore_timer_remove(op->timer);
		op->timer = NULL;
	}

	op->coro->sockop = NULL;
	Py_DECREF(op->socket);

	PyObject_Del((PyObject *)op);
}

static PyObject *
pysocket_op_create(struct pysocket *sock, int type, const void *ptr, size_t len)
{
	struct pysocket_op	*op;

	if (coro_running->sockop != NULL)
		fatal("pysocket_op_create: coro has active socketop");

	switch (type) {
	case PYSOCKET_TYPE_RECV:
	case PYSOCKET_TYPE_ACCEPT:
	case PYSOCKET_TYPE_RECVFROM:
		if (sock->recvop != NULL) {
			PyErr_SetString(PyExc_RuntimeError,
			    "only one recv operation can be done per socket");
			return (NULL);
		}
		break;
	case PYSOCKET_TYPE_SEND:
	case PYSOCKET_TYPE_SENDTO:
	case PYSOCKET_TYPE_CONNECT:
		if (sock->sendop != NULL) {
			PyErr_SetString(PyExc_RuntimeError,
			    "only one send operation can be done per socket");
			return (NULL);
		}
		break;
	default:
		fatal("unknown pysocket_op type %u", type);
	}

	op = PyObject_New(struct pysocket_op, &pysocket_op_type);
	if (op == NULL)
		return (NULL);

	op->eof = 0;
	op->self = op;
	op->type = type;
	op->timer = NULL;
	op->socket = sock;
	op->coro = coro_running;

	coro_running->sockop = op;
	Py_INCREF(op->socket);

	switch (type) {
	case PYSOCKET_TYPE_RECV:
	case PYSOCKET_TYPE_RECVFROM:
		sock->recvop = op;
		kore_buf_init(&op->buffer, len);
		break;
	case PYSOCKET_TYPE_SEND:
	case PYSOCKET_TYPE_SENDTO:
		sock->sendop = op;
		kore_buf_init(&op->buffer, len);
		kore_buf_append(&op->buffer, ptr, len);
		kore_buf_reset(&op->buffer);
		break;
	case PYSOCKET_TYPE_ACCEPT:
		sock->recvop = op;
		break;
	case PYSOCKET_TYPE_CONNECT:
		sock->sendop = op;
		break;
	default:
		fatal("unknown pysocket_op type %u", type);
	}

	if (sock->scheduled == 0) {
		sock->scheduled = 1;
		kore_platform_event_all(sock->fd, &sock->event);
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

	if (op->socket->fd == -1) {
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	}

	if (op->eof) {
		if (op->coro->exception != NULL) {
			PyErr_SetString(op->coro->exception,
			    op->coro->exception_msg);
			op->coro->exception = NULL;
			return (NULL);
		}

		if (op->type != PYSOCKET_TYPE_RECV) {
			PyErr_SetString(PyExc_RuntimeError, "socket EOF");
			return (NULL);
		}

		/* Drain the recv socket. */
		op->socket->event.evt.flags |= KORE_EVENT_READ;
		return (pysocket_async_recv(op));
	}

	switch (op->type) {
	case PYSOCKET_TYPE_CONNECT:
		ret = pysocket_async_connect(op);
		break;
	case PYSOCKET_TYPE_ACCEPT:
		ret = pysocket_async_accept(op);
		break;
	case PYSOCKET_TYPE_RECV:
	case PYSOCKET_TYPE_RECVFROM:
		ret = pysocket_async_recv(op);
		break;
	case PYSOCKET_TYPE_SEND:
	case PYSOCKET_TYPE_SENDTO:
		ret = pysocket_async_send(op);
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "invalid op type");
		return (NULL);
	}

	return (ret);
}

static void
pysocket_op_timeout(void *arg, u_int64_t now)
{
	struct pysocket_op	*op = arg;

	op->eof = 1;
	op->timer = NULL;

	op->coro->exception = PyExc_TimeoutError;
	op->coro->exception_msg = "timeout before operation completed";

	if (op->coro->request != NULL)
		http_request_wakeup(op->coro->request);
	else
		python_coro_wakeup(op->coro);
}

static PyObject *
pysocket_async_connect(struct pysocket_op *op)
{
	if (connect(op->socket->fd, (struct sockaddr *)&op->socket->addr,
	    op->socket->addr_len) == -1) {
		if (errno != EALREADY && errno != EINPROGRESS &&
		    errno != EISCONN && errno != EAGAIN) {
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

	if (!(op->socket->event.evt.flags & KORE_EVENT_READ)) {
		Py_RETURN_NONE;
	}

	if ((sock = pysocket_alloc()) == NULL)
		return (NULL);

	sock->addr_len = sizeof(sock->addr);

	if ((fd = accept(op->socket->fd,
	    (struct sockaddr *)&sock->addr, &sock->addr_len)) == -1) {
		Py_DECREF((PyObject *)sock);
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			op->socket->event.evt.flags &= ~KORE_EVENT_READ;
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
	sock->family = op->socket->family;
	sock->protocol = op->socket->protocol;

	PyErr_SetObject(PyExc_StopIteration, (PyObject *)sock);
	Py_DECREF((PyObject *)sock);

	return (NULL);
}

static PyObject *
pysocket_async_recv(struct pysocket_op *op)
{
	ssize_t		ret;
	size_t		len;
	u_int16_t	port;
	socklen_t	socklen;
	struct sockaddr *sendaddr;
	const char	*ptr, *ip;
	PyObject	*bytes, *result, *tuple;

	if (!(op->socket->event.evt.flags & KORE_EVENT_READ)) {
		Py_RETURN_NONE;
	}

	for (;;) {
		if (op->type == PYSOCKET_TYPE_RECV) {
			ret = read(op->socket->fd, op->buffer.data,
			    op->buffer.length);
		} else {
			sendaddr = (struct sockaddr *)&op->sendaddr;
			switch (op->socket->family) {
			case AF_INET:
				socklen = sizeof(op->sendaddr.ipv4);
				break;
			case AF_UNIX:
				socklen = sizeof(op->sendaddr.sun);
				break;
			default:
				fatal("non AF_INET/AF_UNIX in %s", __func__);
			}

			memset(sendaddr, 0, socklen);
			ret = recvfrom(op->socket->fd, op->buffer.data,
			    op->buffer.length, 0, sendaddr, &socklen);
		}

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				op->socket->event.evt.flags &= ~KORE_EVENT_READ;
				Py_RETURN_NONE;
			}
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}

		break;
	}

	op->coro->exception = NULL;
	op->coro->exception_msg = NULL;

	if (op->timer != NULL) {
		kore_timer_remove(op->timer);
		op->timer = NULL;
	}

	if (op->type == PYSOCKET_TYPE_RECV && ret == 0) {
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	}

	ptr = (const char *)op->buffer.data;
	if ((bytes = PyBytes_FromStringAndSize(ptr, ret)) == NULL)
		return (NULL);

	if (op->type == PYSOCKET_TYPE_RECV) {
		PyErr_SetObject(PyExc_StopIteration, bytes);
		Py_DECREF(bytes);
		return (NULL);
	}

	switch(op->socket->family) {
	case AF_INET:
		port = ntohs(op->sendaddr.ipv4.sin_port);
		ip = inet_ntoa(op->sendaddr.ipv4.sin_addr);

		if ((tuple = Py_BuildValue("(sHN)", ip, port, bytes)) == NULL)
			return (NULL);
		break;
	case AF_UNIX:
		len = strlen(op->sendaddr.sun.sun_path);
#if defined(__linux__)
		if (len == 0 && socklen > 0) {
			len = socklen - sizeof(sa_family_t);
			op->sendaddr.sun.sun_path[0] = '@';
			op->sendaddr.sun.sun_path[len] = '\0';
		}
#endif
		if (len == 0) {
			if ((tuple = Py_BuildValue("(ON)",
			    Py_None, bytes)) == NULL)
				return (NULL);
			break;
		}

		if ((tuple = Py_BuildValue("(sN)",
		    op->sendaddr.sun.sun_path, bytes)) == NULL)
			return (NULL);
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "Unsupported family");
		return (NULL);
	}

	result = PyObject_CallFunctionObjArgs(PyExc_StopIteration, tuple, NULL);
	if (result == NULL) {
		Py_DECREF(tuple);
		return (NULL);
	}

	Py_DECREF(tuple);
	PyErr_SetObject(PyExc_StopIteration, result);
	Py_DECREF(result);

	return (NULL);
}

static PyObject *
pysocket_async_send(struct pysocket_op *op)
{
	ssize_t			ret;
	socklen_t		socklen;
	const struct sockaddr	*sendaddr;

	if (!(op->socket->event.evt.flags & KORE_EVENT_WRITE)) {
		Py_RETURN_NONE;
	}

	for (;;) {
		if (op->type == PYSOCKET_TYPE_SEND) {
			ret = write(op->socket->fd,
			    op->buffer.data + op->buffer.offset,
			    op->buffer.length - op->buffer.offset);
		} else {
			sendaddr = (const struct sockaddr *)&op->sendaddr;

			switch (op->socket->family) {
			case AF_INET:
				socklen = sizeof(op->sendaddr.ipv4);
				break;
			case AF_UNIX:
				socklen = sizeof(op->sendaddr.sun);
#if defined(__linux__)
				if (op->sendaddr.sun.sun_path[0] == '@') {
					socklen = sizeof(sa_family_t) +
					    strlen(op->sendaddr.sun.sun_path);
					op->sendaddr.sun.sun_path[0] = '\0';
				}
#endif
				break;
			default:
				fatal("non AF_INET/AF_UNIX in %s", __func__);
			}

			ret = sendto(op->socket->fd,
			    op->buffer.data + op->buffer.offset,
			    op->buffer.length - op->buffer.offset,
			    0, sendaddr, socklen);
		}

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				op->socket->event.evt.flags &=
				    ~KORE_EVENT_WRITE;
				Py_RETURN_NONE;
			}
			PyErr_SetString(PyExc_RuntimeError, errno_s);
			return (NULL);
		}
		break;
	}

	op->buffer.offset += (size_t)ret;

	if (op->buffer.offset == op->buffer.length) {
		PyErr_SetNone(PyExc_StopIteration);
		return (NULL);
	}

	Py_RETURN_NONE;
}

static void
pysocket_evt_handle(void *arg, int eof)
{
	struct pysocket_event		*event = arg;
	struct pysocket			*socket = event->s;

	if ((eof || (event->evt.flags & KORE_EVENT_READ)) &&
	    socket->recvop != NULL) {
		if (socket->recvop->coro->request != NULL)
			http_request_wakeup(socket->recvop->coro->request);
		else
			python_coro_wakeup(socket->recvop->coro);
		socket->recvop->eof = eof;
	}

	if ((eof || (event->evt.flags & KORE_EVENT_WRITE)) &&
	    socket->sendop != NULL) {
		if (socket->sendop->coro->request != NULL)
			http_request_wakeup(socket->sendop->coro->request);
		else
			python_coro_wakeup(socket->sendop->coro);
		socket->sendop->eof = eof;
	}
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
		if (waiting->coro->id == coro_running->id) {
			TAILQ_REMOVE(&op->queue->waiting, waiting, list);
			waiting->op->waiting = NULL;
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

	PyObject_Del((PyObject *)lock);
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

		op->active = 0;
		TAILQ_REMOVE(&op->lock->ops, op, list);

		if (op->coro->request != NULL)
			http_request_wakeup(op->coro->request);
		else
			python_coro_wakeup(op->coro);

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
			/*
			 * We could be beat by another coroutine that grabbed
			 * the lock even if we were the one woken up for it.
			 */
			if (op->active == 0) {
				op->active = 1;
				TAILQ_INSERT_HEAD(&op->lock->ops, op, list);
				Py_INCREF((PyObject *)op);
			}
			Py_RETURN_NONE;
		}

		op->lock->owner = coro_running;
	}

	if (op->active) {
		op->active = 0;
		TAILQ_REMOVE(&op->lock->ops, op, list);
		Py_DECREF((PyObject *)op);
	}

	PyErr_SetNone(PyExc_StopIteration);

	return (NULL);
}

static void
pyproc_timeout(void *arg, u_int64_t now)
{
	struct pyproc	*proc = arg;

	proc->timer = NULL;

	if (proc->coro->sockop != NULL)
		proc->coro->sockop->eof = 1;

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
	Py_ssize_t		len;
	struct pysocket_op	*op;
	PyObject		*obj;
	int			timeo;

	timeo = -1;

	if (proc->out == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "stdout closed");
		return (NULL);
	}

	if (!PyArg_ParseTuple(args, "n|i", &len, &timeo))
		return (NULL);

	obj = pysocket_op_create(proc->out, PYSOCKET_TYPE_RECV, NULL, len);
	if (obj == NULL)
		return (NULL);

	op = (struct pysocket_op *)obj;

	if (timeo != -1) {
		op->timer = kore_timer_add(pysocket_op_timeout,
		    timeo, op, KORE_TIMER_ONESHOT);
	}

	return (obj);
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

	op->running--;
	if (op->running < 0)
		fatal("gatherop: running miscount (%d)", op->running);

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
	struct pygather_coro		*coro;
	struct pygather_result		*res, *next;
	PyObject			*list, *obj;

	if (!TAILQ_EMPTY(&op->coroutines)) {
		if (op->running > 0)
			Py_RETURN_NONE;

		TAILQ_FOREACH(coro, &op->coroutines, list) {
			if (op->running >= op->concurrency)
				break;
			python_coro_wakeup(coro->coro);
			op->running++;
		}

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
	struct connection	*c;
	char			*ptr;
	Py_ssize_t		length;
	int			status;
	struct pyhttp_iterobj	*iterobj;
	PyObject		*obj, *iterator;

	length = -1;

	if (!PyArg_ParseTuple(args, "iO", &status, &obj))
		return (NULL);

	if (PyBytes_CheckExact(obj)) {
		if (PyBytes_AsStringAndSize(obj, &ptr, &length) == -1)
			return (NULL);

		if (length < 0) {
			PyErr_SetString(PyExc_TypeError, "invalid length");
			return (NULL);
		}

		Py_INCREF(obj);

		http_response_stream(pyreq->req, status, ptr, length,
		    pyhttp_response_sent, obj);
	} else if (obj == Py_None) {
		http_response(pyreq->req, status, NULL, 0);
	} else {
		if ((iterator = PyObject_GetIter(obj)) == NULL)
			return (NULL);

		c = pyreq->req->owner;

		iterobj = kore_pool_get(&iterobj_pool);
		iterobj->iterator = iterator;
		iterobj->connection = c;
		iterobj->remove = 0;

		kore_buf_init(&iterobj->buf, 4096);

		c->hdlr_extra = iterobj;
		c->flags |= CONN_IS_BUSY;
		c->disconnect = pyhttp_iterobj_disconnect;

		pyreq->req->flags |= HTTP_REQUEST_NO_CONTENT_LENGTH;
		http_response_header(pyreq->req, "transfer-encoding",
		    "chunked");

		http_response(pyreq->req, status, NULL, 0);
		pyhttp_iterobj_next(iterobj);
	}

	Py_RETURN_TRUE;
}

static int
pyhttp_response_sent(struct netbuf *nb)
{
	PyObject	*data;

	data = nb->extra;
	Py_DECREF(data);

	return (KORE_RESULT_OK);
}

static int
pyhttp_iterobj_next(struct pyhttp_iterobj *iterobj)
{
	struct netbuf		*nb;
	PyObject		*obj;
	const char		*ptr;
	Py_ssize_t		length;

	PyErr_Clear();

	if ((obj = PyIter_Next(iterobj->iterator)) == NULL) {
		if (PyErr_Occurred()) {
			kore_python_log_error("pyhttp_iterobj_next");
			return (KORE_RESULT_ERROR);
		}

		return (KORE_RESULT_OK);
	}

	if ((ptr = PyUnicode_AsUTF8AndSize(obj, &length)) == NULL) {
		kore_python_log_error("pyhttp_iterobj_next");
		return (KORE_RESULT_ERROR);
	}

	kore_buf_reset(&iterobj->buf);
	kore_buf_appendf(&iterobj->buf, "%x\r\n", length);
	kore_buf_append(&iterobj->buf, ptr, length);
	kore_buf_appendf(&iterobj->buf, "\r\n");

	Py_DECREF(obj);

	net_send_stream(iterobj->connection, iterobj->buf.data,
	    iterobj->buf.offset, pyhttp_iterobj_chunk_sent, &nb);

	nb->extra = iterobj;

	return (KORE_RESULT_RETRY);
}

static int
pyhttp_iterobj_chunk_sent(struct netbuf *nb)
{
	int			ret;
	struct pyhttp_iterobj	*iterobj;

	iterobj = nb->extra;

	if (iterobj->remove) {
		ret = KORE_RESULT_ERROR;
	} else {
		ret = pyhttp_iterobj_next(iterobj);
	}

	if (ret != KORE_RESULT_RETRY) {
		iterobj->connection->hdlr_extra = NULL;
		iterobj->connection->disconnect = NULL;
		iterobj->connection->flags &= ~CONN_IS_BUSY;

		if (iterobj->remove == 0)
			http_start_recv(iterobj->connection);

		kore_buf_reset(&iterobj->buf);
		kore_buf_appendf(&iterobj->buf, "0\r\n\r\n");
		net_send_queue(iterobj->connection,
		    iterobj->buf.data, iterobj->buf.offset);

		Py_DECREF(iterobj->iterator);

		kore_buf_cleanup(&iterobj->buf);
		kore_pool_put(&iterobj_pool, iterobj);
	} else {
		ret = KORE_RESULT_OK;
	}

	return (ret);
}

static void
pyhttp_iterobj_disconnect(struct connection *c)
{
	struct pyhttp_iterobj	*iterobj;

	iterobj = c->hdlr_extra;

	iterobj->remove = 1;
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
	Py_ssize_t	i;

	kore_free(pysql->db);
	kore_free(pysql->query);
	kore_pgsql_cleanup(&pysql->sql);

	if (pysql->result != NULL)
		Py_DECREF(pysql->result);

	for (i = 0; i < pysql->param.count; i++)
		Py_XDECREF(pysql->param.objs[i]);

	kore_free(pysql->param.objs);
	kore_free(pysql->param.values);
	kore_free(pysql->param.lengths);
	kore_free(pysql->param.formats);

	PyObject_Del((PyObject *)pysql);
}

static PyObject *
pykore_pgsql_alloc(struct http_request *req, const char *db, const char *query, 
    PyObject *kwargs)
{
	PyObject		*obj;
	struct pykore_pgsql	*pysql;

	pysql = PyObject_New(struct pykore_pgsql, &pykore_pgsql_type);
	if (pysql == NULL)
		return (NULL);

	pysql->req = req;
	pysql->result = NULL;
	pysql->db = kore_strdup(db);
	pysql->query = kore_strdup(query);
	pysql->state = PYKORE_PGSQL_PREINIT;

	pysql->binary = 0;
	pysql->param.count = 0;
	pysql->param.objs = NULL;
	pysql->param.values = NULL;
	pysql->param.lengths = NULL;
	pysql->param.formats = NULL;

	memset(&pysql->sql, 0, sizeof(pysql->sql));

	if (kwargs != NULL) {
		if ((obj = PyDict_GetItemString(kwargs, "params")) != NULL) {
			if (!pykore_pgsql_params(pysql, obj)) {
				Py_DECREF((PyObject *)pysql);
				return (NULL);
			}
		}

		if ((obj = PyDict_GetItemString(kwargs, "binary")) != NULL) {
			if (obj == Py_True) {
				pysql->binary = 1;
			} else if (obj == Py_False) {
				pysql->binary = 0;
			} else {
				Py_DECREF((PyObject *)pysql);
				PyErr_SetString(PyExc_RuntimeError,
				    "pgsql: binary not True or False");
				return (NULL);
			}
		}
	}

	return ((PyObject *)pysql);
}

static int
pykore_pgsql_params(struct pykore_pgsql *op, PyObject *list)
{
	union { const char *cp; char *p; }	ptr;
	PyObject				*item;
	int					format;
	Py_ssize_t				i, len, vlen;

	if (!PyList_CheckExact(list)) {
		if (list == Py_None)
			return (KORE_RESULT_OK);

		PyErr_SetString(PyExc_RuntimeError,
		    "pgsql: params keyword must be a list");
		return (KORE_RESULT_ERROR);
	}

	len = PyList_Size(list);
	if (len == 0)
		return (KORE_RESULT_OK);

	if (len > INT_MAX) {
		PyErr_SetString(PyExc_RuntimeError,
		    "pgsql: list length too large");
		return (KORE_RESULT_ERROR);
	}

	op->param.count = len;
	op->param.lengths = kore_calloc(len, sizeof(int));
	op->param.formats = kore_calloc(len, sizeof(int));
	op->param.values = kore_calloc(len, sizeof(char *));
	op->param.objs = kore_calloc(len, sizeof(PyObject *));

	for (i = 0; i < len; i++) {
		if ((item = PyList_GetItem(list, i)) == NULL)
			return (KORE_RESULT_ERROR);

		if (PyUnicode_CheckExact(item)) {
			format = 0;
			ptr.cp = PyUnicode_AsUTF8AndSize(item, &vlen);
		} else if (PyBytes_CheckExact(item)) {
			format = 1;
			if (PyBytes_AsStringAndSize(item, &ptr.p, &vlen) == -1)
				ptr.p = NULL;
		} else {
			PyErr_Format(PyExc_RuntimeError,
			    "pgsql: item %zu is not a string or bytes", i);
			return (KORE_RESULT_ERROR);
		}

		if (ptr.cp == NULL)
			return (KORE_RESULT_ERROR);

		op->param.lengths[i] = vlen;
		op->param.values[i] = ptr.cp;
		op->param.formats[i] = format;

		/* Hold on to it since we are directly referencing its data. */
		op->param.objs[i] = item;
		Py_INCREF(item);
	}

	return (KORE_RESULT_OK);
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
			PyErr_Format(PyExc_RuntimeError, "pgsql error: %s",
			    pysql->sql.error);
			return (NULL);
		}
		/* fallthrough */
	case PYKORE_PGSQL_QUERY:
		if (!kore_pgsql_query_param_fields(&pysql->sql,
		    pysql->query, pysql->binary,
		    pysql->param.count, pysql->param.values,
		    pysql->param.lengths, pysql->param.formats)) {
			PyErr_Format(PyExc_RuntimeError,
			    "pgsql error: %s", pysql->sql.error);
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
			PyErr_Format(PyExc_RuntimeError,
			    "failed to perform query: %s", pysql->sql.error);
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

static int
pykore_pgsql_result(struct pykore_pgsql *pysql)
{
	const char	*val;
	char		key[64];
	PyObject	*list, *pyrow, *pyval;
	int		rows, row, field, fields, len;

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
			len = kore_pgsql_getlength(&pysql->sql, row, field);

			if (kore_pgsql_column_binary(&pysql->sql, field)) {
				pyval = PyBytes_FromStringAndSize(val, len);
			} else {
				pyval = PyUnicode_FromString(val);
			}

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
pyhttp_pgsql(struct pyhttp_request *pyreq, PyObject *args, PyObject *kwargs)
{
	PyObject			*obj;
	const char			*db, *query;

	if (!PyArg_ParseTuple(args, "ss", &db, &query))
		return (NULL);

	if ((obj = pykore_pgsql_alloc(pyreq->req, db, query, kwargs)) == NULL)
		return (PyErr_NoMemory());

	Py_INCREF(obj);
	pyreq->data = obj;

	return ((PyObject *)obj);
}
#endif

#if defined(KORE_USE_CURL)
static PyObject *
python_kore_httpclient(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject		*obj;
	struct pyhttp_client	*client;
	const char		*url, *v;

	if (!PyArg_ParseTuple(args, "s", &url))
		return (NULL);

	client = PyObject_New(struct pyhttp_client, &pyhttp_client_type);
	if (client == NULL)
		return (NULL);

	client->unix = NULL;
	client->tlskey = NULL;
	client->tlscert = NULL;
	client->cabundle = NULL;

	client->tlsverify = 1;
	client->url = kore_strdup(url);

	if (kwargs != NULL) {
		if ((obj = PyDict_GetItemString(kwargs, "tlscert")) != NULL) {
			if ((v = PyUnicode_AsUTF8(obj)) == NULL) {
				Py_DECREF((PyObject *)client);
				return (NULL);
			}

			client->tlscert = kore_strdup(v);
		}

		if ((obj = PyDict_GetItemString(kwargs, "tlskey")) != NULL) {
			if ((v = PyUnicode_AsUTF8(obj)) == NULL) {
				Py_DECREF((PyObject *)client);
				return (NULL);
			}

			client->tlskey = kore_strdup(v);
		}

		if ((obj = PyDict_GetItemString(kwargs, "cabundle")) != NULL) {
			if ((v = PyUnicode_AsUTF8(obj)) == NULL) {
				Py_DECREF((PyObject *)client);
				return (NULL);
			}

			client->cabundle = kore_strdup(v);
		}

		if ((obj = PyDict_GetItemString(kwargs, "unix")) != NULL) {
			if ((v = PyUnicode_AsUTF8(obj)) == NULL) {
				Py_DECREF((PyObject *)client);
				return (NULL);
			}

			client->unix = kore_strdup(v);
		}

		if ((obj = PyDict_GetItemString(kwargs, "tlsverify")) != NULL) {
			if (obj == Py_True) {
				client->tlsverify = 1;
			} else if (obj == Py_False) {
				client->tlsverify = 0;
			} else {
				Py_DECREF((PyObject *)client);
				PyErr_SetString(PyExc_RuntimeError,
				    "tlsverify not True or False");
				return (NULL);
			}
		}
	}

	if ((client->tlscert != NULL && client->tlskey == NULL) ||
	    (client->tlskey != NULL && client->tlscert == NULL)) {
		Py_DECREF((PyObject *)client);
		PyErr_SetString(PyExc_RuntimeError,
		    "invalid TLS client configuration");
		return (NULL);
	}

	return ((PyObject *)client);
}

static void
pyhttp_client_dealloc(struct pyhttp_client *client)
{
	kore_free(client->url);
	kore_free(client->unix);
	kore_free(client->tlskey);
	kore_free(client->tlscert);
	kore_free(client->cabundle);

	PyObject_Del((PyObject *)client);
}

static PyObject *
pyhttp_client_get(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_GET, kwargs));
}

static PyObject *
pyhttp_client_put(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_PUT, kwargs));
}

static PyObject *
pyhttp_client_post(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_POST, kwargs));
}

static PyObject *
pyhttp_client_head(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_HEAD, kwargs));
}

static PyObject *
pyhttp_client_patch(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_PATCH, kwargs));
}

static PyObject *
pyhttp_client_delete(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_DELETE, kwargs));
}

static PyObject *
pyhttp_client_options(struct pyhttp_client *client, PyObject *args,
    PyObject *kwargs)
{
	return (pyhttp_client_request(client, HTTP_METHOD_OPTIONS, kwargs));
}

static PyObject *
pyhttp_client_request(struct pyhttp_client *client, int m, PyObject *kwargs)
{
	struct pyhttp_client_op		*op;
	char				*ptr;
	const char			*k, *v;
	Py_ssize_t			length, idx;
	PyObject			*data, *headers, *key, *item;

	ptr = NULL;
	length = 0;
	headers = NULL;

	if (kwargs != NULL &&
	    ((headers = PyDict_GetItemString(kwargs, "headers")) != NULL)) {
		if (!PyDict_CheckExact(headers)) {
			PyErr_SetString(PyExc_RuntimeError,
			    "header keyword must be a dict");
			return (NULL);
		}
	}

	switch (m) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
	case HTTP_METHOD_DELETE:
	case HTTP_METHOD_OPTIONS:
		break;
	case HTTP_METHOD_PUT:
	case HTTP_METHOD_POST:
	case HTTP_METHOD_PATCH:
		length = -1;

		if (kwargs == NULL) {
			PyErr_Format(PyExc_RuntimeError,
			    "no keyword arguments given, but body expected ",
			    http_method_text(m));
			return (NULL);
		}

		if ((data = PyDict_GetItemString(kwargs, "body")) == NULL)
			return (NULL);

		if (PyBytes_AsStringAndSize(data, &ptr, &length) == -1)
			return (NULL);

		if (length < 0) {
			PyErr_SetString(PyExc_TypeError, "invalid length");
			return (NULL);
		}
		break;
	default:
		fatal("%s: unknown method %d", __func__, m);
	}

	op = PyObject_New(struct pyhttp_client_op, &pyhttp_client_op_type);
	if (op == NULL)
		return (NULL);

	if (!kore_curl_init(&op->curl, client->url)) {
		Py_DECREF((PyObject *)op);
		PyErr_SetString(PyExc_RuntimeError, "failed to setup call");
		return (NULL);
	}

	op->headers = 0;
	op->coro = coro_running;
	op->state = PYHTTP_CLIENT_OP_RUN;

	Py_INCREF(client);

	kore_curl_http_setup(&op->curl, m, ptr, length);
	kore_curl_bind_callback(&op->curl, python_curl_callback, op);

	/* Go in with our own bare hands. */
	if (client->unix != NULL) {
#if defined(__linux__)
		if (client->unix[0] == '@') {
			curl_easy_setopt(op->curl.handle,
			    CURLOPT_ABSTRACT_UNIX_SOCKET, client->unix + 1);
		} else {
			curl_easy_setopt(op->curl.handle,
			    CURLOPT_UNIX_SOCKET_PATH, client->unix);
		}
#else
		curl_easy_setopt(op->curl.handle, CURLOPT_UNIX_SOCKET_PATH,
		    client->unix);
#endif
	}

	if (client->tlskey != NULL && client->tlscert != NULL) {
		 curl_easy_setopt(op->curl.handle, CURLOPT_SSLCERT,
		    client->tlscert);
		 curl_easy_setopt(op->curl.handle, CURLOPT_SSLKEY,
		    client->tlskey);
	}

	if (client->tlsverify == 0) {
		curl_easy_setopt(op->curl.handle, CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt(op->curl.handle, CURLOPT_SSL_VERIFYPEER, 0);
	}

	if (client->cabundle != NULL) {
		curl_easy_setopt(op->curl.handle, CURLOPT_CAINFO,
		    client->cabundle);
	}

	if (headers != NULL) {
		idx = 0;
		while (PyDict_Next(headers, &idx, &key, &item)) {
			if ((k = PyUnicode_AsUTF8(key)) == NULL) {
				Py_DECREF((PyObject *)op);
				return (NULL);
			}

			if ((v = PyUnicode_AsUTF8(item)) == NULL) {
				Py_DECREF((PyObject *)op);
				return (NULL);
			}

			kore_curl_http_set_header(&op->curl, k, v);
		}
	}

	if (kwargs != NULL &&
	    ((item = PyDict_GetItemString(kwargs, "return_headers")) != NULL)) {
		if (item == Py_True) {
			op->headers = 1;
		} else if (item == Py_False) {
			op->headers = 0;
		} else {
			Py_DECREF((PyObject *)op);
			PyErr_SetString(PyExc_RuntimeError,
			    "return_headers not True or False");
			return (NULL);
		}
	}

	return ((PyObject *)op);
}

static void
pyhttp_client_op_dealloc(struct pyhttp_client_op *op)
{
	kore_curl_cleanup(&op->curl);
	PyObject_Del((PyObject *)op);
}

static PyObject *
pyhttp_client_op_await(PyObject *op)
{
	Py_INCREF(op);
	return (op);
}

static PyObject *
pyhttp_client_op_iternext(struct pyhttp_client_op *op)
{
	size_t			len;
	struct http_header	*hdr;
	const u_int8_t		*response;
	PyObject		*result, *tuple, *dict, *value;

	if (op->state == PYHTTP_CLIENT_OP_RUN) {
		kore_curl_run(&op->curl);
		op->state = PYHTTP_CLIENT_OP_RESULT;
		Py_RETURN_NONE;
	}

	if (!kore_curl_success(&op->curl)) {
		PyErr_Format(PyExc_RuntimeError, "request to '%s' failed: %s",
		    op->curl.url, op->curl.errbuf);
		return (NULL);
	}

	kore_curl_response_as_bytes(&op->curl, &response, &len);

	if (op->headers) {
		kore_curl_http_parse_headers(&op->curl);

		if ((dict = PyDict_New()) == NULL)
			return (NULL);

		TAILQ_FOREACH(hdr, &op->curl.http.resp_hdrs, list) {
			value = PyUnicode_FromString(hdr->value);
			if (value == NULL) {
				Py_DECREF(dict);
				return (NULL);
			}

			if (PyDict_SetItemString(dict,
			    hdr->header, value) == -1) {
				Py_DECREF(dict);
				Py_DECREF(value);
				return (NULL);
			}

			Py_DECREF(value);
		}

		if ((tuple = Py_BuildValue("(iOy#)", op->curl.http.status,
		    dict, (const char *)response, len)) == NULL)
			return (NULL);

		Py_DECREF(dict);
	} else {
		if ((tuple = Py_BuildValue("(iy#)", op->curl.http.status,
		    (const char *)response, len)) == NULL)
			return (NULL);
	}

	result = PyObject_CallFunctionObjArgs(PyExc_StopIteration, tuple, NULL);
	if (result == NULL) {
		Py_DECREF(tuple);
		return (NULL);
	}

	Py_DECREF(tuple);
	PyErr_SetObject(PyExc_StopIteration, result);
	Py_DECREF(result);

	return (NULL);
}

static void
python_curl_callback(struct kore_curl *curl, void *arg)
{
	struct pyhttp_client_op		*op = arg;

	if (op->coro->request != NULL)
		http_request_wakeup(op->coro->request);
	else
		python_coro_wakeup(op->coro);
}
#endif
