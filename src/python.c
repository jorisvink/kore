/*
 * Copyright (c) 2016 Stanislav Yudin <stan@endlessinsomnia.com>
 * Copyright (c) 2017 Joris Vink <joris@coders.se>
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

#include <libgen.h>

#include "kore.h"
#include "http.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#include "python_api.h"
#include "python_methods.h"

static PyMODINIT_FUNC	python_module_init(void);
static PyObject		*python_import(const char *);
static void		python_log_error(const char *);
static PyObject		*pyconnection_alloc(struct connection *);
static PyObject		*python_callable(PyObject *, const char *);

static PyObject		*pyhttp_file_alloc(struct http_file *);
static PyObject		*pyhttp_request_alloc(struct http_request *);

#if defined(KORE_USE_PGSQL)
static PyObject		*pykore_pgsql_alloc(struct http_request *,
			    const char *, const char *);
#endif

static void	python_append_path(const char *);
static int	python_coroutine_run(struct http_request *);
static void	python_push_integer(PyObject *, const char *, long);
static void	python_push_type(const char *, PyObject *, PyTypeObject *);

static int	python_runtime_http_request(void *, struct http_request *);
static int	python_runtime_validator(void *, struct http_request *, void *);
static void	python_runtime_wsmessage(void *, struct connection *,
		    u_int8_t, const void *, size_t);
static void	python_runtime_execute(void *);
static int	python_runtime_onload(void *, int);
static void	python_runtime_connect(void *, struct connection *);

static void	python_module_free(struct kore_module *);
static void	python_module_reload(struct kore_module *);
static void	python_module_load(struct kore_module *, const char *);
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
	.execute = python_runtime_execute
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
	{ "CONN_PROTO_HTTP", CONN_PROTO_HTTP },
	{ "CONN_PROTO_UNKNOWN", CONN_PROTO_UNKNOWN },
	{ "CONN_PROTO_WEBSOCKET", CONN_PROTO_WEBSOCKET },
	{ "CONN_STATE_ESTABLISHED", CONN_STATE_ESTABLISHED },
	{ "METHOD_GET", HTTP_METHOD_GET },
	{ "METHOD_PUT", HTTP_METHOD_PUT },
	{ "METHOD_HEAD", HTTP_METHOD_HEAD },
	{ "METHOD_POST", HTTP_METHOD_POST },
	{ "METHOD_DELETE", HTTP_METHOD_DELETE },
	{ "METHOD_OPTIONS", HTTP_METHOD_OPTIONS },
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

void
kore_python_init(void)
{
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
python_log_error(const char *function)
{
	PyObject	*type, *value, *traceback;

	if (!PyErr_Occurred() || PyErr_ExceptionMatches(PyExc_StopIteration))
		return;

	PyErr_Fetch(&type, &value, &traceback);

	if (type == NULL || value == NULL || traceback == NULL) {
		kore_log(LOG_ERR, "unknown python exception in '%s'", function);
		return;
	}

	kore_log(LOG_ERR,
	    "python exception in '%s' - type:%s - value:%s - trace:%s",
	    function,
	    PyUnicode_AsUTF8AndSize(type, NULL),
	    PyUnicode_AsUTF8AndSize(value, NULL),
	    PyUnicode_AsUTF8AndSize(traceback, NULL));

	Py_DECREF(type);
	Py_DECREF(value);
	Py_DECREF(traceback);
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
		python_log_error("python_module_reload");
		return;
	}

	Py_DECREF(module->handle);
	module->handle = handle;
}

static void
python_module_load(struct kore_module *module, const char *onload)
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
python_coroutine_run(struct http_request *req)
{
	PyObject	*item;

	for (;;) {
		PyErr_Clear();
		item = _PyGen_Send((PyGenObject *)req->py_coro, NULL);
		if (item == NULL) {
			python_log_error("coroutine");
			Py_DECREF(req->py_coro);
			req->py_coro = NULL;
			return (KORE_RESULT_OK);
		}

		if (item == Py_None) {
			Py_DECREF(item);
			break;
		}

		Py_DECREF(item);
	}

	return (KORE_RESULT_RETRY);
}

static int
python_runtime_http_request(void *addr, struct http_request *req)
{
	PyObject	*pyret, *pyreq, *args, *callable;

	if (req->py_coro != NULL)
		return (python_coroutine_run(req));

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
		python_log_error("python_runtime_http_request");
		fatal("failed to execute python call");
	}

	if (PyCoro_CheckExact(pyret)) {
		req->py_coro = pyret;
		return (python_coroutine_run(req));
	}

	if (pyret != Py_None)
		fatal("python_runtime_http_request: unexpected return type");

	Py_DECREF(pyret);

	return (KORE_RESULT_OK);
}

static int
python_runtime_validator(void *addr, struct http_request *req, void *data)
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
		python_log_error("python_runtime_validator");
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
		python_log_error("python_runtime_wsconnect");
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
		python_log_error("python_runtime_execute");
		fatal("failed to execute python call");
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
		python_log_error("python_runtime_onload");
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
		python_log_error("python_runtime_connect");
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

	python_push_type("pyconnection", pykore, &pyconnection_type);

	for (i = 0; python_integers[i].symbol != NULL; i++) {
		python_push_integer(pykore, python_integers[i].symbol,
		    python_integers[i].value);
	}

	python_push_type("pyhttp_file", pykore, &pyhttp_file_type);
	python_push_type("pyhttp_request", pykore, &pyhttp_request_type);

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

	if (!PyArg_ParseTuple(args, "ss", &db, &conninfo)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	(void)kore_pgsql_register(db, conninfo);

	Py_RETURN_TRUE;
}
#endif

static PyObject *
python_kore_log(PyObject *self, PyObject *args)
{
	int		prio;
	const char	*message;

	if (!PyArg_ParseTuple(args, "is", &prio, &message)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	kore_log(prio, "%s", message);

	Py_RETURN_TRUE;
}

static PyObject *
python_kore_listen(PyObject *self, PyObject *args)
{
	const char	*ip, *port, *ccb;

	if (!PyArg_ParseTuple(args, "sss", &ip, &port, &ccb)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	if (!strcmp(ccb, ""))
		ccb = NULL;

	if (!kore_server_bind(ip, port, ccb)) {
		PyErr_SetString(PyExc_RuntimeError, "failed to listen");
		return (NULL);
	}

	Py_RETURN_TRUE;
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

	switch (pyc->c->addrtype) {
	case AF_INET:
		ptr = &pyc->c->addr.ipv4.sin_addr;
		break;
	case AF_INET6:
		ptr = &pyc->c->addr.ipv6.sin6_addr;
		break;
	default:
		PyErr_SetString(PyExc_RuntimeError, "invalid addrtype");
		return (NULL);
	}

	if (inet_ntop(pyc->c->addrtype, ptr, addr, sizeof(addr)) == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "inet_ntop failed");
		return (NULL);
	}

	if ((result = PyUnicode_FromString(addr)) == NULL)
		return (PyErr_NoMemory());

	return (result);
}

static PyObject *
pyhttp_request_alloc(struct http_request *req)
{
	struct pyhttp_request		*pyreq;

	pyreq = PyObject_New(struct pyhttp_request, &pyhttp_request_type);
	if (pyreq == NULL)
		return (NULL);

	pyreq->req = req;
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

	if (!PyArg_ParseTuple(args, "iy#", &status, &body, &len)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "ss", &header, &value)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	http_response_header(pyreq->req, header, value);

	Py_RETURN_TRUE;
}

static PyObject *
pyhttp_request_header(struct pyhttp_request *pyreq, PyObject *args)
{
	char			*value;
	const char		*header;
	PyObject		*result;

	if (!PyArg_ParseTuple(args, "s", &header)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "n", &pylen) || pylen < 0) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "s", &name)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "s", &name)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "s", &name)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "n", &pylen) || pylen < 0) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "sss", &onconnect, &onmsg, &ondisconnect)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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

	if (!PyArg_ParseTuple(args, "iy#", &op, &data, &len)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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
	    &broadcast)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

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
		if (!PyObject_TypeCheck(pysrc, &pyconnection_type)) {
			PyErr_SetString(PyExc_TypeError, "invalid parameters");
			return (NULL);
		}
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

	if (!PyArg_ParseTuple(args, "ss", &db, &query)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	if ((obj = pykore_pgsql_alloc(pyreq->req, db, query)) == NULL)
		return (PyErr_NoMemory());

	Py_INCREF(obj);
	pyreq->data = obj;

	return ((PyObject *)obj);
}
#endif
