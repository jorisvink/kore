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

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#include "python_api.h"
#include "python_methods.h"

static PyMODINIT_FUNC	python_module_init(void);
static PyObject		*python_import(const char *);
static void		python_log_error(const char *);
static PyObject		*pyconnection_alloc(struct connection *);
static PyObject		*python_callable(PyObject *, const char *);

#if !defined(KORE_NO_HTTP)
static PyObject		*pyhttp_request_alloc(struct http_request *);
#endif

static void	python_append_path(const char *);
static void	python_push_integer(PyObject *, const char *, long);
static void	python_push_type(const char *, PyObject *, PyTypeObject *);

#if !defined(KORE_NO_HTTP)
static int	python_runtime_http_request(void *, struct http_request *);
static int	python_runtime_validator(void *, struct http_request *, void *);
static void	python_runtime_wsmessage(void *, struct connection *,
		    u_int8_t, const void *, size_t);
#endif
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
#if !defined(KORE_NO_HTTP)
	.http_request = python_runtime_http_request,
	.validator = python_runtime_validator,
	.wsconnect = python_runtime_connect,
	.wsmessage = python_runtime_wsmessage,
	.wsdisconnect = python_runtime_connect,
#endif
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
#if !defined(KORE_NO_HTTP)
	{ "METHOD_GET", HTTP_METHOD_GET },
	{ "METHOD_PUT", HTTP_METHOD_PUT },
	{ "METHOD_HEAD", HTTP_METHOD_HEAD },
	{ "METHOD_POST", HTTP_METHOD_POST },
	{ "METHOD_DELETE", HTTP_METHOD_DELETE },
	{ "WEBSOCKET_OP_TEXT", WEBSOCKET_OP_TEXT },
	{ "WEBSOCKET_OP_BINARY", WEBSOCKET_OP_BINARY },
	{ "WEBSOCKET_BROADCAST_LOCAL", WEBSOCKET_BROADCAST_LOCAL },
	{ "WEBSOCKET_BROADCAST_GLOBAL", WEBSOCKET_BROADCAST_GLOBAL },
#endif
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
	if (Py_IsInitialized())
		Py_Finalize();
}

static void *
python_malloc(void *ctx, size_t len)
{
	return (kore_malloc(len));
}

static void *
python_calloc(void *ctx, size_t memb, size_t len)
{
	void		*ptr;

	ptr = kore_calloc(memb, len);
	memset(ptr, 0, len);

	return (ptr);
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

	if (!PyErr_Occurred())
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

#if !defined(KORE_NO_HTTP)
static void
pyhttp_dealloc(struct pyhttp_request *pyreq)
{
	PyObject_Del((PyObject *)pyreq);
}

static int
python_runtime_http_request(void *addr, struct http_request *req)
{
	int		ret;
	PyObject	*pyret, *pyreq, *args, *callable;

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

	if (!PyLong_Check(pyret))
		fatal("python_runtime_http_request: unexpected return type");

	ret = (int)PyLong_AsLong(pyret);
	if (ret != KORE_RESULT_RETRY)
		Py_XDECREF(req->py_object);

	Py_DECREF(pyret);

	return (ret);
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

	if ((pydata = PyBytes_FromStringAndSize(data, len)) == NULL)
		fatal("python_runtime_wsmessage: PyBytes_FromString failed");

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
#endif

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

#if !defined(KORE_NO_HTTP)
	python_push_type("pyhttp_request", pykore, &pyhttp_request_type);
#endif

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

static PyObject *
python_exported_log(PyObject *self, PyObject *args)
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

#if !defined(KORE_NO_HTTP)
static PyObject *
pyhttp_request_alloc(struct http_request *req)
{
	struct pyhttp_request		*pyreq;

	pyreq = PyObject_New(struct pyhttp_request, &pyhttp_request_type);
	if (pyreq == NULL)
		return (NULL);

	pyreq->req = req;

	return ((PyObject *)pyreq);
}

static PyObject *
pyhttp_response(struct pyhttp_request *pyreq, PyObject *args)
{
	Py_buffer		body;
	int			status;

	if (!PyArg_ParseTuple(args, "iy*", &status, &body)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	http_response(pyreq->req, status, body.buf, body.len);
	PyBuffer_Release(&body);

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
python_websocket_broadcast(PyObject *self, PyObject *args)
{
	struct connection	*c;
	struct pyconnection	*pyc;
	Py_buffer		data;
	PyObject		*pysrc;
	int			op, broadcast;

	if (!PyArg_ParseTuple(args, "Oiy*i", &pysrc, &op, &data, &broadcast)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}

	if (pysrc == Py_None) {
		c = NULL;
	} else {
		if (!PyObject_TypeCheck(pysrc, &pyconnection_type)) {
			PyBuffer_Release(&data);
			PyErr_SetString(PyExc_TypeError, "invalid parameters");
			return (NULL);
		}
		pyc = (struct pyconnection *)pysrc;
		c = pyc->c;
	}

	kore_websocket_broadcast(c, op, data.buf, data.len, broadcast);
	PyBuffer_Release(&data);

	Py_RETURN_TRUE;
}

static PyObject *
python_websocket_send(PyObject *self, PyObject *args)
{
	int			op;
	struct pyconnection	*pyc;
	Py_buffer		data;

	if (!PyArg_ParseTuple(args, "O!iy*",
	    &pyconnection_type, &pyc, &op, &data)) {
		PyErr_SetString(PyExc_TypeError, "invalid parameters");
		return (NULL);
	}


	kore_websocket_send(pyc->c, op, data.buf, data.len);
	PyBuffer_Release(&data);

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

static int
pyhttp_set_state(struct pyhttp_request *pyreq, PyObject *value, void *closure)
{
	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError,
		    "pyhttp_set_state: value is NULL");
		return (-1);
	}

	Py_XDECREF(pyreq->req->py_object);
	pyreq->req->py_object = value;
	Py_INCREF(pyreq->req->py_object);

	return (0);
}

static PyObject *
pyhttp_get_state(struct pyhttp_request *pyreq, void *closure)
{
	if (pyreq->req->py_object == NULL)
		Py_RETURN_NONE;

	Py_INCREF(pyreq->req->py_object);

	return (pyreq->req->py_object);
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
pyhttp_get_connection(struct pyhttp_request *pyreq, void *closure)
{
	PyObject	*pyc;

	if ((pyc = pyconnection_alloc(pyreq->req->owner)) == NULL)
		return (PyErr_NoMemory());

	return (pyc);
}
#endif
