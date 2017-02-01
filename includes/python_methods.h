/*
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

static PyObject		*python_kore_log(PyObject *, PyObject *);
static PyObject		*python_kore_fatal(PyObject *, PyObject *);
static PyObject		*python_kore_listen(PyObject *, PyObject *);
static PyObject		*python_websocket_send(PyObject *, PyObject *);
static PyObject		*python_websocket_broadcast(PyObject *, PyObject *);

#define METHOD(n, c, a)		{ n, (PyCFunction)c, a, NULL }
#define GETTER(n, g)		{ n, (getter)g, NULL, NULL, NULL }
#define SETTER(n, s)		{ n, NULL, (setter)g, NULL, NULL }
#define GETSET(n, g, s)		{ n, (getter)g, (setter)s, NULL, NULL }

static struct PyMethodDef pykore_methods[] = {
	METHOD("log", python_kore_log, METH_VARARGS),
	METHOD("fatal", python_kore_fatal, METH_VARARGS),
	METHOD("listen", python_kore_listen, METH_VARARGS),
	METHOD("websocket_send", python_websocket_send, METH_VARARGS),
	METHOD("websocket_broadcast", python_websocket_broadcast, METH_VARARGS),
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef pykore_module = {
	PyModuleDef_HEAD_INIT, "kore", NULL, -1, pykore_methods
};

struct pyconnection {
	PyObject_HEAD
	struct connection	*c;
};

static PyMethodDef pyconnection_methods[] = {
	METHOD(NULL, NULL, -1),
};

static PyGetSetDef pyconnection_getset[] = {
	GETTER(NULL, NULL),
};

static void	pyconnection_dealloc(struct pyconnection *);

static PyTypeObject pyconnection_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.connection",
	.tp_doc = "struct connection",
	.tp_getset = pyconnection_getset,
	.tp_methods = pyconnection_methods,
	.tp_basicsize = sizeof(struct pyconnection),
	.tp_dealloc = (destructor)pyconnection_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#if !defined(KORE_NO_HTTP)
struct pyhttp_request {
	PyObject_HEAD
	struct http_request	*req;
};

struct pyhttp_file {
	PyObject_HEAD
	struct http_file	*file;
};

static void	pyhttp_dealloc(struct pyhttp_request *);
static void	pyhttp_file_dealloc(struct pyhttp_file *);

static PyObject	*pyhttp_response(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_argument(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_body_read(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_file_lookup(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_get(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_post(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_multi(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_request_header(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_response_header(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_websocket_handshake(struct pyhttp_request *,
		    PyObject *);

static PyMethodDef pyhttp_request_methods[] = {
	METHOD("response", pyhttp_response, METH_VARARGS),
	METHOD("argument", pyhttp_argument, METH_VARARGS),
	METHOD("body_read", pyhttp_body_read, METH_VARARGS),
	METHOD("file_lookup", pyhttp_file_lookup, METH_VARARGS),
	METHOD("populate_get", pyhttp_populate_get, METH_NOARGS),
	METHOD("populate_post", pyhttp_populate_post, METH_NOARGS),
	METHOD("populate_multi", pyhttp_populate_multi, METH_NOARGS),
	METHOD("request_header", pyhttp_request_header, METH_VARARGS),
	METHOD("response_header", pyhttp_response_header, METH_VARARGS),
	METHOD("websocket_handshake", pyhttp_websocket_handshake, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static int	pyhttp_set_state(struct pyhttp_request *, PyObject *, void *);

static PyObject	*pyhttp_get_host(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_path(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_agent(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_state(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_method(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_connection(struct pyhttp_request *, void *);

static PyGetSetDef pyhttp_request_getset[] = {
	GETTER("host", pyhttp_get_host),
	GETTER("path", pyhttp_get_path),
	GETTER("body", pyhttp_get_body),
	GETTER("agent", pyhttp_get_agent),
	GETTER("method", pyhttp_get_method),
	GETTER("connection", pyhttp_get_connection),
	GETSET("state", pyhttp_get_state, pyhttp_set_state),
	GETTER(NULL, NULL)
};

static PyTypeObject pyhttp_request_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.http_request",
	.tp_doc = "struct http_request",
	.tp_getset = pyhttp_request_getset,
	.tp_methods = pyhttp_request_methods,
	.tp_dealloc = (destructor)pyhttp_dealloc,
	.tp_basicsize = sizeof(struct pyhttp_request),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

static PyObject	*pyhttp_file_read(struct pyhttp_file *, PyObject *);

static PyMethodDef pyhttp_file_methods[] = {
	METHOD("read", pyhttp_file_read, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static PyObject	*pyhttp_file_get_name(struct pyhttp_file *, void *);
static PyObject	*pyhttp_file_get_filename(struct pyhttp_file *, void *);

static PyGetSetDef pyhttp_file_getset[] = {
	GETTER("name", pyhttp_file_get_name),
	GETTER("filename", pyhttp_file_get_filename),
	GETTER(NULL, NULL)
};

static PyTypeObject pyhttp_file_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.http_file",
	.tp_doc = "struct http_file",
	.tp_getset = pyhttp_file_getset,
	.tp_methods = pyhttp_file_methods,
	.tp_dealloc = (destructor)pyhttp_file_dealloc,
	.tp_basicsize = sizeof(struct pyhttp_file),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};
#endif
