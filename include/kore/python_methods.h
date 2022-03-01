/*
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

#define CORO_STATE_RUNNABLE		1
#define CORO_STATE_SUSPENDED		2

struct python_coro {
	u_int64_t			id;
	int				state;
	int				killed;
	PyObject			*obj;
	char				*name;
	PyObject			*result;
	struct pylock_op		*lockop;
	struct pysocket_op		*sockop;
	struct pygather_op		*gatherop;
	struct http_request		*request;
	PyObject			*exception;
	char				*exception_msg;
	TAILQ_ENTRY(python_coro)	list;
};

TAILQ_HEAD(coro_list, python_coro);

static PyObject		*python_kore_app(PyObject *, PyObject *);
static PyObject		*python_kore_log(PyObject *, PyObject *);
static PyObject		*python_kore_time(PyObject *, PyObject *);
static PyObject		*python_kore_lock(PyObject *, PyObject *);
static PyObject		*python_kore_proc(PyObject *, PyObject *);
static PyObject		*python_kore_fatal(PyObject *, PyObject *);
static PyObject		*python_kore_queue(PyObject *, PyObject *);
static PyObject		*python_kore_worker(PyObject *, PyObject *);
static PyObject		*python_kore_tracer(PyObject *, PyObject *);
static PyObject		*python_kore_fatalx(PyObject *, PyObject *);
static PyObject		*python_kore_task_id(PyObject *, PyObject *);
static PyObject		*python_kore_sigtrap(PyObject *, PyObject *);
static PyObject		*python_kore_setname(PyObject *, PyObject *);
static PyObject		*python_kore_suspend(PyObject *, PyObject *);
static PyObject		*python_kore_shutdown(PyObject *, PyObject *);
static PyObject		*python_kore_coroname(PyObject *, PyObject *);
static PyObject		*python_kore_corotrace(PyObject *, PyObject *);
static PyObject		*python_kore_task_kill(PyObject *, PyObject *);
static PyObject		*python_kore_prerequest(PyObject *, PyObject *);
static PyObject		*python_kore_task_create(PyObject *, PyObject *);
static PyObject		*python_kore_socket_wrap(PyObject *, PyObject *);
static PyObject		*python_kore_route(PyObject *, PyObject *, PyObject *);
static PyObject		*python_kore_timer(PyObject *, PyObject *, PyObject *);
static PyObject		*python_kore_domain(PyObject *, PyObject *, PyObject *);
static PyObject		*python_kore_gather(PyObject *, PyObject *, PyObject *);
static PyObject		*python_kore_sendobj(PyObject *, PyObject *,
			    PyObject *);
static PyObject		*python_kore_server(PyObject *, PyObject *,
			    PyObject *);
static PyObject		*python_kore_privsep(PyObject *, PyObject *,
			    PyObject *);


#if defined(KORE_USE_PGSQL)
static PyObject		*python_kore_pgsql_query(PyObject *, PyObject *,
			    PyObject *);
static PyObject		*python_kore_pgsql_register(PyObject *, PyObject *);
#endif

#if defined(KORE_USE_CURL)
static PyObject		*python_kore_curl_handle(PyObject *, PyObject *);
static PyObject		*python_kore_httpclient(PyObject *,
			    PyObject *, PyObject *);
#endif

static PyObject		*python_websocket_broadcast(PyObject *, PyObject *);

#define METHOD(n, c, a)		{ n, (PyCFunction)c, a, NULL }
#define GETTER(n, g)		{ n, (getter)g, NULL, NULL, NULL }
#define SETTER(n, s)		{ n, NULL, (setter)s, NULL, NULL }
#define GETSET(n, g, s)		{ n, (getter)g, (setter)s, NULL, NULL }

static struct PyMethodDef pykore_methods[] = {
	METHOD("app", python_kore_app, METH_VARARGS),
	METHOD("log", python_kore_log, METH_VARARGS),
	METHOD("time", python_kore_time, METH_NOARGS),
	METHOD("lock", python_kore_lock, METH_NOARGS),
	METHOD("proc", python_kore_proc, METH_VARARGS),
	METHOD("queue", python_kore_queue, METH_VARARGS),
	METHOD("worker", python_kore_worker, METH_VARARGS),
	METHOD("tracer", python_kore_tracer, METH_VARARGS),
	METHOD("fatal", python_kore_fatal, METH_VARARGS),
	METHOD("fatalx", python_kore_fatalx, METH_VARARGS),
	METHOD("task_id", python_kore_task_id, METH_NOARGS),
	METHOD("sigtrap", python_kore_sigtrap, METH_VARARGS),
	METHOD("setname", python_kore_setname, METH_VARARGS),
	METHOD("suspend", python_kore_suspend, METH_VARARGS),
	METHOD("shutdown", python_kore_shutdown, METH_NOARGS),
	METHOD("coroname", python_kore_coroname, METH_VARARGS),
	METHOD("corotrace", python_kore_corotrace, METH_VARARGS),
	METHOD("task_kill", python_kore_task_kill, METH_VARARGS),
	METHOD("prerequest", python_kore_prerequest, METH_VARARGS),
	METHOD("task_create", python_kore_task_create, METH_VARARGS),
	METHOD("socket_wrap", python_kore_socket_wrap, METH_VARARGS),
	METHOD("route", python_kore_route, METH_VARARGS | METH_KEYWORDS),
	METHOD("timer", python_kore_timer, METH_VARARGS | METH_KEYWORDS),
	METHOD("domain", python_kore_domain, METH_VARARGS | METH_KEYWORDS),
	METHOD("server", python_kore_server, METH_VARARGS | METH_KEYWORDS),
	METHOD("gather", python_kore_gather, METH_VARARGS | METH_KEYWORDS),
	METHOD("privsep", python_kore_privsep, METH_VARARGS | METH_KEYWORDS),
	METHOD("sendobj", python_kore_sendobj, METH_VARARGS | METH_KEYWORDS),
	METHOD("websocket_broadcast", python_websocket_broadcast, METH_VARARGS),
#if defined(KORE_USE_PGSQL)
	METHOD("dbsetup", python_kore_pgsql_register, METH_VARARGS),
	METHOD("dbquery", python_kore_pgsql_query,
	    METH_VARARGS | METH_KEYWORDS),
#endif
#if defined(KORE_USE_CURL)
	METHOD("curl", python_kore_curl_handle, METH_VARARGS),
	METHOD("httpclient", python_kore_httpclient,
	    METH_VARARGS | METH_KEYWORDS),
#endif
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef pykore_module = {
	PyModuleDef_HEAD_INIT, "kore", NULL, -1, pykore_methods
};

struct pyconfig {
	PyObject_HEAD
};

static int	pyconfig_setattr(PyObject *, PyObject *, PyObject *);

static PyTypeObject pyconfig_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.config",
	.tp_doc = "kore configuration",
	.tp_setattro = pyconfig_setattr,
	.tp_basicsize = sizeof(struct pyconfig),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#if defined(__linux__)
struct pyseccomp {
	PyObject_HEAD
	size_t			elm;
	u_int8_t		*filters;
};

static PyObject	*pyseccomp_allow(struct pyseccomp *, PyObject *);
static PyObject	*pyseccomp_allow_arg(struct pyseccomp *, PyObject *);
static PyObject	*pyseccomp_allow_flag(struct pyseccomp *, PyObject *);
static PyObject	*pyseccomp_allow_mask(struct pyseccomp *, PyObject *);

static PyObject	*pyseccomp_deny(struct pyseccomp *, PyObject *, PyObject *);
static PyObject	*pyseccomp_deny_arg(struct pyseccomp *, PyObject *, PyObject *);
static PyObject	*pyseccomp_deny_flag(struct pyseccomp *,
		    PyObject *, PyObject *);
static PyObject	*pyseccomp_deny_mask(struct pyseccomp *,
		    PyObject *, PyObject *);

static PyObject	*pyseccomp_bpf_stmt(struct pyseccomp *, PyObject *);

static PyMethodDef pyseccomp_methods[] = {
	METHOD("allow", pyseccomp_allow, METH_VARARGS),
	METHOD("bpf_stmt", pyseccomp_bpf_stmt, METH_VARARGS),
	METHOD("allow_arg", pyseccomp_allow_arg, METH_VARARGS),
	METHOD("allow_flag", pyseccomp_allow_flag, METH_VARARGS),
	METHOD("allow_mask", pyseccomp_allow_mask, METH_VARARGS),
	METHOD("deny", pyseccomp_deny, METH_VARARGS | METH_KEYWORDS),
	METHOD("deny_arg", pyseccomp_deny_arg, METH_VARARGS | METH_KEYWORDS),
	METHOD("deny_flag", pyseccomp_deny_flag, METH_VARARGS | METH_KEYWORDS),
	METHOD("deny_mask", pyseccomp_deny_mask, METH_VARARGS | METH_KEYWORDS),
	METHOD(NULL, NULL, -1)
};

static void	pyseccomp_dealloc(struct pyseccomp *);

static PyTypeObject pyseccomp_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.seccomp",
	.tp_doc = "kore seccomp configuration",
	.tp_methods = pyseccomp_methods,
	.tp_basicsize = sizeof(struct pyseccomp),
	.tp_dealloc = (destructor)pyseccomp_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};
#endif

struct pyroute {
	PyObject_HEAD
	char			*path;
	PyObject		*func;
	PyObject		*kwargs;
	struct kore_domain	*domain;
	TAILQ_ENTRY(pyroute)	list;
};

static PyObject	*pyroute_inner(struct pyroute *, PyObject *);
static void	pyroute_dealloc(struct pyroute *);

static PyMethodDef pyroute_methods[] = {
	METHOD("inner", pyroute_inner, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static PyTypeObject pyroute_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.route",
	.tp_doc = "kore route function",
	.tp_methods = pyroute_methods,
	.tp_basicsize = sizeof(struct pyroute),
	.tp_dealloc = (destructor)pyroute_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pydomain {
	PyObject_HEAD
	struct kore_domain		*config;
	struct kore_module_handle	*next;
	PyObject			*kwargs;
};

static PyObject	*pydomain_filemaps(struct pydomain *, PyObject *);
static PyObject	*pydomain_route(struct pydomain *, PyObject *, PyObject *);

static PyMethodDef pydomain_methods[] = {
	METHOD("filemaps", pydomain_filemaps, METH_VARARGS),
	METHOD("route", pydomain_route, METH_VARARGS | METH_KEYWORDS),
	METHOD(NULL, NULL, -1)
};

static int	pydomain_set_accesslog(struct pydomain *, PyObject *, void *);

static PyGetSetDef pydomain_getset[] = {
	SETTER("accesslog", pydomain_set_accesslog),
	SETTER(NULL, NULL),
};

static void	pydomain_dealloc(struct pydomain *);

static PyTypeObject pydomain_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.domain",
	.tp_doc = "kore domain configuration",
	.tp_getset = pydomain_getset,
	.tp_methods = pydomain_methods,
	.tp_basicsize = sizeof(struct pydomain),
	.tp_dealloc = (destructor)pydomain_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#define PYSUSPEND_OP_INIT	1
#define PYSUSPEND_OP_WAIT	2
#define PYSUSPEND_OP_CONTINUE	3

struct pysuspend_op {
	PyObject_HEAD
	int			state;
	int			delay;
	struct python_coro	*coro;
	struct kore_timer	*timer;
};

static void	pysuspend_op_dealloc(struct pysuspend_op *);

static PyObject	*pysuspend_op_await(PyObject *);
static PyObject	*pysuspend_op_iternext(struct pysuspend_op *);

static PyAsyncMethods pysuspend_op_async = {
	(unaryfunc)pysuspend_op_await,
	NULL,
	NULL
};

static PyTypeObject pysuspend_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.suspend",
	.tp_doc = "suspension operation",
	.tp_as_async = &pysuspend_op_async,
	.tp_iternext = (iternextfunc)pysuspend_op_iternext,
	.tp_basicsize = sizeof(struct pysuspend_op),
	.tp_dealloc = (destructor)pysuspend_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pytimer {
	PyObject_HEAD
	int			flags;
	struct kore_timer	*run;
	PyObject		*callable;
	PyObject		*udata;
};

static PyObject	*pytimer_close(struct pytimer *, PyObject *);

static PyMethodDef pytimer_methods[] = {
	METHOD("close", pytimer_close, METH_NOARGS),
	METHOD(NULL, NULL, -1)
};

static void	pytimer_dealloc(struct pytimer *);

static PyTypeObject pytimer_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.timer",
	.tp_doc = "kore timer implementation",
	.tp_methods = pytimer_methods,
	.tp_basicsize = sizeof(struct pytimer),
	.tp_dealloc = (destructor)pytimer_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

/* XXX */
struct pysocket;
struct pysocket_op;

struct pysocket_event {
	struct kore_event	evt;
	struct pysocket		*s;
};

struct pysocket {
	PyObject_HEAD
	int			fd;
	int			family;
	int			protocol;
	int			scheduled;
	PyObject		*socket;
	socklen_t		addr_len;

	struct pysocket_event	event;
	struct pysocket_op	*recvop;
	struct pysocket_op	*sendop;

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_un	sun;
	} addr;
};

static PyObject *pysocket_send(struct pysocket *, PyObject *);
static PyObject *pysocket_recv(struct pysocket *, PyObject *);
static PyObject *pysocket_close(struct pysocket *, PyObject *);
static PyObject *pysocket_accept(struct pysocket *, PyObject *);
static PyObject *pysocket_sendto(struct pysocket *, PyObject *);
static PyObject *pysocket_connect(struct pysocket *, PyObject *);
static PyObject *pysocket_recvmsg(struct pysocket *, PyObject *);
static PyObject *pysocket_recvfrom(struct pysocket *, PyObject *);

static PyMethodDef pysocket_methods[] = {
	METHOD("recv", pysocket_recv, METH_VARARGS),
	METHOD("send", pysocket_send, METH_VARARGS),
	METHOD("close", pysocket_close, METH_NOARGS),
	METHOD("accept", pysocket_accept, METH_NOARGS),
	METHOD("sendto", pysocket_sendto, METH_VARARGS),
	METHOD("connect", pysocket_connect, METH_VARARGS),
	METHOD("recvmsg", pysocket_recvmsg, METH_VARARGS),
	METHOD("recvfrom", pysocket_recvfrom, METH_VARARGS),
	METHOD(NULL, NULL, -1),
};

static void	pysocket_dealloc(struct pysocket *);

static PyTypeObject pysocket_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.socket",
	.tp_doc = "kore socket implementation",
	.tp_methods = pysocket_methods,
	.tp_basicsize = sizeof(struct pysocket),
	.tp_dealloc = (destructor)pysocket_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#define PYSOCKET_TYPE_ACCEPT	1
#define PYSOCKET_TYPE_CONNECT	2
#define PYSOCKET_TYPE_RECV	3
#define PYSOCKET_TYPE_SEND	4
#define PYSOCKET_TYPE_RECVFROM	5
#define PYSOCKET_TYPE_SENDTO	6
#define PYSOCKET_TYPE_RECVMSG	7

struct pysocket_op {
	PyObject_HEAD
	int				eof;
	int				type;
	void				*self;
	struct python_coro		*coro;
	int				state;
	size_t				length;
	struct kore_buf			buffer;
	struct pysocket			*socket;
	struct kore_timer		*timer;

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_un	sun;
	} sendaddr;
};

static void	pysocket_op_dealloc(struct pysocket_op *);

static PyObject	*pysocket_op_await(PyObject *);
static PyObject	*pysocket_op_iternext(struct pysocket_op *);

static PyAsyncMethods pysocket_op_async = {
	(unaryfunc)pysocket_op_await,
	NULL,
	NULL
};

static PyTypeObject pysocket_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.socketop",
	.tp_doc = "socket operation",
	.tp_as_async = &pysocket_op_async,
	.tp_iternext = (iternextfunc)pysocket_op_iternext,
	.tp_basicsize = sizeof(struct pysocket_op),
	.tp_dealloc = (destructor)pysocket_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyqueue_waiting {
	struct python_coro		*coro;
	struct pyqueue_op		*op;
	TAILQ_ENTRY(pyqueue_waiting)	list;
};

struct pyqueue_object {
	PyObject			*obj;
	TAILQ_ENTRY(pyqueue_object)	list;
};

struct pyqueue {
	PyObject_HEAD
	TAILQ_HEAD(, pyqueue_object)	objects;
	TAILQ_HEAD(, pyqueue_waiting)	waiting;
};

static PyObject *pyqueue_pop(struct pyqueue *, PyObject *);
static PyObject *pyqueue_push(struct pyqueue *, PyObject *);
static PyObject *pyqueue_popnow(struct pyqueue *, PyObject *);

static PyMethodDef pyqueue_methods[] = {
	METHOD("pop", pyqueue_pop, METH_NOARGS),
	METHOD("push", pyqueue_push, METH_VARARGS),
	METHOD("popnow", pyqueue_popnow, METH_NOARGS),
	METHOD(NULL, NULL, -1)
};

static void	pyqueue_dealloc(struct pyqueue *);

static PyTypeObject pyqueue_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.queue",
	.tp_doc = "queue",
	.tp_methods = pyqueue_methods,
	.tp_basicsize = sizeof(struct pyqueue),
	.tp_dealloc = (destructor)pyqueue_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyqueue_op {
	PyObject_HEAD
	struct pyqueue		*queue;
	struct pyqueue_waiting	*waiting;
};

static void	pyqueue_op_dealloc(struct pyqueue_op *);

static PyObject	*pyqueue_op_await(PyObject *);
static PyObject	*pyqueue_op_iternext(struct pyqueue_op *);

static PyAsyncMethods pyqueue_op_async = {
	(unaryfunc)pyqueue_op_await,
	NULL,
	NULL
};

static PyTypeObject pyqueue_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.queueop",
	.tp_doc = "queue waitable",
	.tp_as_async = &pyqueue_op_async,
	.tp_iternext = (iternextfunc)pyqueue_op_iternext,
	.tp_basicsize = sizeof(struct pyqueue_op),
	.tp_dealloc = (destructor)pyqueue_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pylock {
	PyObject_HEAD
	struct python_coro		*owner;
	TAILQ_HEAD(, pylock_op)		ops;
};

static PyObject *pylock_aexit(struct pylock *, PyObject *);
static PyObject *pylock_aenter(struct pylock *, PyObject *);
static PyObject *pylock_release(struct pylock *, PyObject *);
static PyObject *pylock_trylock(struct pylock *, PyObject *);

static PyMethodDef pylock_methods[] = {
	METHOD("acquire", pylock_aenter, METH_NOARGS),
	METHOD("release", pylock_release, METH_NOARGS),
	METHOD("trylock", pylock_trylock, METH_NOARGS),
	METHOD("__aexit__", pylock_aexit, METH_VARARGS),
	METHOD("__aenter__", pylock_aenter, METH_NOARGS),
	METHOD(NULL, NULL, -1)
};

static void	pylock_dealloc(struct pylock *);

static PyTypeObject pylock_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.lock",
	.tp_doc = "locking mechanism",
	.tp_methods = pylock_methods,
	.tp_basicsize = sizeof(struct pylock),
	.tp_dealloc = (destructor)pylock_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pylock_op {
	PyObject_HEAD
	int			locking;
	int			active;
	struct pylock		*lock;
	struct python_coro	*coro;
	TAILQ_ENTRY(pylock_op)	list;
};

static void	pylock_op_dealloc(struct pylock_op *);

static PyObject	*pylock_op_await(PyObject *);
static PyObject	*pylock_op_iternext(struct pylock_op *);

static PyAsyncMethods pylock_op_async = {
	(unaryfunc)pylock_op_await,
	NULL,
	NULL
};

static PyTypeObject pylock_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.lockop",
	.tp_doc = "lock awaitable",
	.tp_as_async = &pylock_op_async,
	.tp_iternext = (iternextfunc)pylock_op_iternext,
	.tp_basicsize = sizeof(struct pylock_op),
	.tp_dealloc = (destructor)pylock_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyproc {
	PyObject_HEAD
	pid_t			pid;
	pid_t			apid;
	int			reaped;
	int			status;
	struct pyproc_op	*op;
	struct pysocket		*in;
	struct pysocket		*out;
	struct python_coro	*coro;
	struct kore_timer	*timer;
	TAILQ_ENTRY(pyproc)	list;
};

static void	pyproc_dealloc(struct pyproc *);

static PyObject	*pyproc_kill(struct pyproc *, PyObject *);
static PyObject	*pyproc_reap(struct pyproc *, PyObject *);
static PyObject	*pyproc_recv(struct pyproc *, PyObject *);
static PyObject	*pyproc_send(struct pyproc *, PyObject *);
static PyObject	*pyproc_close_stdin(struct pyproc *, PyObject *);

static PyMethodDef pyproc_methods[] = {
	METHOD("kill", pyproc_kill, METH_NOARGS),
	METHOD("reap", pyproc_reap, METH_NOARGS),
	METHOD("recv", pyproc_recv, METH_VARARGS),
	METHOD("send", pyproc_send, METH_VARARGS),
	METHOD("close_stdin", pyproc_close_stdin, METH_NOARGS),
	METHOD(NULL, NULL, -1),
};

static PyObject	*pyproc_get_pid(struct pyproc *, void *);

static PyGetSetDef pyproc_getset[] = {
	GETTER("pid", pyproc_get_pid),
	GETTER(NULL, NULL),
};

static PyTypeObject pyproc_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.proc",
	.tp_doc = "async process",
	.tp_getset = pyproc_getset,
	.tp_methods = pyproc_methods,
	.tp_basicsize = sizeof(struct pyproc),
	.tp_dealloc = (destructor)pyproc_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyproc_op {
	PyObject_HEAD
	struct pyproc		*proc;
	struct python_coro	*coro;
};

static void	pyproc_op_dealloc(struct pyproc_op *);

static PyObject	*pyproc_op_await(PyObject *);
static PyObject	*pyproc_op_iternext(struct pyproc_op *);

static PyAsyncMethods pyproc_op_async = {
	(unaryfunc)pyproc_op_await,
	NULL,
	NULL
};

static PyTypeObject pyproc_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.proc_op",
	.tp_doc = "proc reaper awaitable",
	.tp_as_async = &pyproc_op_async,
	.tp_iternext = (iternextfunc)pyproc_op_iternext,
	.tp_basicsize = sizeof(struct pyproc_op),
	.tp_dealloc = (destructor)pyproc_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pygather_coro {
	struct python_coro		*coro;
	PyObject			*result;
	TAILQ_ENTRY(pygather_coro)	list;
};

struct pygather_result {
	PyObject			*obj;
	TAILQ_ENTRY(pygather_result)	list;
};

struct pygather_op {
	PyObject_HEAD
	int				count;
	int				running;
	int				concurrency;
	struct python_coro		*coro;
	TAILQ_HEAD(, pygather_result)	results;
	TAILQ_HEAD(, pygather_coro)	coroutines;
};

static void	pygather_op_dealloc(struct pygather_op *);

static PyObject	*pygather_op_await(PyObject *);
static PyObject	*pygather_op_iternext(struct pygather_op *);

static PyAsyncMethods pygather_op_async = {
	(unaryfunc)pygather_op_await,
	NULL,
	NULL
};

static PyTypeObject pygather_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.pygather_op",
	.tp_doc = "coroutine gathering",
	.tp_as_async = &pygather_op_async,
	.tp_iternext = (iternextfunc)pygather_op_iternext,
	.tp_basicsize = sizeof(struct pygather_op),
	.tp_dealloc = (destructor)pygather_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyconnection {
	PyObject_HEAD
	struct connection	*c;
};

static PyObject *pyconnection_disconnect(struct pyconnection *, PyObject *);
static PyObject *pyconnection_websocket_send(struct pyconnection *, PyObject *);

static PyMethodDef pyconnection_methods[] = {
	METHOD("disconnect", pyconnection_disconnect, METH_NOARGS),
	METHOD("websocket_send", pyconnection_websocket_send, METH_VARARGS),
	METHOD(NULL, NULL, -1),
};

static PyObject	*pyconnection_get_fd(struct pyconnection *, void *);
static PyObject	*pyconnection_get_addr(struct pyconnection *, void *);

static PyObject	*pyconnection_get_peer_x509(struct pyconnection *, void *);
static PyObject	*pyconnection_get_peer_x509dict(struct pyconnection *, void *);

static PyGetSetDef pyconnection_getset[] = {
	GETTER("fd", pyconnection_get_fd),
	GETTER("addr", pyconnection_get_addr),
	GETTER("x509", pyconnection_get_peer_x509),
	GETTER("x509dict", pyconnection_get_peer_x509dict),
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

#define PYHTTP_STATE_INIT		0
#define PYHTTP_STATE_PREPROCESS		1
#define PYHTTP_STATE_RUN		2

struct pyhttp_request {
	PyObject_HEAD
	struct http_request	*req;
	PyObject		*dict;
	PyObject		*data;
};

struct pyhttp_iterobj {
	int			remove;
	PyObject		*iterator;
	struct connection	*connection;
	struct kore_buf		buf;
};

struct pyhttp_file {
	PyObject_HEAD
	struct http_file	*file;
};

static void	pyhttp_dealloc(struct pyhttp_request *);
static void	pyhttp_file_dealloc(struct pyhttp_file *);

static PyObject *pyhttp_cookie(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_response(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_argument(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_body_read(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_file_lookup(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_get(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_post(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_multi(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_cookies(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_request_header(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_response_header(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_websocket_handshake(struct pyhttp_request *,
		    PyObject *);

static PyMethodDef pyhttp_request_methods[] = {
	METHOD("cookie", pyhttp_cookie, METH_VARARGS),
	METHOD("response", pyhttp_response, METH_VARARGS),
	METHOD("argument", pyhttp_argument, METH_VARARGS),
	METHOD("body_read", pyhttp_body_read, METH_VARARGS),
	METHOD("file_lookup", pyhttp_file_lookup, METH_VARARGS),
	METHOD("populate_get", pyhttp_populate_get, METH_NOARGS),
	METHOD("populate_post", pyhttp_populate_post, METH_NOARGS),
	METHOD("populate_multi", pyhttp_populate_multi, METH_NOARGS),
	METHOD("populate_cookies", pyhttp_populate_cookies, METH_NOARGS),
	METHOD("request_header", pyhttp_request_header, METH_VARARGS),
	METHOD("response_header", pyhttp_response_header, METH_VARARGS),
	METHOD("websocket_handshake", pyhttp_websocket_handshake, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static PyObject	*pyhttp_get_host(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_path(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_agent(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_method(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_protocol(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body_path(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_connection(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body_digest(struct pyhttp_request *, void *);

static PyGetSetDef pyhttp_request_getset[] = {
	GETTER("host", pyhttp_get_host),
	GETTER("path", pyhttp_get_path),
	GETTER("body", pyhttp_get_body),
	GETTER("agent", pyhttp_get_agent),
	GETTER("method", pyhttp_get_method),
	GETTER("protocol", pyhttp_get_protocol),
	GETTER("body_path", pyhttp_get_body_path),
	GETTER("body_digest", pyhttp_get_body_digest),
	GETTER("connection", pyhttp_get_connection),
	GETTER(NULL, NULL)
};

static PyTypeObject pyhttp_request_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.http_request",
	.tp_doc = "struct http_request",
	.tp_setattro = PyObject_GenericSetAttr,
	.tp_getattro = PyObject_GenericGetAttr,
	.tp_getset = pyhttp_request_getset,
	.tp_methods = pyhttp_request_methods,
	.tp_dealloc = (destructor)pyhttp_dealloc,
	.tp_basicsize = sizeof(struct pyhttp_request),
	.tp_dictoffset = offsetof(struct pyhttp_request, dict),
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

#if defined(KORE_USE_CURL)

#define CURL_CLIENT_OP_RUN	1
#define CURL_CLIENT_OP_RESULT	2

struct pycurl_slist {
	struct curl_slist		*slist;
	LIST_ENTRY(pycurl_slist)	list;
};

struct pycurl_data {
	struct kore_curl		curl;
	LIST_HEAD(, pycurl_slist)	slists;
};

struct pycurl_handle {
	PyObject_HEAD
	char			*url;
	struct kore_buf		*body;
	struct pycurl_data	data;
};

struct pycurl_handle_op {
	PyObject_HEAD
	int			state;
	struct python_coro	*coro;
	struct pycurl_handle	*handle;
};

static PyObject	*pycurl_handle_op_await(PyObject *);
static PyObject	*pycurl_handle_op_iternext(struct pycurl_handle_op *);

static void	pycurl_handle_dealloc(struct pycurl_handle *);
static void	pycurl_handle_op_dealloc(struct pycurl_handle_op *);

static PyObject *pycurl_handle_run(struct pycurl_handle *, PyObject *);
static PyObject *pycurl_handle_setopt(struct pycurl_handle *, PyObject *);
static PyObject *pycurl_handle_setbody(struct pycurl_handle *, PyObject *);

static PyObject *pycurl_handle_setopt_string(struct pycurl_data *,
		    int, PyObject *);
static PyObject *pycurl_handle_setopt_long(struct pycurl_data *,
		    int, PyObject *);
static PyObject *pycurl_handle_setopt_slist(struct pycurl_data *,
		    int, PyObject *);

static PyMethodDef pycurl_handle_methods[] = {
	METHOD("run", pycurl_handle_run, METH_VARARGS),
	METHOD("setopt", pycurl_handle_setopt, METH_VARARGS),
	METHOD("setbody", pycurl_handle_setbody, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static PyTypeObject pycurl_handle_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.curl",
	.tp_doc = "An asynchronous CURL handle",
	.tp_methods = pycurl_handle_methods,
	.tp_basicsize = sizeof(struct pycurl_handle),
	.tp_dealloc = (destructor)pycurl_handle_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

static PyAsyncMethods pycurl_handle_op_async = {
	(unaryfunc)pycurl_handle_op_await,
	NULL,
	NULL
};

static PyTypeObject pycurl_handle_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.curlop",
	.tp_doc = "Asynchronous CURL operation",
	.tp_as_async = &pycurl_handle_op_async,
	.tp_iternext = (iternextfunc)pycurl_handle_op_iternext,
	.tp_basicsize = sizeof(struct pycurl_handle_op),
	.tp_dealloc = (destructor)pycurl_handle_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyhttp_client {
	PyObject_HEAD
	char			*url;
	char			*unix;
	char			*tlskey;
	char			*tlscert;
	char			*cabundle;
	PyObject		*curlopt;
	int			tlsverify;
};

struct pyhttp_client_op {
	PyObject_HEAD
	int			state;
	int			headers;
	struct python_coro	*coro;
	struct pyhttp_client	*client;
	struct pycurl_data	data;
};


static PyObject	*pyhttp_client_op_await(PyObject *);
static PyObject	*pyhttp_client_op_iternext(struct pyhttp_client_op *);

static void	pyhttp_client_dealloc(struct pyhttp_client *);
static void	pyhttp_client_op_dealloc(struct pyhttp_client_op *);

static PyObject *pyhttp_client_get(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_put(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_post(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_head(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_patch(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_delete(struct pyhttp_client *,
		    PyObject *, PyObject *);
static PyObject *pyhttp_client_options(struct pyhttp_client *,
		    PyObject *, PyObject *);

static PyMethodDef pyhttp_client_methods[] = {
	METHOD("get", pyhttp_client_get, METH_VARARGS | METH_KEYWORDS),
	METHOD("put", pyhttp_client_put, METH_VARARGS | METH_KEYWORDS),
	METHOD("post", pyhttp_client_post, METH_VARARGS | METH_KEYWORDS),
	METHOD("head", pyhttp_client_head, METH_VARARGS | METH_KEYWORDS),
	METHOD("patch", pyhttp_client_patch, METH_VARARGS | METH_KEYWORDS),
	METHOD("delete", pyhttp_client_delete, METH_VARARGS | METH_KEYWORDS),
	METHOD("options", pyhttp_client_options, METH_VARARGS | METH_KEYWORDS),
	METHOD(NULL, NULL, -1)
};

static PyTypeObject pyhttp_client_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.httpclient",
	.tp_doc = "An asynchronous HTTP client",
	.tp_methods = pyhttp_client_methods,
	.tp_basicsize = sizeof(struct pyhttp_client),
	.tp_dealloc = (destructor)pyhttp_client_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

static PyAsyncMethods pyhttp_client_op_async = {
	(unaryfunc)pyhttp_client_op_await,
	NULL,
	NULL
};

static PyTypeObject pyhttp_client_op_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.httpclientop",
	.tp_doc = "Asynchronous HTTP client operation",
	.tp_as_async = &pyhttp_client_op_async,
	.tp_iternext = (iternextfunc)pyhttp_client_op_iternext,
	.tp_basicsize = sizeof(struct pyhttp_client_op),
	.tp_dealloc = (destructor)pyhttp_client_op_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};
#endif

#if defined(KORE_USE_PGSQL)

#define PYKORE_PGSQL_PREINIT		1
#define PYKORE_PGSQL_INITIALIZE		2
#define PYKORE_PGSQL_QUERY		3
#define PYKORE_PGSQL_WAIT		4

struct pykore_pgsql {
	PyObject_HEAD
	struct kore_pgsql	sql;
	int			state;
	int			binary;

	char			*db;
	struct python_coro	*coro;
	char			*query;
	PyObject		*result;

	struct {
		int		count;
		const char	**values;
		int		*lengths;
		int		*formats;
		PyObject	**objs;
	} param;
};

static void	pykore_pgsql_dealloc(struct pykore_pgsql *);

static PyObject	*pykore_pgsql_await(PyObject *);
static PyObject	*pykore_pgsql_iternext(struct pykore_pgsql *);

static PyAsyncMethods pykore_pgsql_async = {
	(unaryfunc)pykore_pgsql_await,
	NULL,
	NULL
};

static PyTypeObject pykore_pgsql_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "kore.pgsql",
	.tp_doc = "struct kore_pgsql",
	.tp_as_async = &pykore_pgsql_async,
	.tp_iternext = (iternextfunc)pykore_pgsql_iternext,
	.tp_basicsize = sizeof(struct pykore_pgsql),
	.tp_dealloc = (destructor)pykore_pgsql_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};
#endif
