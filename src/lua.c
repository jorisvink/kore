/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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

#include "kore.h"

#if !defined(KORE_NO_HTTP)
#include "http.h"
#endif

#include "lua_api.h"
#include "lua_methods.h"

struct lua_http_request {
	struct http_request	*req;
};

struct lua_symbol {
	lua_State		*L;
	int			ref;
	LIST_ENTRY(lua_symbol)	list;
};

struct lua_module {
	lua_State			*L;
	LIST_HEAD(, lua_symbol)		symbols;
};

static int	lua_runtime_resolve(const char *, const struct stat *);
static int	lua_runtime_http_request(void *, struct http_request *);
static void	lua_runtime_http_request_free(void *, struct http_request *);
static int	lua_runtime_http_body_chunk(void *, struct http_request *,
		    const void *, size_t);
static int	lua_runtime_validator(void *, struct http_request *,
		    const void *);
static void	lua_runtime_wsmessage(void *, struct connection *,
		    u_int8_t, const void *, size_t);
static void	lua_runtime_execute(void *);
static int	lua_runtime_onload(void *, int);
static void	lua_runtime_signal(void *, int);
static void	lua_runtime_configure(void *, int, char **);
static void	lua_runtime_connect(void *, struct connection *);

static void	lua_module_load(struct kore_module *);
static void	lua_module_free(struct kore_module *);
static void	lua_module_reload(struct kore_module *);
static void	*lua_module_getsym(struct kore_module *, const char *);

static void	*lua_mem_alloc(void *, void *, size_t, size_t);

static int	lua_kore_module_init(lua_State *);
static void	lua_symbol_resolve(struct lua_symbol *, lua_State **);

static int		lua_argument_get_bool(lua_State *, const char *);
static const char	*lua_argument_get_string(lua_State *, const char *);

struct kore_module_functions kore_lua_module = {
	.free = lua_module_free,
	.load = lua_module_load,
	.getsym = lua_module_getsym,
	.reload = lua_module_reload
};

struct kore_runtime kore_lua_runtime = {
	KORE_RUNTIME_LUA,
	.resolve = lua_runtime_resolve,
	.http_request = lua_runtime_http_request,
	.http_body_chunk = lua_runtime_http_body_chunk,
	.http_request_free = lua_runtime_http_request_free,
	.validator = lua_runtime_validator,
	.wsconnect = lua_runtime_connect,
	.wsmessage = lua_runtime_wsmessage,
	.wsdisconnect = lua_runtime_connect,
	.onload = lua_runtime_onload,
	.signal = lua_runtime_signal,
	.connect = lua_runtime_connect,
	.execute = lua_runtime_execute,
	.configure = lua_runtime_configure,
};

#define LUA_CONSTANT(x)		{ #x, x }

static struct {
	const char		*symbol;
	int			value;
} lua_integers[] = {
	LUA_CONSTANT(LOG_ERR),
	LUA_CONSTANT(LOG_INFO),
	LUA_CONSTANT(LOG_NOTICE),
	LUA_CONSTANT(HTTP_METHOD_GET),
	LUA_CONSTANT(HTTP_METHOD_PUT),
	LUA_CONSTANT(HTTP_METHOD_POST),
	LUA_CONSTANT(HTTP_METHOD_HEAD),
	LUA_CONSTANT(HTTP_METHOD_PATCH),
	LUA_CONSTANT(HTTP_METHOD_DELETE),
	LUA_CONSTANT(HTTP_METHOD_OPTIONS),
	{ NULL, -1 },
};

void
kore_lua_init(void)
{
	if (!kore_configure_setting("deployment", "dev"))
		fatal("failed to set initial deployment to dev");
}

void
kore_lua_cleanup(void)
{
}

static void *
lua_mem_alloc(void *uptr, void *ptr, size_t osize, size_t nsize)
{
	if (nsize == 0) {
		kore_free(ptr);
		return (NULL);
	}

	return (kore_realloc(ptr, nsize));
}

static void
lua_symbol_resolve(struct lua_symbol *sym, lua_State **L)
{
	lua_rawgeti(sym->L, LUA_REGISTRYINDEX, sym->ref);
	*L = sym->L;
}

static int
lua_argument_get_bool(lua_State *L, const char *field)
{
	int		ret;

	lua_pushstring(L, field);
	ret = lua_gettable(L, -2);

	if (ret == LUA_TNIL) {
		lua_pop(L, 1);
		return (0);
	}

	luaL_argcheck(L, ret == LUA_TBOOLEAN, 0, field);

	ret = lua_toboolean(L, -1);
	lua_pop(L, 1);

	return (ret);
}

static const char *
lua_argument_get_string(lua_State *L, const char *field)
{
	const char	*v;
	int		type;

	lua_pushstring(L, field);
	type = lua_gettable(L, -2);

	if (type == LUA_TNIL) {
		lua_pop(L, 1);
		return (NULL);
	}

	luaL_argcheck(L, type == LUA_TSTRING, 0, field);

	v = lua_tostring(L, -1);
	lua_pop(L, 1);

	return (v);
}

static int
lua_kore_module_init(lua_State *L)
{
	int		i;

	luaL_newlib(L, lua_kore_functions);

	for (i = 0; lua_integers[i].symbol != NULL; i++) {
		lua_pushstring(L, lua_integers[i].symbol);
		lua_pushnumber(L, lua_integers[i].value);
		lua_settable(L, -3);
	}

	return (1);
}

static void
lua_module_free(struct kore_module *module)
{
	struct lua_symbol	*sym;
	struct lua_module	*lua;

	lua = module->handle;

	while ((sym = LIST_FIRST(&lua->symbols)) != NULL) {
		LIST_REMOVE(sym, list);
		kore_free(sym);
	}

	kore_free(lua);
}

static void
lua_module_reload(struct kore_module *module)
{
	lua_module_free(module);
	lua_module_load(module);
}

static void
lua_module_load(struct kore_module *module)
{
	struct lua_module	*lua;

	lua = kore_calloc(1, sizeof(*lua));
	LIST_INIT(&lua->symbols);

	if ((lua->L = lua_newstate(lua_mem_alloc, NULL)) == NULL)
		fatal("luaL_newstate");

	luaL_openlibs(lua->L);

	luaL_requiref(lua->L, "kore", lua_kore_module_init, 1);
	lua_pop(lua->L, 1);

	luaL_newmetatable(lua->L, "http_request");
	luaL_setfuncs(lua->L, lua_http_request_meta, 0);
	lua_pop(lua->L, 1);

	lua_pushliteral(lua->L, "http_request_methods");
	luaL_newlib(lua->L, lua_http_request_methods);
	lua_settable(lua->L, LUA_REGISTRYINDEX);

	luaL_newlib(lua->L, lua_http_request_methods);
	lua_pop(lua->L, 1);

	if (luaL_loadfile(lua->L, module->path) != LUA_OK) {
		fatal("%s: failed to import module (%s)", module->path,
		    lua_tostring(lua->L, -1));
	}

	if (lua_pcall(lua->L, 0, 0, 0) != LUA_OK) {
		fatal("%s: failed to import module (%s)", module->path,
		    lua_tostring(lua->L, -1));
	}

	module->handle = lua;
}

static void *
lua_module_getsym(struct kore_module *module, const char *symbol)
{
	int			ref;
	struct lua_module	*lua;
	struct lua_symbol	*sym;

	lua = module->handle;

	if (lua_getglobal(lua->L, symbol) != LUA_TFUNCTION)
		return (NULL);

	if ((ref = luaL_ref(lua->L, LUA_REGISTRYINDEX)) == LUA_REFNIL)
		return (NULL);

	sym = kore_calloc(1, sizeof(*sym));

	sym->ref = ref;
	sym->L = lua->L;

	LIST_INSERT_HEAD(&lua->symbols, sym, list);

	return (sym);
}

static int
lua_runtime_resolve(const char *module, const struct stat *st)
{
	const char	*ext;

	if (!S_ISREG(st->st_mode))
		return (KORE_RESULT_ERROR);

	ext = strrchr(module, '.');

	if (ext == NULL || strcasecmp(ext, ".lua"))
		return (KORE_RESULT_ERROR);

	kore_module_load(module, NULL, KORE_MODULE_LUA);

	return (KORE_RESULT_OK);
}

static int
lua_runtime_http_request(void *addr, struct http_request *req)
{
	lua_State			*L;
	struct lua_http_request		*lreq;

	lua_symbol_resolve(addr, &L);

	lreq = lua_newuserdata(L, sizeof(*lreq));
	luaL_setmetatable(L, "http_request");

	lreq->req = req;

	if (lua_pcall(L, 1, 0, 0)) {
		kore_log(LOG_NOTICE, "%s: failed to call handler: %s", __func__,
		    lua_tostring(L, -1));
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	return (KORE_RESULT_OK);
}

static void
lua_runtime_http_request_free(void *addr, struct http_request *req)
{
	fatal("%s: not yet implemented", __func__);
}

static int
lua_runtime_http_body_chunk(void *addr, struct http_request *req,
    const void *data, size_t len)
{
	fatal("%s: not yet implemented", __func__);

	return (KORE_RESULT_ERROR);
}

static int
lua_runtime_validator(void *addr, struct http_request *req, const void *data)
{
	fatal("%s: not yet implemented", __func__);

	return (KORE_RESULT_ERROR);
}

static void
lua_runtime_wsmessage(void *addr, struct connection *c, u_int8_t op,
    const void *data, size_t len)
{
	fatal("%s: not yet implemented", __func__);
}

static void
lua_runtime_execute(void *addr)
{
	lua_State	*L;

	lua_symbol_resolve(addr, &L);

	if (lua_pcall(L, 0, 0, 0)) {
		fatal("failed to execute function: %s",
		    lua_tostring(L, -1));
	}
}

static void
lua_runtime_configure(void *addr, int argc, char **argv)
{
	lua_State	*L;
	int		idx;

	lua_symbol_resolve(addr, &L);

	lua_pushinteger(L, argc);
	lua_newtable(L);

	for (idx = 0; idx < argc; idx++) {
		lua_pushstring(L, argv[idx]);
		lua_rawseti(L, -2, idx);
	}

	if (lua_pcall(L, 2, 0, 0)) {
		fatal("failed to configure your application (%s)",
		    lua_tostring(L, -1));
	}
}

static int
lua_runtime_onload(void *addr, int action)
{
	fatal("%s: not yet implemented", __func__);

	return (KORE_RESULT_ERROR);
}

static void
lua_runtime_connect(void *addr, struct connection *c)
{
	fatal("%s: not yet implemented", __func__);
}

static void
lua_runtime_signal(void *addr, int sig)
{
	fatal("%s: not yet implemented", __func__);
}

static int
lua_kore_config(lua_State *L)
{
	char		*v;
	const char	*opt, *val;

	lua_pushnil(L);

	while (lua_next(L, -2) != 0) {
		if (!lua_isstring(L, -2))
			fatal("kore.config: keyword not a string");

		opt = lua_tostring(L, -2);

		if (lua_isinteger(L, -1)) {
			lua_pushvalue(L, -1);
			val = lua_tostring(L, -1);
			lua_pop(L, 1);
		} else if (lua_isstring(L, -1)) {
			val = lua_tostring(L, -1);
		} else {
			fatal("kore.config: value not a string or integer");
		}

		v = kore_strdup(val);

		if (!kore_configure_setting(opt, v)) {
			kore_free(v);
			luaL_error(L, "kore.config: cannot be set at runtime");
			lua_pop(L, 1);
			return (0);
		}

		kore_free(v);
		lua_pop(L, 1);
	}

	return (0);
}

static int
lua_kore_server(lua_State *L)
{
	struct kore_server	*srv;
	const char		*name, *ip, *port;

	if ((name = lua_argument_get_string(L, "name")) == NULL)
		name = "default";

	if ((ip = lua_argument_get_string(L, "ip")) == NULL) {
		luaL_error(L, "kore.server: missing ip keyword");
		return (0);
	}

	if ((port = lua_argument_get_string(L, "port")) == NULL) {
		luaL_error(L, "kore.server: missing port keyword");
		return (0);
	}

	if ((srv = kore_server_lookup(name)) != NULL) {
		luaL_error(L, "kore.server: server '%s' exists", name);
		return (0);
	}

	srv = kore_server_create(name);
	srv->tls = lua_argument_get_bool(L, "tls");

	if (srv->tls && !kore_tls_supported()) {
		kore_server_free(srv);
		luaL_error(L, "kore.server: TLS not supported");
		return (0);
	}

	if (!kore_server_bind(srv, ip, port, NULL)) {
		kore_server_free(srv);
		luaL_error(L, "kore.server: failed to bind %s:%s", ip, port);
		return (0);
	}

	kore_server_finalize(srv);

	return (0);
}

static int
lua_http_request_gc(lua_State *L)
{
	struct lua_http_request		*lreq;

	lreq = luaL_checkudata(L, 1, "http_request");
	kore_free(lreq);

	return (0);
}

static int
lua_http_request_index(lua_State *L)
{
	struct lua_http_request		*lreq;
	const char			*field;

	lreq = luaL_checkudata(L, 1, "http_request");
	field = luaL_checkstring(L, 2);

	lua_getfield(L, LUA_REGISTRYINDEX, "http_request_methods");
	lua_getfield(L, -1, field);

	if (!lua_isnil(L, -1))
		return (1);

	lua_pop(L, 2);

	if (!strcmp(field, "path")) {
		lua_pushstring(L, lreq->req->path);
		return (1);
	} else if (!strcmp(field, "host")) {
		lua_pushstring(L, lreq->req->host);
		return (1);
	} else if (!strcmp(field, "agent")) {
		lua_pushstring(L, lreq->req->agent);
		return (1);
	} else if (!strcmp(field, "referer")) {
		lua_pushstring(L, lreq->req->referer);
		return (1);
	} else if (!strcmp(field, "method")) {
		lua_pushinteger(L, lreq->req->method);
		return (1);
	}

	return (0);
}

static int
lua_http_response_header(lua_State *L)
{
	struct lua_http_request		*lreq;
	const char			*header, *value;

	lreq = luaL_checkudata(L, 1, "http_request");
	header = luaL_checkstring(L, 2);
	value = luaL_checkstring(L, 3);

	http_response_header(lreq->req, header, value);

	return (0);
}

static int
lua_http_request_header(lua_State *L)
{
	struct lua_http_request		*lreq;
	const char			*header, *value;

	lreq = luaL_checkudata(L, 1, "http_request");
	header = luaL_checkstring(L, 2);

	if (!http_request_header(lreq->req, header, &value)) {
		lua_pushnil(L);
	} else {
		lua_pushstring(L, value);
	}

	return (1);
}

static int
lua_http_response(lua_State *L)
{
	size_t				len;
	struct lua_http_request		*lreq;
	const void			*data;
	int				status;

	lreq = luaL_checkudata(L, 1, "http_request");
	status = luaL_checkinteger(L, 2);

	if (lua_isnil(L, 3)) {
		len = 0;
		data = NULL;
	} else {
		data = luaL_checklstring(L, 3, &len);
	}

	http_response(lreq->req, status, data, len);

	return (0);
}
