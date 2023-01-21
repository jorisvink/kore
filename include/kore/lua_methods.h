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

#ifndef __H_LUA_METHODS_H
#define __H_LUA_METHODS_H

static int		lua_http_request_gc(lua_State *);
static int		lua_http_request_index(lua_State *);

static int		lua_http_response(lua_State *);
static int		lua_http_request_header(lua_State *);
static int		lua_http_response_header(lua_State *);

static const luaL_Reg lua_http_request_meta[] = {
	{ "__gc",			lua_http_request_gc },
	{ "__index",			lua_http_request_index },
	{ NULL, 			NULL },
};

static const luaL_Reg lua_http_request_methods[] = {
	{ "response",			lua_http_response },
	{ "request_header",		lua_http_request_header },
	{ "response_header",		lua_http_response_header },
	{ NULL, 			NULL },
};

static int		lua_kore_config(lua_State *);
static int		lua_kore_server(lua_State *);

static const luaL_Reg lua_kore_functions[] = {
	{ "config",			lua_kore_config },
	{ "server",			lua_kore_server },
	{ NULL, 			NULL },
};

#endif
