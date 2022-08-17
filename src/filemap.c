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

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>

#include "kore.h"

#if !defined(KORE_NO_HTTP)

#include "http.h"

struct filemap_entry {
	char				*root;
	size_t				root_len;
	struct kore_domain		*domain;
	char				*ondisk;
	size_t				ondisk_len;
	TAILQ_ENTRY(filemap_entry)	list;
};

int	filemap_resolve(struct http_request *);

static void	filemap_serve(struct http_request *, const struct filemap_entry *);

static TAILQ_HEAD(, filemap_entry)	maps;

char	*kore_filemap_ext = NULL;
char	*kore_filemap_index = NULL;

void
kore_filemap_init(void)
{
	TAILQ_INIT(&maps);
}

struct kore_route *
kore_filemap_create(struct kore_domain *dom, const char *path,
    const char *root, const char *auth)
{
	size_t				sz;
	struct stat			st;
	int				len;
	struct kore_route		*rt;
	struct filemap_entry		*entry;
	char				regex[1024], fpath[PATH_MAX];

	sz = strlen(root);
	if (sz == 0)
		return (NULL);

	if (root[0] != '/' || root[sz - 1] != '/')
		return (NULL);

	if (worker_privsep.root != NULL) {
		len = snprintf(fpath, sizeof(fpath), "%s/%s",
		    worker_privsep.root, path);
		if (len == -1 || (size_t)len >= sizeof(fpath))
			fatal("kore_filemap_create: failed to concat paths");
	} else {
		if (kore_strlcpy(fpath, path, sizeof(fpath)) >= sizeof(fpath))
			fatal("kore_filemap_create: failed to copy path");
	}

	if (stat(fpath, &st) == -1) {
		kore_log(LOG_ERR, "%s: failed to stat '%s': %s", __func__,
		    fpath, errno_s);
		return (NULL);
	}

	len = snprintf(regex, sizeof(regex), "^%s.*$", root);
	if (len == -1 || (size_t)len >= sizeof(regex))
		fatal("kore_filemap_create: buffer too small");

	if ((rt = kore_route_create(dom, regex, HANDLER_TYPE_DYNAMIC)) == NULL)
		return (NULL);

	if (auth != NULL) {
		rt->auth = kore_auth_lookup(auth);
		if (rt->auth == NULL) {
			fatal("filemap for '%s' has unknown auth '%s'",
			    path, auth);
		}
	}

	kore_route_callback(rt, "filemap_resolve");
	rt->methods = HTTP_METHOD_GET | HTTP_METHOD_HEAD;

	entry = kore_calloc(1, sizeof(*entry));
	entry->domain = dom;
	entry->root_len = sz;
	entry->root = kore_strdup(root);

	/*
	 * Resolve the ondisk component inside the workers to make sure
	 * realpath() resolves the correct path (they maybe chrooted).
	 */
	entry->ondisk_len = strlen(path);
	entry->ondisk = kore_strdup(path);

	TAILQ_INSERT_TAIL(&maps, entry, list);

	return (rt);
}

void
kore_filemap_resolve_paths(void)
{
	struct filemap_entry	*entry;
	char			rpath[PATH_MAX];

	TAILQ_FOREACH(entry, &maps, list) {
		if (realpath(entry->ondisk, rpath) == NULL)
			fatal("realpath(%s): %s", entry->ondisk, errno_s);

		kore_free(entry->ondisk);
		entry->ondisk_len = strlen(rpath);
		entry->ondisk = kore_strdup(rpath);
	}
}

int
filemap_resolve(struct http_request *req)
{
	size_t			best_len;
	struct filemap_entry	*entry, *best;

	if (req->method != HTTP_METHOD_GET &&
	    req->method != HTTP_METHOD_HEAD) {
		http_response_header(req, "allow", "get, head");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return (KORE_RESULT_OK);
	}

	best = NULL;
	best_len = 0;

	TAILQ_FOREACH(entry, &maps, list) {
		if (entry->domain != req->rt->dom)
			continue;

		if (!strncmp(entry->root, req->path, entry->root_len)) {
			if (best == NULL || entry->root_len > best_len) {
				best = entry;
				best_len = entry->root_len;
				continue;
			}
		}
	}

	if (best == NULL) {
		http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		return (KORE_RESULT_OK);
	}

	filemap_serve(req, best);

	return (KORE_RESULT_OK);
}

static void
filemap_serve(struct http_request *req, const struct filemap_entry *map)
{
	struct stat		st;
	struct connection	*c;
	struct kore_fileref	*ref;
	struct kore_server	*srv;
	const char		*path;
	int			len, fd, index;
	char			fpath[PATH_MAX], rpath[PATH_MAX];

	path = req->path + map->root_len;

	len = snprintf(fpath, sizeof(fpath), "%s/%s", map->ondisk, path);
	if (len == -1 || (size_t)len >= sizeof(fpath)) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return;
	}

	if (!http_argument_urldecode(fpath)) {
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

	index = 0;

lookup:
	if (realpath(fpath, rpath) == NULL) {
		if (errno == ENOENT) {
			if (index == 0 && kore_filemap_ext != NULL) {
				len = snprintf(fpath, sizeof(fpath),
				    "%s/%s%s", map->ondisk, path,
				    kore_filemap_ext);
				if (len == -1 ||
				    (size_t)len >= sizeof(fpath)) {
					http_response(req,
					    HTTP_STATUS_INTERNAL_ERROR,
					    NULL, 0);
					return;
				}
				index++;
				goto lookup;
			}
		}
		http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		return;
	}

	if (strncmp(rpath, fpath, map->ondisk_len)) {
		http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		return;
	}

	c = req->owner;
	srv = c->owner->server;

	if ((ref = kore_fileref_get(rpath, srv->tls)) == NULL) {
		if ((fd = open(fpath, O_RDONLY | O_NOFOLLOW)) == -1) {
			switch (errno) {
			case ENOENT:
				if (index || kore_filemap_ext == NULL) {
					req->status = HTTP_STATUS_NOT_FOUND;
				} else {
					len = snprintf(fpath, sizeof(fpath),
					    "%s/%s%s", map->ondisk, path,
					    kore_filemap_ext);
					if (len == -1 ||
					    (size_t)len >= sizeof(fpath)) {
						http_response(req,
						    HTTP_STATUS_INTERNAL_ERROR,
						    NULL, 0);
						return;
					}
					index++;
					goto lookup;
				}
				break;
			case EPERM:
			case EACCES:
				req->status = HTTP_STATUS_FORBIDDEN;
				break;
			default:
				req->status = HTTP_STATUS_INTERNAL_ERROR;
				break;
			}

			http_response(req, req->status, NULL, 0);
			return;
		}

		if (fstat(fd, &st) == -1) {
			http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
			goto cleanup;
		}

		if (S_ISREG(st.st_mode)) {
			if (st.st_size <= 0) {
				http_response(req,
				    HTTP_STATUS_NOT_FOUND, NULL, 0);
				goto cleanup;
			}

			/* kore_fileref_create() takes ownership of the fd. */
			ref = kore_fileref_create(srv, fpath, fd,
			    st.st_size, &st.st_mtim);
			if (ref == NULL) {
				http_response(req,
				    HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
			} else {
				fd = -1;
			}
		} else if (S_ISDIR(st.st_mode) && index == 0) {
			close(fd);
			if (req->path[strlen(req->path) - 1] != '/') {
				(void)snprintf(fpath,
				    sizeof(fpath), "%s/", req->path);
				http_response_header(req, "location", fpath);
				http_response(req, HTTP_STATUS_FOUND, NULL, 0);
				return;
			}

			len = snprintf(fpath, sizeof(fpath),
			    "%s/%s%s", map->ondisk, path,
			    kore_filemap_index != NULL ?
			    kore_filemap_index : "index.html");
			if (len == -1 || (size_t)len >= sizeof(fpath)) {
				http_response(req,
				    HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
				return;
			}
			index++;
			goto lookup;
		} else {
			http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		}
	}

	if (ref != NULL) {
		http_response_fileref(req, HTTP_STATUS_OK, ref);
		fd = -1;
	}

cleanup:
	if (fd != -1)
		close(fd);
}

#endif
