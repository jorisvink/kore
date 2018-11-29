/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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
#include <sys/mman.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <stdint.h>

#include <kore/kore.h>
#include <kore/http.h>

#include "assets.h"

struct video {
	int			fd;
	int			ref;
	off_t			size;
	char			*path;
	u_int8_t		*data;
	void			*base;

	TAILQ_ENTRY(video)	list;
};

int		init(int);
int		video_stream(struct http_request *);

static void	video_unmap(struct video *);
static int	video_stream_finish(struct netbuf *);
static int	video_mmap(struct http_request *, struct video *);
static int	video_open(struct http_request *, struct video **);

TAILQ_HEAD(, video)		videos;

int
init(int state)
{
	if (state == KORE_MODULE_UNLOAD) {
		kore_log(LOG_NOTICE, "not reloading module");
		return (KORE_RESULT_ERROR);
	}

	TAILQ_INIT(&videos);
	return (KORE_RESULT_OK);
}

int
video_stream(struct http_request *req)
{
	struct video	*v;
	const char	*header;
	off_t		start, end;
	int		n, err, status;
	char		*bytes, *range[3], rb[128], *ext, ctype[32];

	if (!video_open(req, &v))
		return (KORE_RESULT_OK);

	if ((ext = strrchr(req->path, '.')) == NULL) {
		v->ref--;
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_OK);
	}

	if (!kore_snprintf(ctype, sizeof(ctype), NULL, "video/%s", ext + 1)) {
		v->ref--;
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}

	kore_log(LOG_NOTICE, "%p: opened %s (%s) for streaming (%jd ref:%d)",
	    (void *)req->owner, v->path, ctype, (intmax_t)v->size, v->ref);

	if (http_request_header(req, "range", &header)) {
		if ((bytes = strchr(header, '=')) == NULL) {
			v->ref--;
			http_response(req, 416, NULL, 0);
			return (KORE_RESULT_OK);
		}

		bytes++;
		n = kore_split_string(bytes, "-", range, 3);
		if (n == 0) {
			v->ref--;
			http_response(req, 416, NULL, 0);
			return (KORE_RESULT_OK);
		}

		if (n >= 1) {
			start = kore_strtonum64(range[0], 1, &err);
			if (err != KORE_RESULT_OK) {
				v->ref--;
				http_response(req, 416, NULL, 0);
				return (KORE_RESULT_OK);
			}
		}

		if (n > 1) {
			end = kore_strtonum64(range[1], 1, &err);
			if (err != KORE_RESULT_OK) {
				v->ref--;
				http_response(req, 416, NULL, 0);
				return (KORE_RESULT_OK);
			}
		} else {
			end = 0;
		}

		if (end == 0)
			end = v->size;

		if (start > end || start > v->size || end > v->size) {
			v->ref--;
			http_response(req, 416, NULL, 0);
			return (KORE_RESULT_OK);
		}

		status = 206;
		if (!kore_snprintf(rb, sizeof(rb), NULL,
		    "bytes %ld-%ld/%ld", start, end - 1, v->size)) {
			v->ref--;
			http_response(req, 500, NULL, 0);
			return (KORE_RESULT_OK);
		}

		kore_log(LOG_NOTICE, "%p: %s sending: %jd-%jd/%jd",
		    (void *)req->owner, v->path, (intmax_t)start,
		    (intmax_t)end - 1, (intmax_t)v->size);
		http_response_header(req, "content-range", rb);
	} else {
		start = 0;
		status = 200;
		end = v->size;
	}

	http_response_header(req, "content-type", ctype);
	http_response_header(req, "accept-ranges", "bytes");
	http_response_stream(req, status, v->data + start,
	    end - start, video_stream_finish, v);

	return (KORE_RESULT_OK);
}

static int
video_open(struct http_request *req, struct video **out)
{
	struct stat		st;
	struct video		*v;
	char			fpath[MAXPATHLEN];

	if (!kore_snprintf(fpath, sizeof(fpath), NULL, "videos%s", req->path)) {
		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	TAILQ_FOREACH(v, &videos, list) {
		if (!strcmp(v->path, fpath)) {
			if (video_mmap(req, v)) {
				*out = v;
				return (KORE_RESULT_OK);
			}

			close(v->fd);
			TAILQ_REMOVE(&videos, v, list);
			kore_free(v->path);
			kore_free(v);

			http_response(req, 500, NULL, 0);
			return (KORE_RESULT_ERROR);
		}
	}

	v = kore_malloc(sizeof(*v));
	v->ref = 0;
	v->base = NULL;
	v->data = NULL;
	v->path = kore_strdup(fpath);

	if ((v->fd = open(fpath, O_RDONLY)) == -1) {
		kore_free(v->path);
		kore_free(v);

		if (errno == ENOENT)
			http_response(req, 404, NULL, 0);
		else
			http_response(req, 500, NULL, 0);

		return (KORE_RESULT_ERROR);
	}

	if (fstat(v->fd, &st) == -1) {
		close(v->fd);
		kore_free(v->path);
		kore_free(v);

		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	v->size = st.st_size;
	if (!video_mmap(req, v)) {
		close(v->fd);
		kore_free(v->path);
		kore_free(v);

		http_response(req, 500, NULL, 0);
		return (KORE_RESULT_ERROR);
	}

	*out = v;
	TAILQ_INSERT_TAIL(&videos, v, list);

	return (KORE_RESULT_OK);
}

static int
video_mmap(struct http_request *req, struct video *v)
{
	if (v->base != NULL && v->data != NULL) {
		v->ref++;
		return (KORE_RESULT_OK);
	}

	v->base = mmap(NULL, v->size, PROT_READ, MAP_SHARED, v->fd, 0);
	if (v->base == MAP_FAILED)
		return (KORE_RESULT_ERROR);

	v->ref++;
	v->data = v->base;

	return (KORE_RESULT_OK);
}

static int
video_stream_finish(struct netbuf *nb)
{
	struct video	*v = nb->extra;

	v->ref--;
	kore_log(LOG_NOTICE, "%p: video stream %s done (%zu/%zu ref:%d)",
	    (void *)nb->owner, v->path, nb->s_off, nb->b_len, v->ref);

	if (v->ref == 0)
		video_unmap(v);

	return (KORE_RESULT_OK);
}

static void
video_unmap(struct video *v)
{
	if (munmap(v->base, v->size) == -1) {
		kore_log(LOG_ERR, "munmap(%s): %s", v->path, errno_s);
	} else {
		v->base = NULL;
		v->data = NULL;
		kore_log(LOG_NOTICE,
		    "unmapped %s for streaming, no refs left", v->path);
	}
}
