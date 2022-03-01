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
#include <sys/mman.h>

#include <stdint.h>

#include "kore.h"

/* cached filerefs expire after 30 seconds of inactivity. */
#define FILEREF_EXPIRATION		(1000 * 30)

static void	fileref_timer_prime(void);
static void	fileref_drop(struct kore_fileref *);
static void	fileref_soft_remove(struct kore_fileref *);
static void	fileref_expiration_check(void *, u_int64_t);

static TAILQ_HEAD(, kore_fileref)	refs;
static struct kore_pool			ref_pool;
static struct kore_timer		*ref_timer = NULL;

void
kore_fileref_init(void)
{
	TAILQ_INIT(&refs);
	kore_pool_init(&ref_pool, "ref_pool", sizeof(struct kore_fileref), 100);
}

struct kore_fileref *
kore_fileref_create(struct kore_server *srv, const char *path, int fd,
    off_t size, struct timespec *ts)
{
	struct kore_fileref	*ref;

	fileref_timer_prime();

	if ((ref = kore_fileref_get(path, srv->tls)) != NULL)
		return (ref);

	ref = kore_pool_get(&ref_pool);

	ref->cnt = 1;
	ref->flags = 0;
	ref->size = size;
	ref->ontls = srv->tls;
	ref->path = kore_strdup(path);
	ref->mtime_sec = ts->tv_sec;
	ref->mtime = ((u_int64_t)(ts->tv_sec * 1000 + (ts->tv_nsec / 1000000)));

#if !defined(KORE_USE_PLATFORM_SENDFILE)
	if ((uintmax_t)size> SIZE_MAX) {
		kore_pool_put(&ref_pool, ref);
		return (NULL);
	}

	ref->base = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ref->base == MAP_FAILED)
		fatal("net_send_file: mmap failed: %s", errno_s);
	if (madvise(ref->base, (size_t)size, MADV_SEQUENTIAL) == -1)
		fatal("net_send_file: madvise: %s", errno_s);
	close(fd);
#else
	if (srv->tls == 0) {
		ref->fd = fd;
	} else {
		if ((uintmax_t)size > SIZE_MAX) {
			kore_pool_put(&ref_pool, ref);
			return (NULL);
		}

		ref->base = mmap(NULL,
		    (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (ref->base == MAP_FAILED)
			fatal("net_send_file: mmap failed: %s", errno_s);
		if (madvise(ref->base, (size_t)size, MADV_SEQUENTIAL) == -1)
			fatal("net_send_file: madvise: %s", errno_s);
		close(fd);
	}
#endif

#if defined(FILEREF_DEBUG)
	kore_log(LOG_DEBUG, "ref:%p created", (void *)ref);
#endif

	TAILQ_INSERT_TAIL(&refs, ref, list);

	return (ref);
}

/*
 * Caller must call kore_fileref_release() after kore_fileref_get() even
 * if they don't end up using the ref.
 */
struct kore_fileref *
kore_fileref_get(const char *path, int ontls)
{
	struct stat		st;
	struct kore_fileref	*ref;
	u_int64_t		mtime;

	TAILQ_FOREACH(ref, &refs, list) {
		if (!strcmp(ref->path, path) && ref->ontls == ontls) {
			if (stat(ref->path, &st) == -1) {
				if (errno != ENOENT) {
					kore_log(LOG_ERR, "stat(%s): %s",
					    ref->path, errno_s);
				}
				fileref_soft_remove(ref);
				return (NULL);
			}

			mtime = ((u_int64_t)(st.st_mtim.tv_sec * 1000 +
			    (st.st_mtim.tv_nsec / 1000000)));

			if (ref->mtime != mtime) {
				fileref_soft_remove(ref);
				return (NULL);
			}

			ref->cnt++;
#if defined(FILEREF_DEBUG)
			kore_log(LOG_DEBUG, "ref:%p cnt:%d",
			    (void *)ref, ref->cnt);
#endif
			TAILQ_REMOVE(&refs, ref, list);
			TAILQ_INSERT_HEAD(&refs, ref, list);
			return (ref);
		}
	}

	return (NULL);
}

void
kore_fileref_release(struct kore_fileref *ref)
{
	ref->cnt--;

#if defined(FILEREF_DEBUG)
	kore_log(LOG_DEBUG, "ref:%p released cnt:%d", (void *)ref, ref->cnt);
#endif

	if (ref->cnt < 0) {
		fatal("kore_fileref_release: cnt < 0 (%p:%d)",
		    (void *)ref, ref->cnt);
	}

	if (ref->cnt == 0) {
		if (ref->flags & KORE_FILEREF_SOFT_REMOVED)
			fileref_drop(ref);
		else
			ref->expiration = kore_time_ms() + FILEREF_EXPIRATION;
	}
}

static void
fileref_timer_prime(void)
{
	if (ref_timer != NULL)
		return;

	ref_timer = kore_timer_add(fileref_expiration_check, 10000, NULL, 0);
}

static void
fileref_soft_remove(struct kore_fileref *ref)
{
	if (ref->flags & KORE_FILEREF_SOFT_REMOVED)
		fatal("fileref_soft_remove: %p already removed", (void *)ref);

#if defined(FILEREF_DEBUG)
	kore_log(LOG_DEBUG, "ref:%p softremoved", (void *)ref);
#endif

	TAILQ_REMOVE(&refs, ref, list);
	ref->flags |= KORE_FILEREF_SOFT_REMOVED;

	if (ref->cnt == 0)
		fileref_drop(ref);
}

static void
fileref_expiration_check(void *arg, u_int64_t now)
{
	struct kore_fileref	*ref, *next;

	for (ref = TAILQ_FIRST(&refs); ref != NULL; ref = next) {
		next = TAILQ_NEXT(ref, list);

		if (ref->cnt != 0)
			continue;

		if (ref->expiration > now)
			continue;

#if defined(FILEREF_DEBUG)
		kore_log(LOG_DEBUG, "ref:%p expired, removing", (void *)ref);
#endif

		fileref_drop(ref);
	}

	if (TAILQ_EMPTY(&refs)) {
		/* remove the timer. */
		ref_timer->flags |= KORE_TIMER_ONESHOT;
		ref_timer = NULL;
	}
}

static void
fileref_drop(struct kore_fileref *ref)
{
#if defined(FILEREF_DEBUG)
	kore_log(LOG_DEBUG, "ref:%p dropped", (void *)ref);
#endif

	if (!(ref->flags & KORE_FILEREF_SOFT_REMOVED))
		TAILQ_REMOVE(&refs, ref, list);

	kore_free(ref->path);

#if !defined(KORE_USE_PLATFORM_SENDFILE)
	(void)munmap(ref->base, ref->size);
#else
	close(ref->fd);
#endif
	kore_pool_put(&ref_pool, ref);
}
