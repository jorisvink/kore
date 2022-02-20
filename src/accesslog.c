/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
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
#include <sys/socket.h>

#include <time.h>
#include <inttypes.h>
#include <signal.h>

#include "kore.h"
#include "http.h"

/*
 * The worker will write accesslogs to its worker data structure which is
 * held in shared memory.
 *
 * Each accesslog is prefixed with the internal domain ID (2 bytes) and
 * the length of the log entry (2 bytes) (packed in kore_alog_header).
 *
 * The parent will every 10ms fetch the produced accesslogs from the workers
 * and copy them to its own log buffer. Once this log buffer becomes full
 * or 1 second has passed the parent will parse the logs and append them
 * to the correct domain logbuffer which is eventually flushed to disk.
 */

#define LOGBUF_SIZE			(KORE_ACCESSLOG_BUFLEN * worker_count)
#define DOMAIN_LOGBUF_LEN		(1024 * 1024)
#define LOG_ENTRY_MINSIZE_GUESS		90

static void	accesslog_lock(struct kore_worker *);
static void	accesslog_unlock(struct kore_worker *);
static void	accesslog_flush_cb(struct kore_domain *);
static void	accesslog_flush(struct kore_domain *, u_int64_t, int);

static u_int64_t	time_cache = 0;
static char		tbuf[128] = { '\0' };

static struct kore_buf	*logbuf = NULL;

void
kore_accesslog_worker_init(void)
{
	kore_domain_closelogs();
}

void
kore_accesslog(struct http_request *req)
{
	struct timespec		ts;
	struct tm		*tm;
	u_int64_t		now;
	struct kore_alog_header	*hdr;
	size_t			avail;
	time_t			curtime;
	int			len, attempts;
	char			addr[INET6_ADDRSTRLEN], *cn_value;
	const char		*ptr, *method, *http_version, *cn, *referer;

	switch (req->method) {
	case HTTP_METHOD_GET:
		method = "GET";
		break;
	case HTTP_METHOD_POST:
		method = "POST";
		break;
	case HTTP_METHOD_PUT:
		method = "PUT";
		break;
	case HTTP_METHOD_DELETE:
		method = "DELETE";
		break;
	case HTTP_METHOD_HEAD:
		method = "HEAD";
		break;
	case HTTP_METHOD_PATCH:
		method = "PATCH";
		break;
	default:
		method = "UNKNOWN";
		break;
	}

	if (req->flags & HTTP_VERSION_1_0)
		http_version = "HTTP/1.0";
	else
		http_version = "HTTP/1.1";

	if (req->referer != NULL)
		referer = req->referer;
	else
		referer = "-";

	if (req->agent == NULL)
		req->agent = "-";

	cn = "-";
	cn_value = NULL;

	if (req->owner->tls_cert != NULL) {
		if (kore_x509_subject_name(req->owner, &cn_value,
		    KORE_X509_COMMON_NAME_ONLY))
			cn = cn_value;
	}

	switch (req->owner->family) {
	case AF_INET:
		ptr = inet_ntop(req->owner->family,
		    &(req->owner->addr.ipv4.sin_addr), addr, sizeof(addr));
		break;
	case AF_INET6:
		ptr = inet_ntop(req->owner->family,
		    &(req->owner->addr.ipv6.sin6_addr), addr, sizeof(addr));
		break;
	case AF_UNIX:
		ptr = NULL;
		break;
	default:
		fatal("unknown family %d", req->owner->family);
	}

	if (ptr == NULL) {
		addr[0] = '-';
		addr[1] = '\0';
	}

	now = kore_time_ms();
	if ((now - time_cache) >= 1000) {
		time(&curtime);
		tm = localtime(&curtime);
		(void)strftime(tbuf, sizeof(tbuf), "%d/%b/%Y:%H:%M:%S %z", tm);
		time_cache = now;
	}

	attempts = 0;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;

	for (;;) {
		if (attempts++ > 1000) {
			if (getppid() == 1) {
				if (kill(worker->pid, SIGQUIT) == -1)
					fatal("failed to shutdown");
				return;
			}

			attempts = 0;
		}

		accesslog_lock(worker);

		avail = KORE_ACCESSLOG_BUFLEN - worker->lb.offset;
		if (avail < sizeof(*hdr) + LOG_ENTRY_MINSIZE_GUESS) {
			accesslog_unlock(worker);
			nanosleep(&ts, NULL);
			continue;
		}

		hdr = (struct kore_alog_header *)
		    (worker->lb.buf + worker->lb.offset);
		worker->lb.offset += sizeof(*hdr);

		len = snprintf(worker->lb.buf + worker->lb.offset, avail,
		    "%s - %s [%s] \"%s %s %s\" %d %" PRIu64" \"%s\" \"%s\"\n",
		    addr, cn, tbuf, method, req->path, http_version,
		    req->status, req->content_length, referer, req->agent);
		if (len == -1)
			fatal("failed to create log entry");

		if ((size_t)len >= avail) {
			worker->lb.offset -= sizeof(*hdr);
			accesslog_unlock(worker);
			nanosleep(&ts, NULL);
			continue;
		}

		if ((size_t)len > USHRT_MAX) {
			kore_log(LOG_WARNING,
			    "log entry length exceeds limit (%d)", len);
			worker->lb.offset -= sizeof(*hdr);
			break;
		}

		hdr->loglen = len;
		hdr->domain = req->rt->dom->id;

		worker->lb.offset += (size_t)len;
		break;
	}

	kore_free(cn_value);
	accesslog_unlock(worker);
}

void
kore_accesslog_gather(void *arg, u_int64_t now, int force)
{
	int				id;
	struct kore_worker		*kw;
	struct kore_alog_header		*hdr;
	struct kore_domain		*dom;
	size_t				off, remain;

	if (logbuf == NULL)
		logbuf = kore_buf_alloc(LOGBUF_SIZE);

	for (id = KORE_WORKER_BASE; id < worker_count; id++) {
		kw = kore_worker_data(id);

		accesslog_lock(kw);

		if (force || kw->lb.offset >= KORE_ACCESSLOG_SYNC) {
			kore_buf_append(logbuf, kw->lb.buf, kw->lb.offset);
			kw->lb.offset = 0;
		}

		accesslog_unlock(kw);
	}

	if (force || logbuf->offset >= LOGBUF_SIZE) {
		off = 0;
		remain = logbuf->offset;

		while (remain > 0) {
			if (remain < sizeof(*hdr)) {
				kore_log(LOG_ERR,
				    "invalid log buffer: (%zu remain)", remain);
				break;
			}

			hdr = (struct kore_alog_header *)(logbuf->data + off);
			off += sizeof(*hdr);
			remain -= sizeof(*hdr);

			if (hdr->loglen > remain) {
				kore_log(LOG_ERR,
				    "invalid log header: %u (%zu remain)",
				    hdr->loglen, remain);
				break;
			}

			if ((dom = kore_domain_byid(hdr->domain)) == NULL)
				fatal("unknown domain id %u", hdr->domain);

			if (dom->logbuf == NULL)
				dom->logbuf = kore_buf_alloc(DOMAIN_LOGBUF_LEN);

			kore_buf_append(dom->logbuf, &logbuf->data[off],
			    hdr->loglen);

			off += hdr->loglen;
			remain -= hdr->loglen;

			accesslog_flush(dom, now, force);
		}

		kore_buf_reset(logbuf);
	}

	if (force)
		kore_domain_callback(accesslog_flush_cb);
}

void
kore_accesslog_run(void *arg, u_int64_t now)
{
	static int	ticks = 0;

	kore_accesslog_gather(arg, now, ticks++ % 100 ? 0 : 1);
}

static void
accesslog_flush_cb(struct kore_domain *dom)
{
	accesslog_flush(dom, 0, 1);
}

static void
accesslog_flush(struct kore_domain *dom, u_int64_t now, int force)
{
	ssize_t		written;

	if (force && dom->logbuf == NULL)
		return;

	if (force || dom->logbuf->offset >= DOMAIN_LOGBUF_LEN) {
		written = write(dom->accesslog, dom->logbuf->data,
		    dom->logbuf->offset);
		if (written == -1) {
			if (errno == EINTR)
				return;
			if (dom->logwarn == 0 ||
			    errno != dom->logerr) {
				kore_log(LOG_NOTICE,
				    "error writing log for %s (%s)",
				    dom->domain, errno_s);
				dom->logwarn = now;
				dom->logerr = errno;
			}
			kore_buf_reset(dom->logbuf);
			return;
		}

		if ((size_t)written != dom->logbuf->offset) {
			kore_log(LOG_ERR, "partial accesslog write for %s",
			    dom->domain);
		}

		kore_buf_reset(dom->logbuf);
	}
}

static void
accesslog_lock(struct kore_worker *kw)
{
	for (;;) {
		if (__sync_bool_compare_and_swap(&kw->lb.lock, 0, 1))
			break;
	}
}

static void
accesslog_unlock(struct kore_worker *kw)
{
	if (!__sync_bool_compare_and_swap(&kw->lb.lock, 1, 0))
		fatal("accesslog_unlock: failed to release");
}
