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

#include <sys/types.h>

#include <inttypes.h>

#include "kore.h"
#include "http.h"
#include "curl.h"

#if defined(__linux__)
#include "seccomp.h"

static struct sock_filter filter_curl[] = {
	/* Allow sockets and libcurl to call connect. */
	KORE_SYSCALL_ALLOW(bind),
	KORE_SYSCALL_ALLOW(ioctl),
	KORE_SYSCALL_ALLOW(connect),
	KORE_SYSCALL_ALLOW(getsockopt),
	KORE_SYSCALL_ALLOW(getsockname),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET6),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_UNIX),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_NETLINK),

	/* Threading related. */
	KORE_SYSCALL_ALLOW(clone),
	KORE_SYSCALL_ALLOW(set_robust_list),

	/* Other */
	KORE_SYSCALL_ALLOW(uname),
	KORE_SYSCALL_ALLOW(ioctl),
	KORE_SYSCALL_ALLOW(madvise),
	KORE_SYSCALL_ALLOW(recvmsg),
	KORE_SYSCALL_ALLOW(sendmmsg),
	KORE_SYSCALL_ALLOW(faccessat),
	KORE_SYSCALL_ALLOW(newfstatat),
	KORE_SYSCALL_ALLOW(getpeername),
};
#endif

#define FD_CACHE_BUCKETS	2048

struct fd_cache {
	struct kore_event	evt;
	int			fd;
	int			scheduled;
	LIST_ENTRY(fd_cache)	list;
};

struct curl_run {
	int			eof;
	struct fd_cache		*fdc;
	TAILQ_ENTRY(curl_run)	list;
};

static void	curl_process(void);
static void	curl_event_handle(void *, int);
static void	curl_timeout(void *, u_int64_t);
static int	curl_timer(CURLM *, long, void *);
static void	curl_run_handle(struct curl_run *);
static void	curl_run_schedule(struct fd_cache *, int);
static int	curl_socket(CURL *, curl_socket_t, int, void *, void *);

static struct fd_cache	*fd_cache_get(int);

static TAILQ_HEAD(, curl_run)	runlist;
static struct kore_pool		run_pool;
static int			running = 0;
static CURLM			*multi = NULL;
static struct kore_timer	*timer = NULL;
static struct kore_pool		fd_cache_pool;
static char			user_agent[64];
static int			timeout_immediate = 0;
static LIST_HEAD(, fd_cache)	cache[FD_CACHE_BUCKETS];

u_int16_t	kore_curl_timeout = KORE_CURL_TIMEOUT;
u_int64_t	kore_curl_recv_max = KORE_CURL_RECV_MAX;

void
kore_curl_sysinit(void)
{
	CURLMcode	res;
	int		i, len;

	if (curl_global_init(CURL_GLOBAL_ALL))
		fatal("failed to initialize libcurl");

	if ((multi = curl_multi_init()) == NULL)
		fatal("curl_multi_init(): failed");

	/* XXX - make configurable? */
	curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, 500);

	if ((res = curl_multi_setopt(multi,
	    CURLMOPT_SOCKETFUNCTION, curl_socket)) != CURLM_OK)
		fatal("curl_multi_setopt: %s", curl_multi_strerror(res));

	if ((res = curl_multi_setopt(multi,
	    CURLMOPT_TIMERFUNCTION, curl_timer)) != CURLM_OK)
		fatal("curl_multi_setopt: %s", curl_multi_strerror(res));

	for (i = 0; i < FD_CACHE_BUCKETS; i++)
		LIST_INIT(&cache[i]);

	TAILQ_INIT(&runlist);

	kore_pool_init(&fd_cache_pool, "fd_cache_pool", 100,
	    sizeof(struct fd_cache));
	kore_pool_init(&run_pool, "run_pool", 100, sizeof(struct curl_run));

	len = snprintf(user_agent, sizeof(user_agent), "kore/%s", kore_version);
	if (len == -1 || (size_t)len >= sizeof(user_agent))
		fatal("user-agent string too long");

#if defined(__linux__)
	kore_seccomp_filter("curl", filter_curl, KORE_FILTER_LEN(filter_curl));
#endif
#if defined(KORE_USE_PLATFORM_PLEDGE)
	kore_platform_add_pledge("dns");
#endif
}

int
kore_curl_init(struct kore_curl *client, const char *url, int flags)
{
	CURL		*handle;

	if ((flags & KORE_CURL_ASYNC) && (flags & KORE_CURL_SYNC)) {
		(void)kore_strlcpy(client->errbuf, "invalid flags",
		    sizeof(client->errbuf));
		return (KORE_RESULT_ERROR);
	}

	memset(client, 0, sizeof(*client));

	TAILQ_INIT(&client->http.resp_hdrs);

	if ((handle = curl_easy_init()) == NULL) {
		(void)kore_strlcpy(client->errbuf, "failed to setup curl",
		    sizeof(client->errbuf));
		return (KORE_RESULT_ERROR);
	}

	curl_easy_setopt(handle, CURLOPT_WRITEDATA, &client->response);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, kore_curl_tobuf);

	curl_easy_setopt(handle, CURLOPT_URL, url);
	curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(handle, CURLOPT_PRIVATE, client);
	curl_easy_setopt(handle, CURLOPT_USERAGENT, user_agent);
	curl_easy_setopt(handle, CURLOPT_TIMEOUT, kore_curl_timeout);
	curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, client->errbuf);

	client->flags = flags;
	client->handle = handle;
	client->url = kore_strdup(url);
	client->type = KORE_CURL_TYPE_CUSTOM;

	return (KORE_RESULT_OK);
}

void
kore_curl_cleanup(struct kore_curl *client)
{
	struct http_header	*hdr, *next;

	kore_free(client->url);

	if (client->flags & KORE_CURL_FLAG_BOUND)
		LIST_REMOVE(client, list);

	if (client->handle != NULL) {
		curl_multi_remove_handle(multi, client->handle);
		curl_easy_cleanup(client->handle);
	}

	if (client->http.hdrlist != NULL)
		curl_slist_free_all(client->http.hdrlist);

	if (client->response != NULL)
		kore_buf_free(client->response);

	if (client->http.headers != NULL)
		kore_buf_free(client->http.headers);

	if (client->http.tosend != NULL)
		kore_buf_free(client->http.tosend);

	for (hdr = TAILQ_FIRST(&client->http.resp_hdrs);
	    hdr != NULL; hdr = next) {
		next = TAILQ_NEXT(hdr, list);
		TAILQ_REMOVE(&client->http.resp_hdrs, hdr, list);
		kore_pool_put(&http_header_pool, hdr);
	}
}

void
kore_curl_do_timeout(void)
{
	while (timeout_immediate) {
		curl_timeout(NULL, kore_time_ms());
		if (running == 0)
			curl_timer(multi, -1, NULL);
	}
}

void
kore_curl_run_scheduled(void)
{
	struct curl_run		*run;

	while ((run = TAILQ_FIRST(&runlist))) {
		TAILQ_REMOVE(&runlist, run, list);
		curl_run_handle(run);
		kore_pool_put(&run_pool, run);
	}

	curl_process();
}

size_t
kore_curl_tobuf(char *ptr, size_t size, size_t nmemb, void *udata)
{
	size_t			len;
	struct kore_buf		**buf, *b;

	if (SIZE_MAX / nmemb < size)
		fatal("%s: %zu * %zu overflow", __func__, nmemb, size);

	buf = udata;
	len = size * nmemb;

	if (*buf == NULL)
		*buf = kore_buf_alloc(len);

	b = *buf;

	if (b->offset + len < b->offset)
		fatal("%s: %zu+%zu overflows", __func__, b->offset, len);

	if ((b->offset + len) > kore_curl_recv_max) {
		kore_log(LOG_ERR,
		    "received too large transfer (%zu > %" PRIu64 ")",
		    b->offset + len, kore_curl_recv_max);
		return (0);
	}

	kore_buf_append(b, ptr, len);

	return (len);
}

size_t
kore_curl_frombuf(char *ptr, size_t size, size_t nmemb, void *udata)
{
	size_t			len;
	struct kore_buf		*buf;

	if (SIZE_MAX / nmemb < size)
		fatal("%s: %zu * %zu overflow", __func__, nmemb, size);

	buf = udata;
	len = size * nmemb;

	if (buf->offset == buf->length)
		return (0);

	if (buf->offset + len < buf->offset)
		fatal("%s: %zu+%zu overflows", __func__, buf->offset, len);

	if ((buf->offset + len) < buf->length) {
		memcpy(ptr, buf->data + buf->offset, len);
	} else {
		len = buf->length - buf->offset;
		memcpy(ptr, buf->data + buf->offset, len);
	}

	buf->offset += len;

	return (len);
}

void
kore_curl_bind_request(struct kore_curl *client, struct http_request *req)
{
	if (client->cb != NULL)
		fatal("%s: already bound to callback", __func__);

	client->req = req;
	http_request_sleep(req);

	client->flags |= KORE_CURL_FLAG_BOUND;
	LIST_INSERT_HEAD(&req->chandles, client, list);
}

void
kore_curl_bind_callback(struct kore_curl *client,
    void (*cb)(struct kore_curl *, void *), void *arg)
{
	if (client->req != NULL)
		fatal("%s: already bound to request", __func__);

	client->cb = cb;
	client->arg = arg;
}

void
kore_curl_run(struct kore_curl *client)
{
	if (client->flags & KORE_CURL_ASYNC) {
		curl_multi_add_handle(multi, client->handle);
		return;
	}

	client->result = curl_easy_perform(client->handle);

	curl_easy_getinfo(client->handle,
	    CURLINFO_RESPONSE_CODE, &client->http.status);

	curl_easy_cleanup(client->handle);
	client->handle = NULL;
}

int
kore_curl_success(struct kore_curl *client)
{
	return (client->result == CURLE_OK);
}

const char *
kore_curl_strerror(struct kore_curl *client)
{
	const char	*err;

	if (client->errbuf[0] != '\0')
		err = &client->errbuf[0];
	else
		err = curl_easy_strerror(client->result);

	return (err);
}

void
kore_curl_logerror(struct kore_curl *client)
{
	kore_log(LOG_NOTICE, "curl error: %s -> %s", client->url,
	    kore_curl_strerror(client));
}

void
kore_curl_response_as_bytes(struct kore_curl *client, const u_int8_t **body,
    size_t *len)
{
	if (client->response == NULL) {
		*len = 0;
		*body = NULL;
	} else {
		*len = client->response->offset;
		*body = client->response->data;
	}
}

char *
kore_curl_response_as_string(struct kore_curl *client)
{
	kore_buf_stringify(client->response, NULL);

	return ((char *)client->response->data);
}

void
kore_curl_http_setup(struct kore_curl *client, int method, const void *data,
    size_t len)
{
	const char	*mname;
	int		has_body;

	if (client->handle == NULL)
		fatal("%s: called without setup", __func__);

	mname = NULL;
	has_body = 1;

	client->type = KORE_CURL_TYPE_HTTP_CLIENT;

	curl_easy_setopt(client->handle, CURLOPT_HEADERDATA,
	    &client->http.headers);
	curl_easy_setopt(client->handle, CURLOPT_HEADERFUNCTION,
	    kore_curl_tobuf);

	kore_curl_http_set_header(client, "expect", "");

	switch (method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_OPTIONS:
		break;
	case HTTP_METHOD_HEAD:
		curl_easy_setopt(client->handle, CURLOPT_NOBODY, 1);
		break;
	case HTTP_METHOD_PUT:
		has_body = 1;
		curl_easy_setopt(client->handle, CURLOPT_UPLOAD, 1);
		break;
	case HTTP_METHOD_PATCH:
	case HTTP_METHOD_DELETE:
		mname = http_method_text(method);
		/* fallthrough */
	case HTTP_METHOD_POST:
		has_body = 1;
		curl_easy_setopt(client->handle, CURLOPT_POST, 1);
		break;
	default:
		fatal("%s: unknown method %d", __func__, method);
	}

	if (has_body && data != NULL && len > 0) {
		client->http.tosend = kore_buf_alloc(len);
		kore_buf_append(client->http.tosend, data, len);
		kore_buf_reset(client->http.tosend);

		curl_easy_setopt(client->handle, CURLOPT_READDATA,
		    client->http.tosend);
		curl_easy_setopt(client->handle, CURLOPT_READFUNCTION,
		    kore_curl_frombuf);
	}

	if (has_body) {
		if (method == HTTP_METHOD_PUT) {
			curl_easy_setopt(client->handle,
			    CURLOPT_INFILESIZE_LARGE, (curl_off_t)len);
		} else {
			curl_easy_setopt(client->handle,
			    CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
		}
	} else {
		if (data != NULL || len != 0) {
			fatal("%s: %d should not have a body",
			    __func__, method);
		}
	}

	if (mname != NULL)
		curl_easy_setopt(client->handle, CURLOPT_CUSTOMREQUEST, mname);
}

void
kore_curl_http_set_header(struct kore_curl *client, const char *header,
    const char *value)
{
	struct kore_buf		buf;
	const char		*hdr;

	kore_buf_init(&buf, 512);

	if (value != NULL || *value != '\0') {
		kore_buf_appendf(&buf, "%s: %s", header, value);
	} else {
		kore_buf_appendf(&buf, "%s:", header);
	}

	hdr = kore_buf_stringify(&buf, NULL);

	client->http.hdrlist = curl_slist_append(client->http.hdrlist, hdr);
	kore_buf_cleanup(&buf);

	curl_easy_setopt(client->handle,
	    CURLOPT_HTTPHEADER, client->http.hdrlist);
}

int
kore_curl_http_get_header(struct kore_curl *client, const char *header,
    const char **out)
{
	struct http_header	*hdr;

	if (!(client->flags & KORE_CURL_FLAG_HTTP_PARSED_HEADERS))
		kore_curl_http_parse_headers(client);

	TAILQ_FOREACH(hdr, &(client->http.resp_hdrs), list) {
		if (!strcasecmp(hdr->header, header)) {
			*out = hdr->value;
			return (KORE_RESULT_OK);
		}
	}

	return (KORE_RESULT_ERROR);
}

void
kore_curl_http_parse_headers(struct kore_curl *client)
{
	struct http_header	*hdr;
	int			i, cnt;
	char			*value, *hbuf, *headers[HTTP_REQ_HEADER_MAX];

	if (client->flags & KORE_CURL_FLAG_HTTP_PARSED_HEADERS)
		fatal("%s: headers already parsed", __func__);

	client->flags |= KORE_CURL_FLAG_HTTP_PARSED_HEADERS;

	if (client->http.headers == NULL)
		return;

	hbuf = kore_buf_stringify(client->http.headers, NULL);
	cnt = kore_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);

	for (i = 0; i < cnt; i++) {
		if ((value = http_validate_header(headers[i])) == NULL)
			continue;

		if (*value == '\0')
			continue;

		hdr = kore_pool_get(&http_header_pool);
		hdr->header = headers[i];
		hdr->value = value;
		TAILQ_INSERT_TAIL(&(client->http.resp_hdrs), hdr, list);
	}
}

static int
curl_socket(CURL *easy, curl_socket_t fd, int action, void *arg, void *sock)
{
	CURLcode		res;
	struct fd_cache		*fdc;
	struct kore_curl	*client;

	client = NULL;

	res = curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&client);
	if (res != CURLE_OK)
		fatal("curl_easy_getinfo: %s", curl_easy_strerror(res));

	if (client == NULL)
		fatal("%s: failed to get client context", __func__);

	fdc = fd_cache_get(fd);

	switch (action) {
	case CURL_POLL_NONE:
		break;
	case CURL_POLL_IN:
		if (fdc->scheduled) {
			kore_platform_disable_read(fd);
#if !defined(__linux__)
			kore_platform_disable_write(fd);
#endif
		}
		fdc->scheduled = 1;
		kore_platform_event_level_read(fd, fdc);
		break;
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		if (fdc->scheduled) {
			kore_platform_disable_read(fd);
#if !defined(__linux__)
			kore_platform_disable_write(fd);
#endif
		}
		fdc->scheduled = 1;
		kore_platform_event_level_all(fd, fdc);
		break;
	case CURL_POLL_REMOVE:
		if (fdc->scheduled) {
			fdc->evt.flags = 0;
			fdc->scheduled = 0;
			kore_platform_disable_read(fd);
#if !defined(__linux__)
			kore_platform_disable_write(fd);
#endif
		}
		break;
	default:
		fatal("unknown action value: %d", action);
	}

	if (action != CURL_POLL_NONE && action != CURL_POLL_REMOVE)
		curl_run_schedule(fdc, 0);

	return (CURLM_OK);
}

static void
curl_process(void)
{
	CURLcode		res;
	CURLMsg			*msg;
	CURL			*handle;
	struct kore_curl	*client;
	int			pending;

	pending = 0;

	while ((msg = curl_multi_info_read(multi, &pending)) != NULL) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		handle = msg->easy_handle;

		res = curl_easy_getinfo(handle, CURLINFO_PRIVATE,
		    (char **)&client);
		if (res != CURLE_OK)
			fatal("curl_easy_getinfo: %s", curl_easy_strerror(res));

		if (client == NULL)
			fatal("%s: failed to get client context", __func__);

		client->result = msg->data.result;

		if (client->type == KORE_CURL_TYPE_HTTP_CLIENT) {
			curl_easy_getinfo(client->handle,
			    CURLINFO_RESPONSE_CODE, &client->http.status);
		}

		curl_multi_remove_handle(multi, client->handle);
		curl_easy_cleanup(client->handle);

		client->handle = NULL;

		if (client->req != NULL)
			http_request_wakeup(client->req);
		else if (client->cb != NULL)
			client->cb(client, client->arg);
	}
}

static void
curl_timeout(void *uarg, u_int64_t now)
{
	CURLMcode	res;

	timer = NULL;

	res = curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &running);
	if (res != CURLM_OK)
		fatal("curl_multi_socket_action: %s", curl_multi_strerror(res));

	curl_process();
}

static int
curl_timer(CURLM *mctx, long timeout, void *arg)
{
	timeout_immediate = 0;

	if (timeout < 0) {
		if (timer != NULL) {
			kore_timer_remove(timer);
			timer = NULL;
		}
		return (CURLM_OK);
	}

	if (timer != NULL) {
		kore_timer_remove(timer);
		timer = NULL;
	}

	if (timeout == 0) {
		timeout_immediate = 1;
		return (CURLM_OK);
	}

	timer = kore_timer_add(curl_timeout, timeout, mctx, KORE_TIMER_ONESHOT);

	return (CURLM_OK);
}

static void
curl_run_schedule(struct fd_cache *fdc, int eof)
{
	struct curl_run		*run;

	run = kore_pool_get(&run_pool);
	run->fdc = fdc;
	run->eof = eof;

	TAILQ_INSERT_TAIL(&runlist, run, list);
}

static void
curl_event_handle(void *arg, int eof)
{
	curl_run_schedule(arg, eof);
}

static void
curl_run_handle(struct curl_run *run)
{
	CURLMcode		res;
	int			flags;
	struct fd_cache		*fdc = run->fdc;

	flags = 0;

	if (fdc->evt.flags & KORE_EVENT_READ)
		flags |= CURL_CSELECT_IN;

	if (fdc->evt.flags & KORE_EVENT_WRITE)
		flags |= CURL_CSELECT_OUT;

	if (run->eof)
		flags |= CURL_CSELECT_ERR;

	res = curl_multi_socket_action(multi, fdc->fd, flags, &running);
	if (res != CURLM_OK)
		fatal("curl_multi_socket_action: %s", curl_multi_strerror(res));
}

static struct fd_cache *
fd_cache_get(int fd)
{
	struct fd_cache		*fdc;
	int			bucket;

	bucket = fd % FD_CACHE_BUCKETS;

	LIST_FOREACH(fdc, &cache[bucket], list) {
		if (fdc->fd == fd)
			return (fdc);
	}

	fdc = kore_pool_get(&fd_cache_pool);

	fdc->fd = fd;
	fdc->scheduled = 0;

	fdc->evt.flags = 0;
	fdc->evt.handle = curl_event_handle;
	fdc->evt.type = KORE_TYPE_CURL_HANDLE;

	LIST_INSERT_HEAD(&cache[bucket], fdc, list);

	return (fdc);
}
