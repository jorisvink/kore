/*
 * Copyright (c) 2013-2015 Joris Vink <joris@coders.se>
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

#include <sys/socket.h>

#include <poll.h>

#include "kore.h"
#include "http.h"

static int		accesslog_fd[2];

struct kore_log_packet {
	u_int8_t	method;
	int		status;
	u_int16_t	time_req;
	u_int16_t	worker_id;
	u_int16_t	worker_cpu;
	u_int8_t	addrtype;
	u_int8_t	addr[sizeof(struct in6_addr)];
	char		host[KORE_DOMAINNAME_LEN];
	char		path[HTTP_URI_LEN];
	char		agent[HTTP_USERAGENT_LEN];
	char		cn[X509_CN_LENGTH];
};

void
kore_accesslog_init(void)
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, accesslog_fd) == -1)
		fatal("kore_accesslog_init(): socketpair() %s", errno_s);
}

void
kore_accesslog_worker_init(void)
{
	close(accesslog_fd[0]);
	kore_domain_closelogs();
}

int
kore_accesslog_wait(void)
{
	ssize_t			len;
	time_t			now;
	struct kore_domain	*dom;
	struct pollfd		pfd[1];
	int			nfds, l;
	struct kore_log_packet	logpacket;
	char			addr[INET6_ADDRSTRLEN];
	char			*method, *buf, *tbuf, *cn;

	pfd[0].fd = accesslog_fd[0];
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	nfds = poll(pfd, 1, 1000);
	if (nfds == -1 || (pfd[0].revents & (POLLERR | POLLHUP | POLLNVAL))) {
		if (nfds == -1 && errno == EINTR)
			return (KORE_RESULT_OK);
		kore_log(LOG_WARNING, "poll(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (nfds == 0)
		return (KORE_RESULT_OK);

	len = recv(accesslog_fd[0], &logpacket, sizeof(logpacket), 0);
	if (len == -1) {
		kore_log(LOG_WARNING, "recv(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (len != sizeof(logpacket))
		return (KORE_RESULT_ERROR);

	if ((dom = kore_domain_lookup(logpacket.host)) == NULL) {
		kore_log(LOG_WARNING,
		    "got accesslog packet for unknown domain: %s",
		    logpacket.host);
		return (KORE_RESULT_OK);
	}

	switch (logpacket.method) {
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
	default:
		method = "UNKNOWN";
		break;
	}

	if (logpacket.cn[0] != '\0')
		cn = logpacket.cn;
	else
		cn = "none";

	if (inet_ntop(logpacket.addrtype, &(logpacket.addr),
	    addr, sizeof(addr)) == NULL)
		kore_strlcpy(addr, "unknown", sizeof(addr));

	time(&now);
	tbuf = kore_time_to_date(now);
	l = asprintf(&buf, "[%s] %s %d %s %s (w#%d) (%dms) (%s) (%s)\n",
	    tbuf, addr, logpacket.status, method, logpacket.path,
	    logpacket.worker_id, logpacket.time_req, cn, logpacket.agent);
	if (l == -1) {
		kore_log(LOG_WARNING,
		    "kore_accesslog_wait(): asprintf() == -1");
		return (KORE_RESULT_ERROR);
	}

	len = write(dom->accesslog, buf, l);
	if (len == -1) {
		free(buf);
		kore_log(LOG_WARNING,
		    "kore_accesslog_wait(): write(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (len != l)
		kore_log(LOG_NOTICE, "accesslog: %s", buf);

	free(buf);
	return (KORE_RESULT_OK);
}

void
kore_accesslog(struct http_request *req)
{
	ssize_t			len;
	struct kore_log_packet	logpacket;

	logpacket.addrtype = req->owner->addrtype;
	if (logpacket.addrtype == AF_INET) {
		memcpy(logpacket.addr,
		    &(req->owner->addr.ipv4.sin_addr),
		    sizeof(req->owner->addr.ipv4.sin_addr));
	} else {
		memcpy(logpacket.addr,
		    &(req->owner->addr.ipv6.sin6_addr),
		    sizeof(req->owner->addr.ipv6.sin6_addr));
	}

	logpacket.status = req->status;
	logpacket.method = req->method;
	logpacket.worker_id = worker->id;
	logpacket.worker_cpu = worker->cpu;
	logpacket.time_req = req->total;
	kore_strlcpy(logpacket.host, req->host, sizeof(logpacket.host));
	kore_strlcpy(logpacket.path, req->path, sizeof(logpacket.path));

	if (req->agent != NULL) {
		kore_strlcpy(logpacket.agent,
		    req->agent, sizeof(logpacket.agent));
	} else {
		kore_strlcpy(logpacket.agent, "unknown",
		    sizeof(logpacket.agent));
	}

	memset(logpacket.cn, '\0', sizeof(logpacket.cn));
#if !defined(KORE_NO_SSL)
	if (req->owner->cert != NULL) {
		if (X509_GET_CN(req->owner->cert,
		    logpacket.cn, sizeof(logpacket.cn)) == -1) {
			kore_log(LOG_WARNING, "client cert without a CN?");
		}
	}
#endif

	len = send(accesslog_fd[1], &logpacket, sizeof(logpacket), 0);
	if (len == -1) {
		kore_log(LOG_WARNING, "kore_accesslog(): send(): %s", errno_s);
	} else if (len != sizeof(logpacket)) {
		kore_log(LOG_WARNING, "short accesslog packet sent");
	}
}
