/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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
#include <time.h>

#include "kore.h"
#include "http.h"

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
#if !defined(KORE_NO_TLS)
	char		cn[X509_CN_LENGTH];
#endif
};

void
kore_accesslog_init(void)
{
}

void
kore_accesslog_worker_init(void)
{
	kore_domain_closelogs();
}

int
kore_accesslog_write(const void *data, u_int32_t len)
{
	int			l;
	time_t			now;
	ssize_t			sent;
	struct kore_domain	*dom;
	struct kore_log_packet	logpacket;
	char			addr[INET6_ADDRSTRLEN];
	char			*method, *buf, *tbuf, *cn;

	if (len != sizeof(struct kore_log_packet))
		return (KORE_RESULT_ERROR);

	(void)memcpy(&logpacket, data, sizeof(logpacket));

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
	case HTTP_METHOD_PATCH:
		method = "PATCH";
		break;
	default:
		method = "UNKNOWN";
		break;
	}

	cn = "none";
#if !defined(KORE_NO_TLS)
	if (logpacket.cn[0] != '\0')
		cn = logpacket.cn;
#endif

	if (inet_ntop(logpacket.addrtype, &(logpacket.addr),
	    addr, sizeof(addr)) == NULL)
		(void)kore_strlcpy(addr, "unknown", sizeof(addr));

	time(&now);
	tbuf = kore_time_to_date(now);
	l = asprintf(&buf, "[%s] %s %d %s %s (w#%d) (%dms) (%s) (%s)\n",
	    tbuf, addr, logpacket.status, method, logpacket.path,
	    logpacket.worker_id, logpacket.time_req, cn, logpacket.agent);
	if (l == -1) {
		kore_log(LOG_WARNING,
		    "kore_accesslog_write(): asprintf() == -1");
		return (KORE_RESULT_ERROR);
	}

	sent = write(dom->accesslog, buf, l);
	if (sent == -1) {
		free(buf);
		kore_log(LOG_WARNING,
		    "kore_accesslog_write(): write(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (sent != l)
		kore_log(LOG_NOTICE, "accesslog: %s", buf);

	free(buf);
	return (KORE_RESULT_OK);
}

void
kore_accesslog(struct http_request *req)
{
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

	if (kore_strlcpy(logpacket.host,
	    req->host, sizeof(logpacket.host)) >= sizeof(logpacket.host))
		kore_log(LOG_NOTICE, "kore_accesslog: host truncated");

	if (kore_strlcpy(logpacket.path,
	    req->path, sizeof(logpacket.path)) >= sizeof(logpacket.path))
		kore_log(LOG_NOTICE, "kore_accesslog: path truncated");

	if (req->agent != NULL) {
		if (kore_strlcpy(logpacket.agent, req->agent,
		    sizeof(logpacket.agent)) >= sizeof(logpacket.agent))
			kore_log(LOG_NOTICE, "kore_accesslog: agent truncated");
	} else {
		(void)kore_strlcpy(logpacket.agent, "unknown",
		    sizeof(logpacket.agent));
	}

#if !defined(KORE_NO_TLS)
	memset(logpacket.cn, '\0', sizeof(logpacket.cn));
	if (req->owner->cert != NULL) {
		if (X509_GET_CN(req->owner->cert,
		    logpacket.cn, sizeof(logpacket.cn)) == -1) {
			kore_log(LOG_WARNING, "client cert without a CN?");
		}
	}
#endif

	kore_msg_send(KORE_MSG_PARENT,
	    KORE_MSG_ACCESSLOG, &logpacket, sizeof(logpacket));
}
