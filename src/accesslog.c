/*
 * Copyright (c) 2013-2018 Joris Vink <joris@coders.se>
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
	size_t		length;
	int		family;
	u_int8_t	addr[sizeof(struct in6_addr)];
	char		host[KORE_DOMAINNAME_LEN];
	char		path[HTTP_URI_LEN];
	char		agent[HTTP_USERAGENT_LEN];
	char		referer[HTTP_REFERER_LEN];
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
	struct tm		*tm;
	ssize_t			sent;
	struct kore_domain	*dom;
	struct kore_log_packet	logpacket;
	char			*method, *buf, *cn;
	char			addr[INET6_ADDRSTRLEN], tbuf[128];

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

	cn = "-";
#if !defined(KORE_NO_TLS)
	if (logpacket.cn[0] != '\0')
		cn = logpacket.cn;
#endif

	if (logpacket.family != AF_UNIX) {
		if (inet_ntop(logpacket.family, &(logpacket.addr),
		    addr, sizeof(addr)) == NULL)
			(void)kore_strlcpy(addr, "-", sizeof(addr));
	} else {
		(void)kore_strlcpy(addr, "unix-socket", sizeof(addr));
	}

	time(&now);
	tm = localtime(&now);
	(void)strftime(tbuf, sizeof(tbuf), "%d/%b/%Y:%H:%M:%S %z", tm);

	l = asprintf(&buf,
	    "%s - %s [%s] \"%s %s HTTP/1.1\" %d %zu \"%s\" \"%s\"\n",
	    addr, cn, tbuf, method, logpacket.path, logpacket.status,
	    logpacket.length, logpacket.referer, logpacket.agent);
	if (l == -1) {
		kore_log(LOG_WARNING,
		    "kore_accesslog_write(): asprintf(): %s", errno_s);
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
		kore_log(LOG_WARNING, "kore_accesslog_write(): short write");

	free(buf);
	return (KORE_RESULT_OK);
}

void
kore_accesslog(struct http_request *req)
{
	struct kore_log_packet	logpacket;

	logpacket.family = req->owner->family;

	switch (logpacket.family) {
	case AF_INET:
		memcpy(logpacket.addr,
		    &(req->owner->addr.ipv4.sin_addr),
		    sizeof(req->owner->addr.ipv4.sin_addr));
		break;
	case AF_INET6:
		memcpy(logpacket.addr,
		    &(req->owner->addr.ipv6.sin6_addr),
		    sizeof(req->owner->addr.ipv6.sin6_addr));
		break;
	default:
		break;
	}

	logpacket.status = req->status;
	logpacket.method = req->method;
	logpacket.length = req->content_length;

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
		(void)kore_strlcpy(logpacket.agent, "-",
		    sizeof(logpacket.agent));
	}

	if (req->referer != NULL) {
		if (kore_strlcpy(logpacket.referer, req->referer,
		    sizeof(logpacket.referer)) >= sizeof(logpacket.referer)) {
			kore_log(LOG_NOTICE,
			    "kore_accesslog: referer truncated");
		}
	} else {
		(void)kore_strlcpy(logpacket.referer, "-",
		    sizeof(logpacket.referer));
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
