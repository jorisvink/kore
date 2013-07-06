/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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
	struct in_addr	src;
	char		host[KORE_DOMAINNAME_LEN];
	char		path[HTTP_URI_LEN];
	char		agent[HTTP_USERAGENT_LEN];
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
	size_t			slen;
	int			nfds;
	struct kore_domain	*dom;
	struct pollfd		pfd[1];
	struct kore_log_packet	logpacket;
	char			*method, buf[4096], *tbuf;

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

	if (logpacket.method == HTTP_METHOD_GET)
		method = "GET";
	else
		method = "POST";

	time(&now);
	tbuf = kore_time_to_date(now);
	snprintf(buf, sizeof(buf), "[%s] %s %d %s %s (w#%d) (%dms) (%s)\n",
	    tbuf, inet_ntoa(logpacket.src), logpacket.status, method,
	    logpacket.path, logpacket.worker_id, logpacket.time_req,
	    logpacket.agent);
	slen = strlen(buf);

	len = write(dom->accesslog, buf, slen);
	if (len == -1) {
		kore_log(LOG_WARNING,
		    "kore_accesslog_wait(): write(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if ((size_t)len != slen)
		kore_log(LOG_NOTICE, "accesslog: %s", buf);

	return (KORE_RESULT_OK);
}

void
kore_accesslog(struct http_request *req)
{
	ssize_t			len;
	struct kore_log_packet	logpacket;

	logpacket.status = req->status;
	logpacket.method = req->method;
	logpacket.worker_id = worker->id;
	logpacket.worker_cpu = worker->cpu;
	logpacket.src = req->owner->sin.sin_addr;
	logpacket.time_req = req->end - req->start;
	kore_strlcpy(logpacket.host, req->host, sizeof(logpacket.host));
	kore_strlcpy(logpacket.path, req->path, sizeof(logpacket.path));

	if (req->agent != NULL) {
		kore_strlcpy(logpacket.agent,
		    req->agent, sizeof(logpacket.agent));
	} else {
		kore_strlcpy(logpacket.agent, "unknown",
		    sizeof(logpacket.agent));
	}

	len = send(accesslog_fd[1], &logpacket, sizeof(logpacket), 0);
	if (len == -1) {
		kore_log(LOG_WARNING, "kore_accesslog(): send(): %s", errno_s);
	} else if (len != sizeof(logpacket)) {
		kore_log(LOG_WARNING, "short accesslog packet sent");
	}
}
