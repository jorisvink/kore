/*
 * Copyright (c) 2022 Joris Vink <joris@coders.se>
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

#include <time.h>
#include <syslog.h>

#include "kore.h"

struct kore_wlog {
	int		prio;
	u_int16_t	wid;
	size_t		loglen;
	char		logmsg[];
};

static void	log_print(int, const char *, ...)
		    __attribute__((format (printf, 2, 3)));
static void	log_from_worker(struct kore_msg *, const void *);

static FILE	*fp = NULL;

void
kore_log_init(void)
{
#if defined(KORE_SINGLE_BINARY)
	extern const char	*__progname;
	const char		*name = kore_strdup(__progname);
#else
	const char		*name = "kore";
#endif

	fp = stdout;

	if (!kore_foreground)
		openlog(name, LOG_NDELAY | LOG_PID, LOG_DAEMON);

	kore_msg_register(KORE_MSG_WORKER_LOG, log_from_worker);
}

void
kore_log_file(const char *path)
{
	if ((fp = fopen(path, "a")) == NULL) {
		fp = stdout;
		fatal("fopen(%s): %s", path, errno_s);
	}
}

void
kore_log(int prio, const char *fmt, ...)
{
	va_list			args;
	const char		*str;
	struct kore_wlog	wlog;
	struct kore_buf		buf, pkt;

	kore_buf_init(&buf, 128);

	va_start(args, fmt);
	kore_buf_appendv(&buf, fmt, args);
	va_end(args);

	if (worker != NULL) {
		kore_buf_init(&pkt, sizeof(wlog) + buf.offset);

		memset(&wlog, 0, sizeof(wlog));

		wlog.prio = prio;
		wlog.wid = worker->id;
		wlog.loglen = buf.offset;

		kore_buf_append(&pkt, &wlog, sizeof(wlog));
		kore_buf_append(&pkt, buf.data, buf.offset);

		kore_msg_send(KORE_MSG_PARENT, KORE_MSG_WORKER_LOG,
		    pkt.data, pkt.offset);

		kore_buf_cleanup(&pkt);
	} else {
		str = kore_buf_stringify(&buf, NULL);

		if (kore_foreground || fp != stdout)
			log_print(prio, "[parent]: %s\n", str);
		else
			syslog(prio, "[parent]: %s", str);
	}

	kore_buf_cleanup(&buf);
}

static void
log_from_worker(struct kore_msg *msg, const void *data)
{
	const char		*name;
	const struct kore_wlog	*wlog;

	if (msg->length < sizeof(*wlog)) {
		kore_log(LOG_NOTICE,
		    "too short worker log received (%zu < %zu)",
		    msg->length, sizeof(*wlog));
		return;
	}

	wlog = data;
	name = kore_worker_name(wlog->wid);

	if (kore_foreground || fp != stdout) {
		log_print(wlog->prio, "%s: %.*s\n",
		    name, (int)wlog->loglen, wlog->logmsg);
	} else {
		syslog(wlog->prio, "%s: %.*s",
		    name, (int)wlog->loglen, wlog->logmsg);
	}
}

static void
log_print(int prio, const char *fmt, ...)
{
	struct tm		*t;
	struct timespec		ts;
	va_list			args;
	char			tbuf[32];

	va_start(args, fmt);

	switch (prio) {
	case LOG_ERR:
	case LOG_WARNING:
	case LOG_NOTICE:
	case LOG_INFO:
	case LOG_DEBUG:
		break;
	}

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	t = gmtime(&ts.tv_sec);

	if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", t) > 0)
		fprintf(fp, "%s.%03ld UTC ", tbuf, ts.tv_nsec / 1000000);

	vfprintf(fp, fmt, args);
	fflush(fp);

	va_end(args);
}
