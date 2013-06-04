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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <regex.h>
#include <zlib.h>

#include "spdy.h"
#include "kore.h"

static struct {
	char		*name;
	int		value;
} month_names[] = {
	{ "Jan",	0 },
	{ "Feb",	1 },
	{ "Mar",	2 },
	{ "Apr",	3 },
	{ "May",	4 },
	{ "Jun",	5 },
	{ "Jul",	6 },
	{ "Aug",	7 },
	{ "Sep",	8 },
	{ "Oct",	9 },
	{ "Nov",	10 },
	{ "Dec",	11 },
	{ NULL,		0 },
};

void *
kore_malloc(size_t len)
{
	void		*ptr;

	if ((ptr = malloc(len)) == NULL)
		fatal("kore_malloc(%d): %d", len, errno);

	memset(ptr, 0, len);
	return (ptr);
}

void *
kore_realloc(void *ptr, size_t len)
{
	void		*nptr;

	if ((nptr = realloc(ptr, len)) == NULL)
		fatal("kore_realloc(%p, %d): %d", ptr, len, errno);

	return (nptr);
}

void *
kore_calloc(size_t memb, size_t len)
{
	void		*ptr;

	if ((ptr = calloc(memb, len)) == NULL)
		fatal("kore_calloc(%d, %d): %d", memb, len, errno);

	memset(ptr, 0, memb * len);
	return (ptr);
}

char *
kore_strdup(const char *str)
{
	char		*nstr;

	if ((nstr = strdup(str)) == NULL)
		fatal("kore_strdup(): %d", errno);

	return (nstr);
}

void
kore_debug_internal(char *file, int line, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("[%d] %s:%d - %s\n", mypid, file, line, buf);
}

void
kore_log_init(void)
{
	openlog("kore", LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void
kore_log(int prio, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	syslog(prio, "%s", buf);
}

void
kore_strlcpy(char *dst, const char *src, size_t len)
{
	char		*d = dst;
	const char	*s = src;

	while ((*d++ = *s++) != '\0') {
		if (d == (dst + len - 1)) {
			*d = '\0';
			break;
		}
	}
}

long long
kore_strtonum(const char *str, long long min, long long max, int *err)
{
	long long	l;
	char		*ep;

	if (min > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	l = 0;
	errno = 0;
	l = strtoll(str, &ep, 10);
	if (errno != 0 || str == ep || *ep != '\0') {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	if (l < min) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	if (l > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	*err = KORE_RESULT_OK;
	return (l);
}

int
kore_split_string(char *input, char *delim, char **out, size_t ele)
{
	int		count;
	char		**ap;

	count = 0;
	for (ap = out; ap < &out[ele - 1] &&
	    (*ap = strsep(&input, delim)) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	*ap = NULL;
	return (count);
}

time_t
kore_date_to_time(char *http_date)
{
	time_t			t;
	int			err, i;
	struct tm		tm, *gtm;
	char			*args[7], *tbuf[5], *sdup;

	time(&t);
	gtm = gmtime(&t);
	sdup = kore_strdup(http_date);

	t = KORE_RESULT_ERROR;

	if (kore_split_string(sdup, " ", args, 7) != 6) {
		kore_debug("misformed http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_year = kore_strtonum(args[3], 2013, 2068, &err) - 1900;
	if (err == KORE_RESULT_ERROR || tm.tm_year < gtm->tm_year) {
		kore_debug("misformed year in http-date: '%s'", http_date);
		goto out;
	}

	for (i = 0; month_names[i].name != NULL; i++) {
		if (!strcmp(month_names[i].name, args[2])) {
			tm.tm_mon = month_names[i].value;
			break;
		}
	}

	if (month_names[i].name == NULL) {
		kore_debug("misformed month in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_mday = kore_strtonum(args[1], 1, 31, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed mday in http-date: '%s'", http_date);
		goto out;
	}

	if (kore_split_string(args[4], ":", tbuf, 5) != 3) {
		kore_debug("misformed HH:MM:SS in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_hour = kore_strtonum(tbuf[0], 1, 23, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed hour in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_min = kore_strtonum(tbuf[1], 1, 59, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed minutes in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_sec = kore_strtonum(tbuf[2], 0, 60, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed seconds in http-date: '%s'", http_date);
		goto out;
	}

	t = mktime(&tm);
	if (t == -1) {
		t = 0;
		kore_debug("mktime() on '%s' failed", http_date);
	}

out:
	free(sdup);
	return (t);
}

char *
kore_time_to_date(time_t now)
{
	struct tm		*tm;
	static time_t		last = 0;
	static char		tbuf[32];

	if (now != last) {
		last = now;

		tm = gmtime(&now);
		if (!strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %T GMT", tm)) {
			kore_debug("strftime() gave us NULL (%ld)", now);
			return (NULL);
		}
	}

	return (tbuf);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("%s\n", buf);
	exit(1);
}
