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

#include <sys/time.h>

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

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

static char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void
kore_debug_internal(char *file, int line, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("[%d] %s:%d - %s\n", kore_pid, file, line, buf);
}

void
kore_log_init(void)
{
#if defined(KORE_SINGLE_BINARY)
	extern const char	*__progname;
	const char		*name = __progname;
#else
	const char		*name = "kore";
#endif

	if (!foreground)
		openlog(name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void
kore_log(int prio, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048], tmp[32];

	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (worker != NULL) {
		(void)snprintf(tmp, sizeof(tmp), "wrk %d", worker->id);
#if !defined(KORE_NO_TLS)
		if (worker->id == KORE_WORKER_KEYMGR)
			(void)kore_strlcpy(tmp, "keymgr", sizeof(tmp));
#endif
		if (foreground)
			printf("[%s]: %s\n", tmp, buf);
		else
			syslog(prio, "[%s]: %s", tmp, buf);
	} else {
		if (foreground)
			printf("[parent]: %s\n", buf);
		else
			syslog(prio, "[parent]: %s", buf);
	}
}

size_t
kore_strlcpy(char *dst, const char *src, const size_t len)
{
	char		*d = dst;
	const char	*s = src;
	const char	*end = dst + len - 1;

	if (len == 0)
		fatal("kore_strlcpy: len == 0");

	while ((*d = *s) != '\0') {
		if (d == end) {
			*d = '\0';
			break;
		}

		d++;
		s++;
	}

	while (*s != '\0')
		s++;

	return (s - src);
}

int
kore_snprintf(char *str, size_t size, int *len, const char *fmt, ...)
{
	int		l;
	va_list		args;

	va_start(args, fmt);
	l = vsnprintf(str, size, fmt, args);
	va_end(args);

	if (l == -1 || (size_t)l >= size)
		return (KORE_RESULT_ERROR);

	if (len != NULL)
		*len = l;

	return (KORE_RESULT_OK);
}

long long
kore_strtonum(const char *str, int base, long long min, long long max, int *err)
{
	long long	l;
	char		*ep;

	if (min > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	errno = 0;
	l = strtoll(str, &ep, base);
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

u_int64_t
kore_strtonum64(const char *str, int sign, int *err)
{
	u_int64_t	l;
	long long	ll;
	char		*ep;
	int		check;

	l = 0;
	check = 1;

	ll = strtoll(str, &ep, 10);
	if ((errno == EINVAL || errno == ERANGE) &&
	    (ll == LLONG_MIN || ll == LLONG_MAX)) {
		if (sign) {
			*err = KORE_RESULT_ERROR;
			return (0);
		}

		check = 0;
	}

	if (!sign) {
		l = strtoull(str, &ep, 10);
		if ((errno == EINVAL || errno == ERANGE) && l == ULONG_MAX) {
			*err = KORE_RESULT_ERROR;
			return (0);
		}

		if (check && ll < 0) {
			*err = KORE_RESULT_ERROR;
			return (0);
		}
	}

	if (str == ep || *ep != '\0') {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	*err = KORE_RESULT_OK;
	return ((sign) ? (u_int64_t)ll : l);
}

int
kore_split_string(char *input, const char *delim, char **out, size_t ele)
{
	int		count;
	char		**ap;

	if (ele == 0)
		return (0);

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

void
kore_strip_chars(char *in, const char strip, char **out)
{
	u_int32_t	len;
	char		*s, *p;

	len = strlen(in);
	*out = kore_malloc(len + 1);
	p = *out;

	for (s = in; s < (in + len); s++) {
		if (*s == strip)
			continue;

		*p++ = *s;
	}

	*p = '\0';
}

time_t
kore_date_to_time(char *http_date)
{
	time_t			t;
	int			err, i;
	struct tm		tm, *ltm;
	char			*args[7], *tbuf[5], *sdup;

	time(&t);
	ltm = localtime(&t);
	sdup = kore_strdup(http_date);

	t = KORE_RESULT_ERROR;

	if (kore_split_string(sdup, " ", args, 7) != 6) {
		kore_debug("misformed http-date: '%s'", http_date);
		goto out;
	}

	memset(&tm, 0, sizeof(tm));

	tm.tm_year = kore_strtonum(args[3], 10, 1900, 2068, &err) - 1900;
	if (err == KORE_RESULT_ERROR) {
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

	tm.tm_mday = kore_strtonum(args[1], 10, 1, 31, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed mday in http-date: '%s'", http_date);
		goto out;
	}

	if (kore_split_string(args[4], ":", tbuf, 5) != 3) {
		kore_debug("misformed HH:MM:SS in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_hour = kore_strtonum(tbuf[0], 10, 0, 23, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed hour in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_min = kore_strtonum(tbuf[1], 10, 0, 59, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed minutes in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_sec = kore_strtonum(tbuf[2], 10, 0, 60, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed seconds in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_isdst = ltm->tm_isdst;
	t = mktime(&tm) + ltm->tm_gmtoff;
	if (t == -1) {
		t = 0;
		kore_debug("mktime() on '%s' failed", http_date);
	}

out:
	kore_free(sdup);
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

u_int64_t
kore_time_ms(void)
{
	struct timeval		tv;

	if (gettimeofday(&tv, NULL) == -1)
		return (0);

	return (tv.tv_sec * 1000 + (tv.tv_usec / 1000));
}

int
kore_base64_encode(u_int8_t *data, size_t len, char **out)
{
	u_int32_t		b;
	struct kore_buf		*res;
	size_t			plen, idx;
	u_int8_t		n, *pdata;
	int			i, padding;

	if ((len % 3) != 0) {
		padding = 3 - (len % 3);
		plen = len + padding;
		if (plen < len)
			fatal("plen wrapped");

		pdata = kore_malloc(plen);
		memcpy(pdata, data, len);
		memset(pdata + len, 0, padding);
	} else {
		plen = len;
		padding = 0;
		pdata = data;
	}

	res = kore_buf_alloc(plen);

	i = 2;
	b = 0;
	for (idx = 0; idx < plen; idx++) {
		b |= (pdata[idx] << (i * 8));
		if (i-- == 0) {
			for (i = 3; i >= 0; i--) {
				n = (b >> (6 * i)) & 0x3f;
				if (n >= sizeof(b64table)) {
					kore_debug("unable to encode %d", n);
					kore_buf_free(res);
					return (KORE_RESULT_ERROR);
				}

				if (idx >= len && i < padding)
					break;

				kore_buf_append(res, &(b64table[n]), 1);
			}

			b = 0;
			i = 2;
		}
	}

	for (i = 0; i < padding; i++)
		kore_buf_append(res, (u_int8_t *)"=", 1);

	if (pdata != data)
		kore_free(pdata);

	pdata = kore_buf_release(res, &plen);
	if ((plen + 1) < plen)
		fatal("plen wrapped");

	*out = kore_malloc(plen + 1);
	(void)kore_strlcpy(*out, (char *)pdata, plen + 1);
	kore_free(pdata);

	return (KORE_RESULT_OK);
}

int
kore_base64_decode(char *in, u_int8_t **out, size_t *olen)
{
	int			i, c;
	struct kore_buf		*res;
	u_int8_t		d, n, o;
	u_int32_t		b, len, idx;

	i = 4;
	b = 0;
	d = 0;
	c = 0;
	len = strlen(in);
	res = kore_buf_alloc(len);

	for (idx = 0; idx < len; idx++) {
		c = in[idx];
		if (c == '=')
			break;

		for (o = 0; o < sizeof(b64table); o++) {
			if (b64table[o] == c) {
				d = o;
				break;
			}
		}

		if (o == sizeof(b64table)) {
			*out = NULL;
			kore_buf_free(res);
			return (KORE_RESULT_ERROR);
		}

		b |= (d & 0x3f) << ((i - 1) * 6);
		i--;
		if (i == 0) {
			for (i = 2; i >= 0; i--) {
				n = (b >> (8 * i));
				kore_buf_append(res, &n, 1);
			}

			b = 0;
			i = 4;
		}
	}

	if (c == '=') {
		if (i > 2) {
			*out = NULL;
			kore_buf_free(res);
			return (KORE_RESULT_ERROR);
		}

		o = i;
		for (i = 2; i >= o; i--) {
			n = (b >> (8 * i));
			kore_buf_append(res, &n, 1);
		}
	}

	*out = kore_buf_release(res, olen);
	return (KORE_RESULT_OK);
}

void *
kore_mem_find(void *src, size_t slen, void *needle, size_t len)
{
	size_t		pos;

	for (pos = 0; pos < slen; pos++) {
		if ( *((u_int8_t *)src + pos) != *(u_int8_t *)needle)
			continue;

		if ((slen - pos) < len)
			return (NULL);

		if (!memcmp((u_int8_t *)src + pos, needle, len))
			return ((u_int8_t *)src + pos);
	}

	return (NULL);
}

char *
kore_text_trim(char *string, size_t len)
{
	char		*end;

	if (len == 0)
		return (string);

	end = (string + len) - 1;
	while (isspace(*(unsigned char *)string) && string < end)
		string++;

	while (isspace(*(unsigned char *)end) && end > string)
		*(end)-- = '\0';

	return (string);
}

char *
kore_read_line(FILE *fp, char *in, size_t len)
{
	char	*p, *t;

	if (fgets(in, len, fp) == NULL)
		return (NULL);

	p = in;
	in[strcspn(in, "\n")] = '\0';

	while (isspace(*(unsigned char *)p))
		p++;

	if (p[0] == '#' || p[0] == '\0') {
		p[0] = '\0';
		return (p);
	}

	for (t = p; *t != '\0'; t++) {
		if (*t == '\t')
			*t = ' ';
	}

	return (p);
}

void
fatal(const char *fmt, ...)
{
	va_list			args;
	char			buf[2048];
	extern const char	*__progname;

	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (!foreground)
		kore_log(LOG_ERR, "%s", buf);

#if !defined(KORE_NO_TLS)
	if (worker != NULL && worker->id == KORE_WORKER_KEYMGR)
		kore_keymgr_cleanup();
#endif

	printf("%s: %s\n", __progname, buf);
	exit(1);
}
