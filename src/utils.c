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

static char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void
kore_debug_internal(char *file, int line, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("[%d] %s:%d - %s\n", kore_pid, file, line, buf);
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

	if (worker != NULL)
		syslog(prio, "[wrk %d]: %s", worker->id, buf);
	else
		syslog(prio, "[parent]: %s", buf);
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
kore_strtonum(const char *str, int base, long long min, long long max, int *err)
{
	long long	l;
	char		*ep;

	if (min > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	l = 0;
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

	tm.tm_year = kore_strtonum(args[3], 10, 2013, 2068, &err) - 1900;
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

	tm.tm_mday = kore_strtonum(args[1], 10, 1, 31, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed mday in http-date: '%s'", http_date);
		goto out;
	}

	if (kore_split_string(args[4], ":", tbuf, 5) != 3) {
		kore_debug("misformed HH:MM:SS in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_hour = kore_strtonum(tbuf[0], 10, 1, 23, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed hour in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_min = kore_strtonum(tbuf[1], 10, 1, 59, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_debug("misformed minutes in http-date: '%s'", http_date);
		goto out;
	}

	tm.tm_sec = kore_strtonum(tbuf[2], 10, 0, 60, &err);
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
	kore_mem_free(sdup);
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
kore_base64_encode(u_int8_t *data, u_int32_t len, char **out)
{
	struct kore_buf		*res;
	u_int8_t		n, *pdata;
	int			i, padding;
	u_int32_t		idx, b, plen;

	if ((len % 3) != 0) {
		padding = 3 - (len % 3);
		plen = len + padding;
		pdata = kore_malloc(plen);

		memcpy(pdata, data, len);
		memset(pdata + len, 0, padding);
	} else {
		plen = len;
		padding = 0;
		pdata = data;
	}

	res = kore_buf_create(plen);

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

				kore_buf_append(res,
				    (u_int8_t *)&(b64table[n]), 1);
			}

			b = 0;
			i = 2;
		}
	}

	for (i = 0; i < padding; i++)
		kore_buf_append(res, (u_int8_t *)"=", 1);

	if (pdata != data)
		kore_mem_free(pdata);

	pdata = kore_buf_release(res, &plen);
	*out = kore_malloc(plen + 1);
	kore_strlcpy(*out, (char *)pdata, plen + 1);
	kore_mem_free(pdata);

	return (KORE_RESULT_OK);
}

int
kore_base64_decode(char *in, u_int8_t **out, u_int32_t *olen)
{
	int			i;
	struct kore_buf		*res;
	u_int8_t		d, n, o;
	u_int32_t		b, len, idx;

	i = 3;
	b = 0;
	len = strlen(in);
	res = kore_buf_create(len);

	for (idx = 0; idx < len; idx++) {
		for (o = 0; o < sizeof(b64table); o++) {
			if (b64table[o] == in[idx]) {
				d = o;
				break;
			}
		}

		/* XXX - This could be bad? */
		if (o == sizeof(b64table))
			d = 0;

		b |= (d & 0x3f) << (i * 6);
		if (i-- == 0) {
			for (i = 2; i >= 0; i--) {
				n = (b >> (8 * i));
				kore_buf_append(res, &n, 1);
			}

			b = 0;
			i = 3;
		}
	}

	*out = kore_buf_release(res, olen);
	return (KORE_RESULT_OK);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	kore_log(LOG_ERR, "%s", buf);
	printf("kore: %s\n", buf);
	exit(1);
}
