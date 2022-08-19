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

static void	fatal_log(const char *, va_list);
static int	utils_base64_encode(const void *, size_t, char **,
		    const char *, int);
static int	utils_base64_decode(const char *, u_int8_t **,
		    size_t *, const char *, int);
static int	utils_x509name_tobuf(void *, int, int, const char *,
		    const void *, size_t, int);

static char b64_table[] = 	\
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char b64url_table[] = 	\
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* b64_table and b64url_table are the same size. */
#define B64_TABLE_LEN		(sizeof(b64_table))

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

double
kore_strtodouble(const char *str, long double min, long double max, int *err)
{
	double		d;
	char		*ep;

	if (min > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	errno = 0;
	d = strtod(str, &ep);
	if (errno == ERANGE || str == ep || *ep != '\0') {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	if (d < min) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	if (d > max) {
		*err = KORE_RESULT_ERROR;
		return (0);
	}

	*err = KORE_RESULT_OK;
	return (d);
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
kore_date_to_time(const char *http_date)
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
		kore_log(LOG_WARNING, "misformed http-date: '%s'", http_date);
		goto out;
	}

	memset(&tm, 0, sizeof(tm));

	tm.tm_year = kore_strtonum(args[3], 10, 1900, 2068, &err) - 1900;
	if (err == KORE_RESULT_ERROR) {
		kore_log(LOG_WARNING, "misformed year in http-date: '%s'",
		    http_date);
		goto out;
	}

	for (i = 0; month_names[i].name != NULL; i++) {
		if (!strcmp(month_names[i].name, args[2])) {
			tm.tm_mon = month_names[i].value;
			break;
		}
	}

	if (month_names[i].name == NULL) {
		kore_log(LOG_WARNING, "misformed month in http-date: '%s'",
		    http_date);
		goto out;
	}

	tm.tm_mday = kore_strtonum(args[1], 10, 1, 31, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_log(LOG_WARNING, "misformed mday in http-date: '%s'",
		    http_date);
		goto out;
	}

	if (kore_split_string(args[4], ":", tbuf, 5) != 3) {
		kore_log(LOG_WARNING, "misformed HH:MM:SS in http-date: '%s'",
		    http_date);
		goto out;
	}

	tm.tm_hour = kore_strtonum(tbuf[0], 10, 0, 23, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_log(LOG_WARNING, "misformed hour in http-date: '%s'",
		    http_date);
		goto out;
	}

	tm.tm_min = kore_strtonum(tbuf[1], 10, 0, 59, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_log(LOG_WARNING, "misformed minutes in http-date: '%s'",
		    http_date);
		goto out;
	}

	tm.tm_sec = kore_strtonum(tbuf[2], 10, 0, 60, &err);
	if (err == KORE_RESULT_ERROR) {
		kore_log(LOG_WARNING, "misformed seconds in http-date: '%s'",
		    http_date);
		goto out;
	}

	tm.tm_isdst = ltm->tm_isdst;
	t = mktime(&tm) + ltm->tm_gmtoff;
	if (t == -1) {
		t = 0;
		kore_log(LOG_WARNING, "mktime() on '%s' failed", http_date);
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
		if (!strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %T GMT", tm))
			return (NULL);
	}

	return (tbuf);
}

u_int64_t
kore_time_ms(void)
{
	struct timespec		ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((u_int64_t)(ts.tv_sec * 1000 + (ts.tv_nsec / 1000000)));
}

int
kore_base64url_encode(const void *data, size_t len, char **out, int flags)
{
	return (utils_base64_encode(data, len, out, b64url_table, flags));
}

int
kore_base64_encode(const void *data, size_t len, char **out)
{
	return (utils_base64_encode(data, len, out, b64_table, 0));
}

int
kore_base64url_decode(const char *in, u_int8_t **out, size_t *olen, int flags)
{
	return (utils_base64_decode(in, out, olen, b64url_table, flags));
}

int
kore_base64_decode(const char *in, u_int8_t **out, size_t *olen)
{
	return (utils_base64_decode(in, out, olen, b64_table, 0));
}

void *
kore_mem_find(void *src, size_t slen, const void *needle, size_t len)
{
	size_t		pos;

	for (pos = 0; pos < slen; pos++) {
		if ( *((u_int8_t *)src + pos) != *(const u_int8_t *)needle)
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

const char *
kore_worker_name(int id)
{
	static char	buf[64];

	switch (id) {
	case KORE_WORKER_KEYMGR:
		(void)snprintf(buf, sizeof(buf), "[keymgr]");
		break;
	case KORE_WORKER_ACME:
		(void)snprintf(buf, sizeof(buf), "[acme]");
		break;
	default:
		(void)snprintf(buf, sizeof(buf), "[wrk %d]", id);
		break;
	}

	return (buf);
}

int
kore_x509_issuer_name(struct connection *c, char **out, int flags)
{
	struct kore_buf		buf;
	KORE_X509_NAMES		*name;

	if ((name = kore_tls_x509_issuer_name(c)) == NULL)
		return (KORE_RESULT_ERROR);

	kore_buf_init(&buf, 1024);

	if (!kore_tls_x509name_foreach(name, flags, &buf,
	    utils_x509name_tobuf)) {
		kore_buf_cleanup(&buf);
		return (KORE_RESULT_ERROR);
	}

	*out = kore_buf_stringify(&buf, NULL);

	buf.offset = 0;
	buf.data = NULL;

	return (KORE_RESULT_OK);
}

int
kore_x509_subject_name(struct connection *c, char **out, int flags)
{
	struct kore_buf		buf;
	KORE_X509_NAMES		*name;

	if ((name = kore_tls_x509_subject_name(c)) == NULL)
		return (KORE_RESULT_ERROR);

	kore_buf_init(&buf, 1024);

	if (!kore_tls_x509name_foreach(name, flags, &buf,
	    utils_x509name_tobuf)) {
		kore_buf_cleanup(&buf);
		return (KORE_RESULT_ERROR);
	}

	*out = kore_buf_stringify(&buf, NULL);

	buf.offset = 0;
	buf.data = NULL;

	return (KORE_RESULT_OK);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	fatal_log(fmt, args);
	va_end(args);

	exit(1);
}

void
fatalx(const char *fmt, ...)
{
	va_list		args;

	/* In case people call fatalx() from the parent context. */
	if (worker != NULL)
		kore_msg_send(KORE_MSG_PARENT, KORE_MSG_FATALX, NULL, 0);

	va_start(args, fmt);
	fatal_log(fmt, args);
	va_end(args);

	exit(1);
}

static void
fatal_log(const char *fmt, va_list args)
{
	char			buf[2048];

	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	kore_log(LOG_ERR, "fatal: %s", buf);

	if (worker != NULL && worker->id == KORE_WORKER_KEYMGR)
		kore_keymgr_cleanup(1);
}

static int
utils_x509name_tobuf(void *udata, int islast, int nid, const char *field,
    const void *data, size_t len, int flags)
{
	struct kore_buf		*buf = udata;

	if (flags & KORE_X509_COMMON_NAME_ONLY) {
		if (nid == KORE_X509_NAME_COMMON_NAME)
			kore_buf_append(buf, data, len);
	} else {
		kore_buf_appendf(buf, "%s=", field);
		kore_buf_append(buf, data, len);
		if (!islast)
			kore_buf_appendf(buf, " ");
	}

	return (KORE_RESULT_OK);
}

static int
utils_base64_encode(const void *data, size_t len, char **out,
    const char *table, int flags)
{
	u_int8_t		n;
	size_t			nb;
	const u_int8_t		*ptr;
	u_int32_t		bytes;
	struct kore_buf		result;

	nb = 0;
	ptr = data;
	kore_buf_init(&result, (len / 3) * 4);

	while (len > 0) {
		if (len > 2) {
			nb = 3;
			bytes = *ptr++ << 16;
			bytes |= *ptr++ << 8;
			bytes |= *ptr++;
		} else if (len > 1) {
			nb = 2;
			bytes = *ptr++ << 16;
			bytes |= *ptr++ << 8;
		} else if (len == 1) {
			nb = 1;
			bytes = *ptr++ << 16;
		} else {
			kore_buf_cleanup(&result);
			return (KORE_RESULT_ERROR);
		}

		n = (bytes >> 18) & 0x3f;
		kore_buf_append(&result, &(table[n]), 1);
		n = (bytes >> 12) & 0x3f;
		kore_buf_append(&result, &(table[n]), 1);
		if (nb > 1) {
			n = (bytes >> 6) & 0x3f;
			kore_buf_append(&result, &(table[n]), 1);
			if (nb > 2) {
				n = bytes & 0x3f;
				kore_buf_append(&result, &(table[n]), 1);
			}
		}

		len -= nb;
	}

	if (!(flags & KORE_BASE64_RAW)) {
		switch (nb) {
		case 1:
			kore_buf_appendf(&result, "==");
			break;
		case 2:
			kore_buf_appendf(&result, "=");
			break;
		case 3:
			break;
		default:
			kore_buf_cleanup(&result);
			return (KORE_RESULT_ERROR);
		}
	}

	/* result.data gets taken over so no need to cleanup result. */
	*out = kore_buf_stringify(&result, NULL);

	return (KORE_RESULT_OK);
}

static int
utils_base64_decode(const char *in, u_int8_t **out, size_t *olen,
    const char *table, int flags)
{
	int			i, c;
	u_int8_t		d, n, o;
	struct kore_buf		*res, buf;
	const char		*ptr, *pad;
	u_int32_t		b, len, plen, idx;

	i = 4;
	b = 0;
	d = 0;
	c = 0;
	len = strlen(in);
	memset(&buf, 0, sizeof(buf));

	if (flags & KORE_BASE64_RAW) {
		switch (len % 4) {
		case 2:
			plen = 2;
			pad = "==";
			break;
		case 3:
			plen = 1;
			pad = "=";
			break;
		default:
			return (KORE_RESULT_ERROR);
		}

		kore_buf_init(&buf, len + plen);
		kore_buf_append(&buf, in, len);
		kore_buf_append(&buf, pad, plen);

		len = len + plen;
		ptr = (const char *)buf.data;
	} else {
		ptr = in;
	}

	res = kore_buf_alloc(len);

	for (idx = 0; idx < len; idx++) {
		c = ptr[idx];
		if (c == '=')
			break;

		for (o = 0; o < B64_TABLE_LEN; o++) {
			if (table[o] == c) {
				d = o;
				break;
			}
		}

		if (o == B64_TABLE_LEN) {
			*out = NULL;
			kore_buf_free(res);
			kore_buf_cleanup(&buf);
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
			kore_buf_cleanup(&buf);
			return (KORE_RESULT_ERROR);
		}

		o = i;
		for (i = 2; i >= o; i--) {
			n = (b >> (8 * i));
			kore_buf_append(res, &n, 1);
		}
	}

	kore_buf_cleanup(&buf);
	*out = kore_buf_release(res, olen);

	return (KORE_RESULT_OK);
}
