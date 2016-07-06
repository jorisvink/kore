/*
 * Copyright (c) 2014 Sam Garrett <samdgarrett@gmail.com>
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

#include <assert.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>

#include "kore.h"
#include "unit.h"

void test_kore_date_to_time(void);
void test_kore_time_to_date(void);
void test_kore_time_ms(void);
void test_kore_base64_encode(void);
void test_kore_base64_decode(void);
void test_kore_strtonum64(void);
void test_kore_strtonum(void);
void test_kore_snprintf(void);
void test_kore_strlcpy(void);
void test_kore_split_string(void);

void
test_kore_date_to_time(void)
{
	char	*http_date;
	time_t	expected, actual;
	char	expected_str[BUFSIZ], actual_str[BUFSIZ];

	printf("Running test_kore_date_to_time...\n");

	http_date = "Sun, 04 Jan 2015 08:35:27 EST";
	actual = kore_date_to_time(http_date);
	expected = (time_t) 1420378527;

	snprintf(expected_str, sizeof(expected_str), "%ld", expected);
	snprintf(actual_str, sizeof(actual_str), "%ld", actual);

	assert_strings(expected_str, actual_str);
}

void
test_kore_time_to_date(void)
{
	time_t	a_time;
	char	*expected, *actual;

	printf("Running test_kore_time_to_date...\n");

	expected = "Sun, 04 Jan 2015 13:35:27 GMT";
	a_time = (time_t) 1420378527;
	actual = kore_time_to_date(a_time);

	assert_strings(expected, actual);
}

void
test_kore_time_ms(void)
{
	// using expected datetime from test_kore_time_to_date
	// converted to ms for verifying expected_lt < actual (current ms)
	u_int64_t	expected_lt = 1420378527000;
	u_int64_t	actual;

	printf("Running test_kore_time_ms...\n");

	actual = kore_time_ms();
	assert(expected_lt < actual);
}

void
test_kore_base64_encode(void)
{
	int			resp;
	u_int32_t	len;
	char		expected[BUFSIZ];
	char		*actual, *data = "http://kore.io";

	printf("Running test_kore_base64_encode...\n");

	len = strlen((const char *)data);
	snprintf(expected, sizeof(expected), "%s", "aHR0cDovL2tvcmUuaW8=");

	resp = kore_base64_encode((u_int8_t *)data, len, &actual);

	assert(KORE_RESULT_OK == resp);
	assert_strings(expected, actual);

    kore_mem_free(actual);
}

void
test_kore_base64_decode(void)
{
	int			resp;
	u_int32_t	olen;
	char		expected[BUFSIZ];
	char		*actual, *in = "aHR0cDovL2tvcmUuaW8=";

	printf("Running test_kore_base64_decode...\n");

	olen = strlen(in);
	snprintf(expected, sizeof(expected), "%s", "http://kore.io");

	resp = kore_base64_decode(in, (u_int8_t **)&actual, (u_int32_t *)&olen);

	assert(KORE_RESULT_OK == resp);
	assert_strings(expected, actual);

    kore_mem_free(actual);
}

void
test_kore_strtonum64(void)
{
	u_int64_t	expected, actual;
	char		str[BUFSIZ];
	int			sign = 1;
	int			err = KORE_RESULT_OK;

	printf("Running test_kore_strtonum64...\n");

	expected = LLONG_MAX;
	snprintf(str, sizeof(str), "%" PRIu64, expected);

	actual = kore_strtonum64(str, sign, &err);

	assert(KORE_RESULT_OK == err);
	assert(expected == actual);
}

void
test_kore_strtonum(void)
{
	u_int64_t	expected, actual;
	char		str[BUFSIZ];
	int			base = 10;
	int			err = KORE_RESULT_OK;

	printf("Running test_kore_strtonum...\n");

	expected = LLONG_MAX;
	snprintf(str, sizeof(str), "%" PRIu64, expected);

	actual = kore_strtonum(str, base, LLONG_MIN, LLONG_MAX, &err);

	assert(KORE_RESULT_OK == err);
	assert(expected == actual);
}

void
test_kore_snprintf(void)
{
	char	expected[BUFSIZ], actual[BUFSIZ];
	int		err;
	int		len = 0;

	printf("Running test_kore_snprintf...\n");

	snprintf(expected, sizeof(expected), "%s", "an expected string");

	err = kore_snprintf(actual, sizeof(actual), &len, "%s", expected);

	assert(KORE_RESULT_OK == err);
	assert_strings(expected, actual);
}

void
test_kore_strlcpy(void)
{
	char	expected[BUFSIZ], actual[BUFSIZ];

	printf("Running test_kore_strlcpy...\n");

	snprintf(expected, sizeof(expected), "%s", "an expected string");

	kore_strlcpy(actual, expected, strlen(expected)+1);

	assert_strings(expected, actual);
	assert('\0' == actual[strlen(actual)]);
}

void
test_kore_split_string(void)
{
	char	*expected[BUFSIZ], *actual[BUFSIZ];
	char	input[BUFSIZ];
	char	*delim = "&";
	int		expected_count = 3, count;
	int		ele = expected_count + 1; // +1 because of NULL term
	int		i;

	printf("Running test_kore_split_string...\n");

	snprintf(input, sizeof(input), "a %s b %s c", delim, delim);

	expected[0] = "a ";
	expected[1] = " b ";
	expected[2] = " c";

	count = kore_split_string(input, delim, actual, ele);

	assert(expected_count == count);
	for (i = 0; i < expected_count; i++) {
		assert_strings(expected[i], actual[i]);
	}
	assert('\0' == actual[ele]);
}
