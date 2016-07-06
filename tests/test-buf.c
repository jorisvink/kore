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
#include <stdio.h>

#include "kore.h"
#include "unit.h"

void test_kore_buf_append(void);
void test_kore_buf_appendb(void);
void test_kore_buf_appendf(void);
void test_kore_buf_release(void);
void test_kore_buf_replace_string(void);

void
test_kore_buf_append(void)
{
	struct kore_buf *buf;
	const char		*expected, *actual;

	printf("Running test_kore_buf_append...\n");

	expected = "a test value";
	buf = kore_buf_create(1024);
	kore_buf_append(buf, (const void *)expected, strlen(expected));
	actual = (const char *) buf->data;

	assert_strings(expected, actual);
	kore_buf_free(buf);
}

void
test_kore_buf_appendb(void)
{
	struct kore_buf *buf1;
	struct kore_buf *buf2;
	const char		*expected1, *expected2, *actual1;
	char			expected[BUFSIZ];

	printf("Running test_kore_buf_appendb...\n");

	expected1 = "buf 1";
	buf1 = kore_buf_create(1024);
	kore_buf_append(buf1, (const void *)expected1, strlen(expected1));

	expected2 = "buf 2";
	buf2 = kore_buf_create(1024);
	kore_buf_append(buf2, (const void *)expected2, strlen(expected2));

	kore_buf_appendb(buf1, buf2);

	/* verify actual1 has both strings */
	actual1 = (const char *) buf1->data;
	snprintf(expected, sizeof(expected), "%s%s", expected1, expected2);
	assert_strings(expected, actual1);

	kore_buf_free(buf1);
}

void
test_kore_buf_appendf(void)
{
	struct kore_buf *buf;
	const char		*initial, *actual;
	char			*format, expected[BUFSIZ];

	printf("Running test_kore_buf_appendf...\n");

	initial = "a test value";
	buf = kore_buf_create(1024);
	kore_buf_append(buf, (const void *)initial, strlen(initial));

	format = "%s %s %s %s %s";
	snprintf(expected, sizeof(expected), format, initial, "a", "b", "c", "d");

	kore_buf_appendf(buf, " %s %s %s %s", "a", "b", "c", "d");

	actual = (const char *)buf->data;
	assert_strings(expected, actual);

	kore_buf_free(buf);
}

void
test_kore_buf_release(void)
{
	struct kore_buf *buf;
	const char		*expected;
	u_int32_t		len;
	char			*actual;

	printf("Running test_kore_buf_release...\n");

	expected = "buf 1";
	buf = kore_buf_create(1024);
	kore_buf_append(buf, (const void*)expected, strlen(expected));

	actual = (char *) kore_buf_release(buf, &len);
	assert_strings(expected, (const char *) actual);

	kore_mem_free(actual);
}

void
test_kore_buf_replace_string(void)
{
	struct kore_buf	*buf;
	const char		*base, *original_format, *replace_with,
					*format, *actual;
	char			*to_replace, original[BUFSIZ], expected[BUFSIZ];

	printf("Running test_kore_buf_replace_string...\n");

	base = "a string";
	to_replace = "{replace me}";
	original_format = "%s %s";
	snprintf(original, sizeof(original), original_format, base, to_replace);

	buf = kore_buf_create(1024);
	kore_buf_append(buf, (const void *)original, strlen(original));

	replace_with = "replaced";
	format = "%s %s";
	snprintf(expected, sizeof(expected), format, base, replace_with);

	kore_buf_replace_string(buf, to_replace, (void *)replace_with,
			(size_t)strlen(replace_with));

	actual = (const char *) buf->data;
	assert_strings(expected, actual);

	kore_buf_free(buf);
}
