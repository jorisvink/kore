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

#include "test-buf.c"
#include "test-utils.c"

void test_buf(void);
void test_utils(void);

void
test_buf(void)
{
	test_kore_buf_append();
	test_kore_buf_appendb();
	test_kore_buf_appendf();
	test_kore_buf_release();
	test_kore_buf_replace_string();
}

void
test_utils(void)
{
	/* Fails because GMT is assumed:
	test_kore_date_to_time();
	*/
	test_kore_time_to_date();
	test_kore_time_ms();
	test_kore_base64_encode();
	test_kore_base64_decode();
	test_kore_strtonum64();
	test_kore_strtonum();
	test_kore_snprintf();
	test_kore_strlcpy();
	test_kore_split_string();
}

int
main(int argc, char *argv[])
{
	test_buf();
	test_utils();
	return (0);
}
