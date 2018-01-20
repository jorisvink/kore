/*
 * Copyright (c) 2017-2018 Joris Vink <joris@coders.se>
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

#include <kore/kore.h>
#include <kore/http.h>

/*
 * This example demonstrates how dynamically reloadable modules
 * can use the memory tagging system in Kore in order to restore
 * the global pointers in the module.
 */

/* Some unique value. */
#define MEM_TAG_HELLO		100

int		init(int);
int		page(struct http_request *);

/* Global pointer, gets initialized to NULL when module loads/reloads. */
char		*fixed_ptr = NULL;

int
init(int state)
{
	/* Ignore unload(s). */
	if (state == KORE_MODULE_UNLOAD)
		return (KORE_RESULT_OK);

	printf("fixed_ptr: %p\n", (void *)fixed_ptr);

	/* Attempt to lookup the original pointer. */
	if ((fixed_ptr = kore_mem_lookup(MEM_TAG_HELLO)) == NULL) {
		/* Failed, grab a new chunk of memory and tag it. */
		printf("  allocating fixed_ptr for the first time\n");
		fixed_ptr = kore_malloc_tagged(6, MEM_TAG_HELLO);
		kore_strlcpy(fixed_ptr, "hello", 6);
	} else {
		printf("  fixed_ptr address resolved\n");
	}

	printf("  fixed_ptr: %p\n", (void *)fixed_ptr);
	printf("  value    : %s\n", fixed_ptr);

	return (KORE_RESULT_OK);
}

int
page(struct http_request *req)
{
	http_response(req, 200, fixed_ptr, strlen(fixed_ptr));
	return (KORE_RESULT_OK);
}
