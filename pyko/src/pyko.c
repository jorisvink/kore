/*
 * Copyright (c) 2018 Joris Vink <joris@coders.se>
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
#include <sys/stat.h>

#include <kore/kore.h>

#include <stdio.h>
#include <limits.h>

void
kore_parent_configure(int argc, char **argv)
{
	struct stat	st;
	int		len;
	FILE		*fp;
	char		config[PATH_MAX];

	if (argc != 1)
		fatal("Usage: pyko [python app]");

	if (stat(argv[0], &st) == -1)
		fatal("stat(%s): %s", argv[0], errno_s);

	if (!S_ISDIR(st.st_mode))
		fatal("python module directory required");

	len = snprintf(config, sizeof(config), "%s/kore.conf", argv[0]);
	if (len == -1 || (size_t)len >= sizeof(config))
		fatal("failed to create configuration path");

	if ((fp = fopen(config, "r")) == NULL)
		fatal("failed to open configuration '%s'", config);

	kore_module_load(argv[0], NULL, KORE_MODULE_PYTHON);

	/* kore_parse_config_file() will call fclose(). */
	kore_parse_config_file(fp);
}
