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
#include <kore/python_api.h>

#include <stdio.h>
#include <limits.h>
#include <unistd.h>

void
kore_parent_configure(int argc, char **argv)
{
	struct stat	st;
	int		len;
	FILE		*fp;
	char		*module, pwd[PATH_MAX], config[PATH_MAX];

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("getcwd: %s", errno_s);

	if (argc == 0) {
		module = &pwd[0];
	} else if (argc == 1) {
		if (!strcmp(argv[0], "."))
			module = &pwd[0];
		else
			module = argv[0];
	} else {
		fatal("Usage: pyko [options] [kore python app]");
	}

	if (stat(module, &st) == -1)
		fatal("stat(%s): %s", module, errno_s);

	if (!S_ISDIR(st.st_mode))
		fatal("python module directory required");

	len = snprintf(config, sizeof(config), "%s/kore.conf", module);
	if (len == -1 || (size_t)len >= sizeof(config))
		fatal("failed to create configuration path");

	if ((fp = fopen(config, "r")) == NULL)
		fatal("failed to open configuration '%s'", config);

	kore_python_path(module);
	kore_module_load(module, NULL, KORE_MODULE_PYTHON);

	if (chdir(module) == -1)
		fatal("chdir(%s): %s", module, errno_s);

	/* kore_parse_config_file() will call fclose(). */
	kore_parse_config_file(fp);
}
