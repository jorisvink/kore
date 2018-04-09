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
