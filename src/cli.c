/*
 * Copyright (c) 2014-2022 Joris Vink <joris@coders.se>
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>

#if !defined(KODEV_MINIMAL)
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define LD_FLAGS_MAX		300
#define CFLAGS_MAX		300
#define CXXFLAGS_MAX		CFLAGS_MAX

#define BUILD_NOBUILD		0
#define BUILD_C			1
#define BUILD_CXX		2

struct cli_buf {
	u_int8_t		*data;
	size_t			length;
	size_t			offset;
};

struct mime_type {
	char			*ext;
	char			*type;
	TAILQ_ENTRY(mime_type)	list;
};

TAILQ_HEAD(mime_list, mime_type);

struct buildopt {
	char			*name;
	char			*kore_source;
	char			*kore_flavor;
	int			flavor_nohttp;
	int			single_binary;
	struct cli_buf		*cflags;
	struct cli_buf		*cxxflags;
	struct cli_buf		*ldflags;
	TAILQ_ENTRY(buildopt)	list;
};

TAILQ_HEAD(buildopt_list, buildopt);

struct cmd {
	const char		*name;
	const char		*descr;
	void			(*cb)(int, char **);
};

struct filegen {
	void			(*cb)(void);
};

struct cfile {
	struct stat		st;
	int			build;
	char			*name;
	char			*fpath;
	char			*opath;
	TAILQ_ENTRY(cfile)	list;
};

TAILQ_HEAD(cfile_list, cfile);

static struct cli_buf	*cli_buf_alloc(size_t);
static void		cli_buf_free(struct cli_buf *);
static char		*cli_buf_stringify(struct cli_buf *, size_t *);
static void		cli_buf_append(struct cli_buf *, const void *, size_t);
static void		cli_buf_appendf(struct cli_buf *, const char *, ...)
			    __attribute__((format (printf, 2, 3)));
static void		cli_buf_appendv(struct cli_buf *, const char *,
			    va_list) __attribute__((format (printf, 2, 0)));

static void		*cli_malloc(size_t);
static char		*cli_strdup(const char *);
static void		*cli_realloc(void *, size_t);

static char		*cli_text_trim(char *, size_t);
static char		*cli_read_line(FILE *, char *, size_t);
static long long	cli_strtonum(const char *, long long, long long);
static int		cli_split_string(char *, const char *, char **, size_t);

static void		usage(void) __attribute__((noreturn));
static void		fatal(const char *, ...) __attribute__((noreturn))
			    __attribute__((format (printf, 1, 2)));

static void		cli_file_close(int);
static void		cli_run_kore(void);
static void		cli_run_kore_python(void);
static void		cli_compile_kore(void *);
static void		cli_link_application(void *);
static void		cli_compile_source_file(void *);
static void		cli_mkdir(const char *, int);
static int		cli_dir_exists(const char *);
static int		cli_file_exists(const char *);
static void		cli_cleanup_files(const char *);
static void		cli_build_cflags(struct buildopt *);
static void		cli_build_cxxflags(struct buildopt *);
static void		cli_build_ldflags(struct buildopt *);
static void		cli_file_read(int, char **, size_t *);
static void		cli_file_writef(int, const char *, ...)
			    __attribute__((format (printf, 2, 3)));
static void		cli_file_open(const char *, int, int *);
static void		cli_file_remove(char *, struct dirent *);
static void		cli_build_asset(char *, struct dirent *);
static void		cli_file_write(int, const void *, size_t);
static int		cli_vasprintf(char **, const char *, ...)
			    __attribute__((format (printf, 2, 3)));
static void		cli_spawn_proc(void (*cb)(void *), void *);
static void		cli_write_asset(const char *, const char *,
			    struct buildopt *);
static void		cli_register_kore_file(char *, struct dirent *);
static void		cli_register_source_file(char *, struct dirent *);
static int		cli_file_requires_build(struct stat *, const char *);
static void		cli_find_files(const char *,
			    void (*cb)(char *, struct dirent *));
static void		cli_add_source_file(char *, char *, char *,
			    struct stat *, int);

static struct buildopt	*cli_buildopt_default(void);
static struct buildopt	*cli_buildopt_new(const char *);
static struct buildopt	*cli_buildopt_find(const char *);
static void		cli_buildopt_cleanup(void);
static void		cli_buildopt_parse(const char *);
static void		cli_buildopt_cflags(struct buildopt *, const char *);
static void		cli_buildopt_cxxflags(struct buildopt *, const char *);
static void		cli_buildopt_ldflags(struct buildopt *, const char *);
static void		cli_buildopt_single_binary(struct buildopt *,
			    const char *);
static void		cli_buildopt_kore_source(struct buildopt *,
			    const char *);
static void		cli_buildopt_kore_flavor(struct buildopt *,
			    const char *);
static void		cli_buildopt_mime(struct buildopt *, const char *);

static void		cli_build_flags_common(struct buildopt *,
			    struct cli_buf *);

static void		cli_flavor_load(void);
static void		cli_flavor_change(const char *);
static void		cli_kore_load_file(const char *, struct buildopt *,
			    char **, size_t *);

static void		cli_run(int, char **);
static void		cli_help(int, char **);
static void		cli_info(int, char **);
static void		cli_build(int, char **);
static void		cli_clean(int, char **);
static void		cli_source(int, char **);
static void		cli_reload(int, char **);
static void		cli_flavor(int, char **);
static void		cli_cflags(int, char **);
static void		cli_ldflags(int, char **);
static void		cli_genasset(int, char **);
static void		cli_genasset_help(void);

#if !defined(KODEV_MINIMAL)
static void		cli_create(int, char **);
static void		cli_create_help(void);

static void		file_create_src(void);
static void		file_create_config(void);
static void		file_create_gitignore(void);
static void		file_create_python_src(void);

static void		cli_generate_certs(void);
static void		cli_file_create(const char *, const char *, size_t);
#endif

static struct cmd cmds[] = {
	{ "help",	"this help text",			cli_help },
	{ "run",	"run an application (-fnr implied)",	cli_run },
	{ "gen",	"generate asset file for compilation",	cli_genasset },
	{ "reload",	"reload the application (SIGHUP)",	cli_reload },
	{ "info",	"show info on kore on this system",	cli_info },
	{ "build",	"build an application",			cli_build },
	{ "clean",	"cleanup the build files",		cli_clean },
	{ "source",	"print the path to kore sources",	cli_source },
#if !defined(KODEV_MINIMAL)
	{ "create",	"create a new application skeleton",	cli_create },
#endif
	{ "flavor",	"switch between build flavors",		cli_flavor },
	{ "cflags",	"show kore CFLAGS",			cli_cflags },
	{ "ldflags",	"show kore LDFLAGS",			cli_ldflags },
	{ NULL,		NULL,					NULL }
};

#if !defined(KODEV_MINIMAL)
static struct filegen gen_files[] = {
	{ file_create_src },
	{ file_create_config },
	{ file_create_gitignore },
	{ NULL }
};

static const char *gen_dirs[] = {
	"src",
	"cert",
	"conf",
	"assets",
	NULL
};

static const char *python_gen_dirs[] = {
	"cert",
	NULL
};

static struct filegen python_gen_files[] = {
	{ file_create_python_src },
	{ file_create_gitignore },
	{ NULL }
};

static const char *http_serveable_function =
	"int\n"
	"asset_serve_%s_%s(struct http_request *req)\n"
	"{\n"
	"	http_serveable(req, asset_%s_%s, asset_len_%s_%s,\n"
	"	    asset_sha256_%s_%s, \"%s\");\n"
	"	return (KORE_RESULT_OK);\n"
	"}\n";

static const char *src_data =
	"#include <kore/kore.h>\n"
	"#include <kore/http.h>\n"
	"\n"
	"int\t\tpage(struct http_request *);\n"
	"\n"
	"int\n"
	"page(struct http_request *req)\n"
	"{\n"
	"\thttp_response(req, 200, NULL, 0);\n"
	"\treturn (KORE_RESULT_OK);\n"
	"}\n";

static const char *config_data =
	"# %s configuration\n"
	"\n"
	"server tls {\n"
	"\tbind 127.0.0.1 8888\n"
	"}\n"
	"\n"
	"load\t\t./%s.so\n"
	"\n"
	"domain * {\n"
	"\tattach\t\ttls\n"
	"\n"
	"\tcertfile\tcert/server.pem\n"
	"\tcertkey\t\tcert/key.pem\n"
	"\n"
	"\troute / {\n"
	"\t\thandler page\n"
	"\t}\n"
	"\n"
	"}\n";

static const char *build_data =
	"# %s build config\n"
	"# You can switch flavors using: kodev flavor [newflavor]\n"
	"\n"
	"# Set to yes if you wish to produce a single binary instead\n"
	"# of a dynamic library. If you set this to yes you must also\n"
	"# set kore_source together with kore_flavor.\n"
	"#single_binary=no\n"
	"#kore_source=/home/joris/src/kore\n"
	"#kore_flavor=\n"
	"\n"
	"# The flags below are shared between flavors\n"
	"cflags=-Wall -Wmissing-declarations -Wshadow\n"
	"cflags=-Wstrict-prototypes -Wmissing-prototypes\n"
	"cflags=-Wpointer-arith -Wcast-qual -Wsign-compare\n"
	"\n"
	"cxxflags=-Wall -Wmissing-declarations -Wshadow\n"
	"cxxflags=-Wpointer-arith -Wcast-qual -Wsign-compare\n"
	"\n"
	"# Mime types for assets served via the builtin asset_serve_*\n"
	"#mime_add=txt:text/plain; charset=utf-8\n"
	"#mime_add=png:image/png\n"
	"#mime_add=html:text/html; charset=utf-8\n"
	"\n"
	"dev {\n"
	"	# These flags are added to the shared ones when\n"
	"	# you build the \"dev\" flavor.\n"
	"	cflags=-g\n"
	"	cxxflags=-g\n"
	"}\n"
	"\n"
	"#prod {\n"
	"#	You can specify additional flags here which are only\n"
	"#	included if you build with the \"prod\" flavor.\n"
	"#}\n";

static const char *python_init_data =
	"from .app import koreapp\n";

static const char *python_app_data =
	"import kore\n"
	"\n"
	"class KoreApp:\n"
	"    def configure(self, args):\n"
	"        kore.config.deployment = \"development\"\n"
	"        kore.server(\"default\", ip=\"127.0.0.1\", port=\"8888\")\n"
	"\n"
	"        d = kore.domain(\"*\",\n"
	"            attach=\"default\",\n"
	"            key=\"cert/key.pem\",\n"
	"            cert=\"cert/server.pem\",\n"
	"        )\n"
	"\n"
	"        d.route(\"/\", self.index, methods=[\"get\"])\n"
	"\n"
	"    async def index(self, req):\n"
	"        req.response(200, b'')\n"
	"\n"
	"koreapp = KoreApp()";

static const char *gitignore = "*.o\n.flavor\n.objs\n%s.so\nassets.h\ncert\n";

#endif /* !KODEV_MINIMAL */

static int			s_fd = -1;
static char			*appl = NULL;
static int			run_after = 0;
static char			*compiler_c = "cc";
static char			*compiler_cpp = "c++";
static char			*compiler_ld = "cc";
static const char		*prefix = PREFIX;
static struct mime_list		mime_types;
static struct cfile_list	source_files;
static struct buildopt_list	build_options;
static int			source_files_count;
static int			cxx_files_count;
static struct cmd		*command = NULL;
static int			cflags_count = 0;
static int			genasset_cmd = 0;
static int			cxxflags_count = 0;
static int			ldflags_count = 0;
static char			*flavor = NULL;
static char			*out_dir = ".";
static char			*object_dir = ".objs";
static char			*cflags[CFLAGS_MAX];
static char			*cxxflags[CXXFLAGS_MAX];
static char			*ldflags[LD_FLAGS_MAX];

static void
usage(void)
{
	int		i;

	fprintf(stderr, "Usage: kodev [command]\n");
#if defined(KODEV_MINIMAL)
	fprintf(stderr, "minimal (only build commands supported)\n");
#endif
	fprintf(stderr, "\nAvailable commands:\n");

	for (i = 0; cmds[i].name != NULL; i++)
		printf("\t%s\t%s\n", cmds[i].name, cmds[i].descr);

	fprintf(stderr, "\nFind more information on https://kore.io\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int		i;
	char		*env;

	if (argc < 2)
		usage();

	argc--;
	argv++;

	if ((env = getenv("KORE_PREFIX")) != NULL)
		prefix = env;

	if ((env = getenv("KORE_OBJDIR")) != NULL)
		object_dir = env;

	if ((env = getenv("KODEV_OUTPUT")) != NULL)
		out_dir = env;

	(void)umask(S_IWGRP | S_IWOTH);

	for (i = 0; cmds[i].name != NULL; i++) {
		if (!strcmp(argv[0], cmds[i].name)) {
			if (strcmp(argv[0], "create")) {
				argc--;
				argv++;
			}
			command = &cmds[i];
			cmds[i].cb(argc, argv);
			break;
		}
	}

	if (cmds[i].name == NULL) {
		fprintf(stderr, "unknown command: %s\n", argv[0]);
		usage();
	}

	return (0);
}

static void
cli_help(int argc, char **argv)
{
	usage();
}

#if !defined(KODEV_MINIMAL)
static void
cli_create_help(void)
{
	printf("Usage: kodev create [-p] [name]\n");
	printf("Synopsis:\n");
	printf("  Create a new application skeleton directory structure.\n");
	printf("\n");
	printf("  Optional flags:\n");
	printf("\t-p = generate a python application skeleton\n");

	exit(1);
}

static void
cli_create(int argc, char **argv)
{
	char			*fpath;
	const char		**dirs;
	struct filegen		*files;
	int			i, ch, python;

	python = 0;

	while ((ch = getopt(argc, argv, "hp")) != -1) {
		switch (ch) {
		case 'h':
			cli_create_help();
			break;
		case 'p':
			python = 1;
			break;
		default:
			cli_create_help();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		cli_create_help();

	appl = argv[0];
	cli_mkdir(appl, 0755);

	if (python) {
		dirs = python_gen_dirs;
		files = python_gen_files;
	} else {
		dirs = gen_dirs;
		files = gen_files;
	}

	for (i = 0; dirs[i] != NULL; i++) {
		(void)cli_vasprintf(&fpath, "%s/%s", appl, dirs[i]);
		cli_mkdir(fpath, 0755);
		free(fpath);
	}

	for (i = 0; files[i].cb != NULL; i++)
		files[i].cb();

	if (chdir(appl) == -1)
		fatal("chdir(%s): %s", appl, errno_s);

	cli_generate_certs();

	printf("%s created successfully!\n", appl);
	printf("WARNING: DO NOT USE THE GENERATED CERTIFICATE IN PRODUCTION\n");
}
#endif

static void
cli_flavor(int argc, char **argv)
{
	struct buildopt		*bopt;
	char			pwd[MAXPATHLEN], *conf;

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);
	(void)cli_vasprintf(&conf, "conf/%s.conf", appl);
	if (!cli_dir_exists("conf") || !cli_file_exists(conf))
		fatal("%s doesn't appear to be a kore app", appl);
	free(conf);

	TAILQ_INIT(&build_options);
	TAILQ_INIT(&mime_types);
	(void)cli_buildopt_new("_default");
	cli_buildopt_parse("conf/build.conf");

	if (argc == 0) {
		cli_flavor_load();
		TAILQ_FOREACH(bopt, &build_options, list) {
			if (!strcmp(bopt->name, "_default"))
				continue;
			if (!strcmp(bopt->name, flavor)) {
				printf("* %s\n", bopt->name);
			} else {
				printf("  %s\n", bopt->name);
			}
		}
	} else {
		cli_flavor_change(argv[0]);
		printf("changed build flavor to: %s\n", argv[0]);
	}

	cli_buildopt_cleanup();
}

static void
cli_build(int argc, char **argv)
{
#if !defined(KODEV_MINIMAL)
	int			l;
	char			*data;
#endif
	struct dirent		dp;
	struct cfile		*cf;
	struct buildopt		*bopt;
	struct timeval		times[2];
	char			*build_path;
	char			*vsrc, *vobj;
	int			requires_relink;
	char			*sofile, *config;
	char			*assets_path, *p, *src_path;
	char			pwd[PATH_MAX], *assets_header;

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("could not get cwd: %s", errno_s);

	appl = cli_strdup(basename(pwd));

	if ((p = getenv("CC")) != NULL) {
		compiler_c = p;
		compiler_ld = p;
	}

	if ((p = getenv("CXX")) != NULL) {
		compiler_cpp = p;
		compiler_ld = p;
	}

	source_files_count = 0;
	cxx_files_count = 0;
	TAILQ_INIT(&source_files);
	TAILQ_INIT(&build_options);
	TAILQ_INIT(&mime_types);

	(void)cli_vasprintf(&src_path, "src");
	(void)cli_vasprintf(&assets_path, "assets");
	(void)cli_vasprintf(&config, "conf/%s.conf", appl);
	(void)cli_vasprintf(&build_path, "conf/build.conf");
	(void)cli_vasprintf(&assets_header, "%s/assets.h", object_dir);

	if (!cli_dir_exists(src_path) || !cli_file_exists(config))
		fatal("%s doesn't appear to be a kore app", appl);

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");

#if !defined(KODEV_MINIMAL)
	if (!cli_file_exists(build_path)) {
		l = cli_vasprintf(&data, build_data, appl);
		cli_file_create("conf/build.conf", data, l);
		free(data);
	}
#endif

	cli_find_files(src_path, cli_register_source_file);
	free(src_path);

	cli_buildopt_parse(build_path);
	free(build_path);

	if (!cli_dir_exists(object_dir))
		cli_mkdir(object_dir, 0755);

	if (bopt->single_binary) {
		if (bopt->kore_source == NULL)
			fatal("single_binary set but not kore_source");

		printf("building kore (%s)\n", bopt->kore_source);
		cli_spawn_proc(cli_compile_kore, bopt);

		(void)cli_vasprintf(&src_path, "%s/src", bopt->kore_source);
		cli_find_files(src_path, cli_register_kore_file);
		free(src_path);

		(void)cli_vasprintf(&vsrc, "%s/version.c", object_dir);
		(void)cli_vasprintf(&vobj, "%s/version.o", object_dir);

		cli_add_source_file("version.c",
		    vsrc, vobj, NULL, BUILD_NOBUILD);
	}

	printf("building %s (%s)\n", appl, flavor);

	cli_build_cflags(bopt);
	cli_build_cxxflags(bopt);
	cli_build_ldflags(bopt);

	(void)unlink(assets_header);

	/* Generate the assets. */
	cli_file_open(assets_header, O_CREAT | O_TRUNC | O_WRONLY, &s_fd);
	cli_file_writef(s_fd, "#ifndef __H_KORE_ASSETS_H\n");
	cli_file_writef(s_fd, "#define __H_KORE_ASSETS_H\n");

	if (cli_dir_exists(assets_path))
		cli_find_files(assets_path, cli_build_asset);

	if (bopt->single_binary) {
		memset(&dp, 0, sizeof(dp));
		dp.d_type = DT_REG;
		printf("adding config %s\n", config);
		(void)snprintf(dp.d_name,
		    sizeof(dp.d_name), "builtin_kore.conf");
		cli_build_asset(config, &dp);
	}

	cli_file_writef(s_fd, "\n#endif\n");
	cli_file_close(s_fd);

	free(assets_path);
	free(config);

	if (cxx_files_count > 0)
		compiler_ld = compiler_cpp;

	requires_relink = 0;
	TAILQ_FOREACH(cf, &source_files, list) {
		if (cf->build == BUILD_NOBUILD)
			continue;

		printf("compiling %s\n", cf->name);
		cli_spawn_proc(cli_compile_source_file, cf);

		times[0].tv_usec = 0;
		times[0].tv_sec = cf->st.st_mtime;
		times[1] = times[0];

		if (utimes(cf->opath, times) == -1)
			printf("utime(%s): %s\n", cf->opath, errno_s);

		requires_relink++;
	}

	free(assets_header);

#if !defined(KODEV_MINIMAL)
	if (bopt->kore_flavor == NULL ||
	    !strstr(bopt->kore_flavor, "NOTLS=1")) {
		if (!cli_dir_exists("cert")) {
			cli_mkdir("cert", 0700);
			cli_generate_certs();
		}
	}
#endif

	if (bopt->single_binary) {
		requires_relink++;
		(void)cli_vasprintf(&sofile, "%s/%s", out_dir, appl);
	} else {
		(void)cli_vasprintf(&sofile, "%s/%s.so", out_dir, appl);
	}

	if (!cli_file_exists(sofile) && source_files_count > 0)
		requires_relink++;

	free(sofile);

	if (requires_relink) {
		cli_spawn_proc(cli_link_application, bopt);
		printf("%s built successfully!\n", appl);
	} else {
		printf("nothing to be done!\n");
	}

	if (run_after == 0)
		cli_buildopt_cleanup();
}

static void
cli_source(int argc, char **argv)
{
	printf("%s/share/kore/\n", prefix);
}

static void
cli_clean(int argc, char **argv)
{
	struct buildopt		*bopt;
	char			pwd[PATH_MAX], *bin;

	if (cli_dir_exists(object_dir))
		cli_cleanup_files(object_dir);

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);

	TAILQ_INIT(&mime_types);
	TAILQ_INIT(&build_options);

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");
	cli_buildopt_parse("conf/build.conf");

	if (bopt->single_binary)
		(void)cli_vasprintf(&bin, "%s/%s", out_dir, appl);
	else
		(void)cli_vasprintf(&bin, "%s/%s.so", out_dir, appl);

	if (unlink(bin) == -1 && errno != ENOENT)
		printf("couldn't unlink %s: %s", bin, errno_s);

	free(bin);
}

static void
cli_run(int argc, char **argv)
{
	if (cli_file_exists("__init__.py")) {
		cli_run_kore_python();
		return;
	}

	run_after = 1;
	cli_build(argc, argv);

	/*
	 * We are exec()'ing kore again, while we could technically set
	 * the right cli options manually and just continue running.
	 */
	cli_run_kore();
}

static void
cli_reload(int argc, char **argv)
{
	int		fd;
	size_t		len;
	pid_t		pid;
	char		*buf;

	cli_file_open("kore.pid", O_RDONLY, &fd);
	cli_file_read(fd, &buf, &len);
	cli_file_close(fd);

	if (len == 0)
		fatal("reload: pid file is empty");

	buf[len - 1] = '\0';

	pid = cli_strtonum(buf, 0, UINT_MAX);

	if (kill(pid, SIGHUP) == -1)
		fatal("failed to reload: %s", errno_s);

	printf("reloaded application\n");
}

static void
cli_info(int argc, char **argv)
{
	size_t			len;
	struct buildopt		*bopt;
	char			*features;

	TAILQ_INIT(&mime_types);
	TAILQ_INIT(&build_options);

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");
	cli_buildopt_parse("conf/build.conf");

	printf("active flavor\t %s\n", flavor);
	printf("output type  \t %s\n",
	    (bopt->single_binary) ? "binary" : "dso");

	if (bopt->single_binary) {
		printf("kore features\t %s\n", bopt->kore_flavor);
		printf("kore source  \t %s\n", bopt->kore_source);
	} else {
		cli_kore_load_file("features", bopt, &features, &len);
		printf("kore binary  \t %s/bin/kore\n", prefix);
		printf("kore features\t %.*s\n", (int)len, features);
		free(features);
	}
}

static void
cli_cflags(int argc, char **argv)
{
	struct cli_buf	*buf;

	buf = cli_buf_alloc(128);
	cli_build_flags_common(NULL, buf);
	printf("%.*s\n", (int)buf->offset, buf->data);
	cli_buf_free(buf);
}

static void
cli_ldflags(int argc, char **argv)
{
	char		*p;
	size_t		len;

	cli_kore_load_file("linker", NULL, &p, &len);
	printf("%.*s ", (int)len, p);

#if defined(__MACH__)
	printf("-dynamiclib -undefined suppress -flat_namespace ");
#else
	printf("-shared ");
#endif
	printf("\n");

	free(p);
}

static void
cli_genasset(int argc, char **argv)
{
	struct stat		st;
	struct dirent		dp;
	char			*hdr;

	genasset_cmd = 1;
	TAILQ_INIT(&build_options);
	(void)cli_buildopt_new("_default");

	if (getenv("KORE_OBJDIR") == NULL)
		object_dir = out_dir;

	if (argv[0] == NULL)
		cli_genasset_help();

	(void)cli_vasprintf(&hdr, "%s/assets.h", out_dir);
	(void)unlink(hdr);

	cli_file_open(hdr, O_CREAT | O_TRUNC | O_WRONLY, &s_fd);
	cli_file_writef(s_fd, "#ifndef __H_KORE_ASSETS_H\n");
	cli_file_writef(s_fd, "#define __H_KORE_ASSETS_H\n");

	if (stat(argv[0], &st) == -1)
		fatal("%s: %s", argv[0], errno_s);

	if (S_ISDIR(st.st_mode)) {
		if (cli_dir_exists(argv[0]))
			cli_find_files(argv[0], cli_build_asset);
	} else if (S_ISREG(st.st_mode)) {
		memset(&dp, 0, sizeof(dp));
		dp.d_type = DT_REG;
		(void)snprintf(dp.d_name, sizeof(dp.d_name), "%s",
		    basename(argv[0]));
		cli_build_asset(argv[0], &dp);
	} else {
		fatal("%s is not a directory or regular file", argv[0]);
	}

	cli_file_writef(s_fd, "\n#endif\n");
	cli_file_close(s_fd);
}

static void
cli_genasset_help(void)
{
	printf("Usage: kodev genasset [source]\n");
	printf("Synopsis:\n");
	printf("  Generates asset file(s) to be used for compilation.\n");
	printf("  The source can be a single file or directory.\n");
	printf("\n");
	printf("This command honors the KODEV_OUTPUT environment variable.\n");
	printf("This command honors the KORE_OBJDIR environment variable.\n");

	exit(1);
}

#if !defined(KODEV_MINIMAL)
static void
file_create_python_src(void)
{
	char		*name;

	(void)cli_vasprintf(&name, "%s/__init__.py", appl);
	cli_file_create(name, python_init_data, strlen(python_init_data));
	free(name);

	(void)cli_vasprintf(&name, "%s/app.py", appl);
	cli_file_create(name, python_app_data, strlen(python_app_data));
	free(name);
}

static void
file_create_src(void)
{
	char		*name;

	(void)cli_vasprintf(&name, "%s/src/%s.c", appl, appl);
	cli_file_create(name, src_data, strlen(src_data));
	free(name);
}

static void
file_create_config(void)
{
	int		l;
	char		*name, *data;

	(void)cli_vasprintf(&name, "%s/conf/%s.conf", appl, appl);
	l = cli_vasprintf(&data, config_data, appl, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);

	(void)cli_vasprintf(&name, "%s/conf/build.conf", appl);
	l = cli_vasprintf(&data, build_data, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);
}

static void
file_create_gitignore(void)
{
	int		l;
	char		*name, *data;

	(void)cli_vasprintf(&name, "%s/.gitignore", appl);
	l = cli_vasprintf(&data, gitignore, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);
}
#endif

static void
cli_mkdir(const char *fpath, int mode)
{
	if (mkdir(fpath, mode) == -1)
		fatal("cli_mkdir(%s): %s", fpath, errno_s);
}

static int
cli_file_exists(const char *fpath)
{
	struct stat		st;

	if (stat(fpath, &st) == -1)
		return (0);

	if (!S_ISREG(st.st_mode))
		return (0);

	return (1);
}

static int
cli_file_requires_build(struct stat *fst, const char *opath)
{
	struct stat	ost;

	if (stat(opath, &ost) == -1) {
		if (errno == ENOENT)
			return (1);
		fatal("stat(%s): %s", opath, errno_s);
	}

	return (fst->st_mtime != ost.st_mtime);
}

static int
cli_dir_exists(const char *fpath)
{
	struct stat		st;

	if (stat(fpath, &st) == -1)
		return (0);

	if (!S_ISDIR(st.st_mode))
		return (0);

	return (1);
}

static void
cli_file_open(const char *fpath, int flags, int *fd)
{
	if ((*fd = open(fpath, flags, 0644)) == -1)
		fatal("cli_file_open(%s): %s", fpath, errno_s);
}

static void
cli_file_read(int fd, char **buf, size_t *len)
{
	struct stat	st;
	char		*p;
	ssize_t		ret;
	size_t		offset, bytes;

	if (fstat(fd, &st) == -1)
		fatal("fstat(): %s", errno_s);

	if (st.st_size > USHRT_MAX)
		fatal("cli_file_read: way too big");

	offset = 0;
	bytes = st.st_size;
	p = cli_malloc(bytes);

	while (offset != bytes) {
		ret = read(fd, p + offset, bytes - offset);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("read(): %s", errno_s);
		}

		if (ret == 0)
			fatal("unexpected EOF");

		offset += (size_t)ret;
	}

	*buf = p;
	*len = bytes;
}

static void
cli_file_close(int fd)
{
	if (close(fd) == -1)
		printf("warning: close() %s\n", errno_s);
}

static void
cli_file_writef(int fd, const char *fmt, ...)
{
	int		l;
	char		*buf;
	va_list		args;

	va_start(args, fmt);
	l = vasprintf(&buf, fmt, args);
	va_end(args);

	if (l == -1)
		fatal("cli_file_writef");

	cli_file_write(fd, buf, l);
	free(buf);
}

static void
cli_file_write(int fd, const void *buf, size_t len)
{
	ssize_t		r;
	const u_int8_t	*d;
	size_t		written;

	d = buf;
	written = 0;
	while (written != len) {
		r = write(fd, d + written, len - written);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fatal("cli_file_write: %s", errno_s);
		}

		written += r;
	}
}

#if !defined(KODEV_MINIMAL)
static void
cli_file_create(const char *name, const char *data, size_t len)
{
	int		fd;

	cli_file_open(name, O_CREAT | O_TRUNC | O_WRONLY, &fd);
	cli_file_write(fd, data, len);
	cli_file_close(fd);

	printf("created %s\n", name);
}
#endif

static void
cli_write_asset(const char *n, const char *e, struct buildopt *bopt)
{
	cli_file_writef(s_fd, "extern const u_int8_t asset_%s_%s[];\n", n, e);
	cli_file_writef(s_fd, "extern const u_int32_t asset_len_%s_%s;\n", n, e);
	cli_file_writef(s_fd, "extern const time_t asset_mtime_%s_%s;\n", n, e);

#if !defined(KODEV_MINIMAL)
	cli_file_writef(s_fd, "extern const char *asset_sha256_%s_%s;\n", n, e);
#endif

	if (bopt->flavor_nohttp == 0) {
		cli_file_writef(s_fd,
		    "int asset_serve_%s_%s(struct http_request *);\n", n, e);
	}
}

static void
cli_build_asset(char *fpath, struct dirent *dp)
{
	u_int8_t		*d;
	struct stat		st;
#if !defined(KODEV_MINIMAL)
	SHA256_CTX		sctx;
	int			i, len;
	struct mime_type	*mime;
	const char		*mime_type;
	u_int8_t		digest[SHA256_DIGEST_LENGTH];
	char			hash[(SHA256_DIGEST_LENGTH * 2) + 1];
#endif
	off_t			off;
	void			*base;
	struct buildopt		*bopt;
	int			in, out;
	char			*cpath, *ext, *opath, *p, *name;

	bopt = cli_buildopt_default();

	/* Ignore hidden files and some editor files */
	if (dp->d_name[0] == '.' ||
	    strrchr(dp->d_name, '~') || strrchr(dp->d_name, '#')) {
		return;
	}

	name = cli_strdup(dp->d_name);

	/* Grab the extension as we're using it in the symbol name. */
	if ((ext = strrchr(name, '.')) == NULL)
		fatal("couldn't find ext in %s", name);

	/* Replace dots, spaces, etc etc with underscores. */
	for (p = name; *p != '\0'; p++) {
		if (*p == '.' || isspace((unsigned char)*p) || *p == '-')
			*p = '_';
	}

	/* Grab inode information. */
	if (stat(fpath, &st) == -1)
		fatal("stat: %s %s", fpath, errno_s);

	/* If this file was empty, skip it. */
	if (st.st_size == 0) {
		printf("skipping empty asset %s\n", name);
		free(name);
		return;
	}

	(void)cli_vasprintf(&opath, "%s/%s.o", object_dir, name);
	(void)cli_vasprintf(&cpath, "%s/%s.c", object_dir, name);

	/* Check if the file needs to be built. */
	if (!cli_file_requires_build(&st, opath)) {
		*(ext)++ = '\0';
		cli_write_asset(name, ext, bopt);
		*ext = '_';

		cli_add_source_file(name, cpath, opath, &st, BUILD_NOBUILD);
		free(name);
		return;
	}

	/* Open the file we're converting. */
	cli_file_open(fpath, O_RDONLY, &in);

	/* mmap our in file. */
	if ((base = mmap(NULL, st.st_size,
	    PROT_READ, MAP_PRIVATE, in, 0)) == MAP_FAILED)
		fatal("mmap: %s %s", fpath, errno_s);

	/* Create the c file where we will write too. */
	cli_file_open(cpath, O_CREAT | O_TRUNC | O_WRONLY, &out);

	/* No longer need name so cut off the extension. */
	printf("building asset %s\n", dp->d_name);
	*(ext)++ = '\0';

	/* Start generating the file. */
	cli_file_writef(out, "/* Auto generated */\n");
	cli_file_writef(out, "#include <sys/types.h>\n\n");
	cli_file_writef(out, "#include <kore/kore.h>\n");
	cli_file_writef(out, "#include <kore/http.h>\n\n");
	cli_file_writef(out, "#include \"assets.h\"\n\n");

	/* Write the file data as a byte array. */
	cli_file_writef(out, "const u_int8_t asset_%s_%s[] = {\n", name, ext);
	d = base;
	for (off = 0; off < st.st_size; off++)
		cli_file_writef(out, "0x%02x,", *d++);

	/*
	 * Always NUL-terminate the asset, even if this NUL is not included in
	 * the actual length. This way assets can be cast to char * without
	 * any additional thinking for the developer.
	 */
	cli_file_writef(out, "0x00");

#if !defined(KODEV_MINIMAL)
	/* Calculate the SHA256 digest of the contents. */
	(void)SHA256_Init(&sctx);
	(void)SHA256_Update(&sctx, base, st.st_size);
	(void)SHA256_Final(digest, &sctx);

	for (i = 0; i < (int)sizeof(digest); i++) {
		len = snprintf(hash + (i * 2), sizeof(hash) - (i * 2),
		    "%02x", digest[i]);
		if (len == -1 || (size_t)len >= sizeof(hash))
			fatal("failed to convert SHA256 digest to hex");
	}

	mime = NULL;
	TAILQ_FOREACH(mime, &mime_types, list) {
		if (!strcasecmp(mime->ext, ext))
			break;
	}

	if (mime != NULL)
		mime_type = mime->type;
	else
		mime_type = "text/plain";
#endif

	/* Add the meta data. */
	cli_file_writef(out, "};\n\n");
	cli_file_writef(out, "const u_int32_t asset_len_%s_%s = %" PRIu32 ";\n",
	    name, ext, (u_int32_t)st.st_size);
	cli_file_writef(out,
	    "const time_t asset_mtime_%s_%s = %" PRId64 ";\n",
	    name, ext, (int64_t)st.st_mtime);

#if !defined(KODEV_MINIMAL)
	if (bopt->flavor_nohttp == 0) {
		cli_file_writef(out,
		    "const char *asset_sha256_%s_%s = \"\\\"%s\\\"\";\n",
		    name, ext, hash);
		cli_file_writef(out, http_serveable_function,
		    name, ext, name, ext, name, ext, name, ext, mime_type);
	}
#endif

	/* Write the file symbols into assets.h so they can be used. */
	cli_write_asset(name, ext, bopt);

	/* Cleanup static file source. */
	if (munmap(base, st.st_size) == -1)
		fatal("munmap: %s %s", fpath, errno_s);

	/* Cleanup fds */
	cli_file_close(in);
	cli_file_close(out);

	/* Restore the original name */
	*--ext = '.';

	/* Register the .c file now (cpath is free'd later). */
	if (genasset_cmd == 0)
		cli_add_source_file(name, cpath, opath, &st, BUILD_C);

	free(name);
}

static void
cli_add_source_file(char *name, char *fpath, char *opath, struct stat *st,
    int build)
{
	struct cfile		*cf;

	source_files_count++;
	cf = cli_malloc(sizeof(*cf));

	if (st != NULL)
		cf->st = *st;
	else
		memset(&cf->st, 0, sizeof(cf->st));

	cf->build = build;
	cf->fpath = fpath;
	cf->opath = opath;
	cf->name = cli_strdup(name);

	TAILQ_INSERT_TAIL(&source_files, cf, list);
}

static void
cli_register_source_file(char *fpath, struct dirent *dp)
{
	struct stat		st;
	char			*ext, *opath;
	int			build;

	if ((ext = strrchr(fpath, '.')) == NULL ||
	    (strcmp(ext, ".c") && strcmp(ext, ".cpp")))
		return;

	if (stat(fpath, &st) == -1)
		fatal("stat(%s): %s", fpath, errno_s);

	if (!strcmp(ext, ".cpp"))
		cxx_files_count++;

	(void)cli_vasprintf(&opath, "%s/%s.o", object_dir, dp->d_name);
	if (!cli_file_requires_build(&st, opath)) {
		build = BUILD_NOBUILD;
	} else if (!strcmp(ext, ".cpp")) {
		build = BUILD_CXX;
	} else {
		build = BUILD_C;
	}

	cli_add_source_file(dp->d_name, fpath, opath, &st, build);
}

static void
cli_register_kore_file(char *fpath, struct dirent *dp)
{
	struct stat		st, ost;
	char			*opath, *ext, *fname;

	if ((ext = strrchr(fpath, '.')) == NULL || strcmp(ext, ".c"))
		return;

	if (stat(fpath, &st) == -1)
		fatal("stat(%s): %s", fpath, errno_s);

	*ext = '\0';
	if ((fname = basename(fpath)) == NULL)
		fatal("basename failed");

	(void)cli_vasprintf(&opath, "%s/%s.o", object_dir, fname);

	/* Silently ignore non existing object files for kore source files. */
	if (stat(opath, &ost) == -1) {
		free(opath);
		return;
	}

	cli_add_source_file(dp->d_name, fpath, opath, &st, BUILD_NOBUILD);
}

static void
cli_file_remove(char *fpath, struct dirent *dp)
{
	if (unlink(fpath) == -1)
		fprintf(stderr, "couldn't unlink %s: %s", fpath, errno_s);
}

static void
cli_find_files(const char *path, void (*cb)(char *, struct dirent *))
{
	DIR			*d;
	struct stat		st;
	struct dirent		*dp;
	char			*fpath;

	if ((d = opendir(path)) == NULL)
		fatal("cli_find_files: opendir(%s): %s", path, errno_s);

	while ((dp = readdir(d)) != NULL) {
		if (!strcmp(dp->d_name, ".") ||
		    !strcmp(dp->d_name, ".."))
			continue;

		(void)cli_vasprintf(&fpath, "%s/%s", path, dp->d_name);
		if (stat(fpath, &st) == -1) {
			fprintf(stderr, "stat(%s): %s\n", fpath, errno_s);
			free(fpath);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			cli_find_files(fpath, cb);
			free(fpath);
		} else if (S_ISREG(st.st_mode)) {
			cb(fpath, dp);
		} else {
			fprintf(stderr, "ignoring %s\n", fpath);
			free(fpath);
		}
	}

	closedir(d);
}

#if !defined(KODEV_MINIMAL)
static void
cli_generate_certs(void)
{
	BIGNUM			*e;
	FILE			*fp;
	time_t			now;
	X509_NAME		*name;
	EVP_PKEY		*pkey;
	X509			*x509;
	RSA			*kpair;
	char			issuer[64];

	/* Create new certificate. */
	if ((x509 = X509_new()) == NULL)
		fatal("X509_new(): %s", ssl_errno_s);

	/* Generate version 3. */
	if (!X509_set_version(x509, 2))
		fatal("X509_set_version(): %s", ssl_errno_s);

	/* Generate RSA keys. */
	if ((pkey = EVP_PKEY_new()) == NULL)
		fatal("EVP_PKEY_new(): %s", ssl_errno_s);
	if ((kpair = RSA_new()) == NULL)
		fatal("RSA_new(): %s", ssl_errno_s);
	if ((e = BN_new()) == NULL)
		fatal("BN_new(): %s", ssl_errno_s);

	if (!BN_set_word(e, 65537))
		fatal("BN_set_word(): %s", ssl_errno_s);
	if (!RSA_generate_key_ex(kpair, 2048, e, NULL))
		fatal("RSA_generate_key_ex(): %s", ssl_errno_s);

	BN_free(e);

	if (!EVP_PKEY_assign_RSA(pkey, kpair))
		fatal("EVP_PKEY_assign_RSA(): %s", ssl_errno_s);

	/* Set serial number to current timestamp. */
	time(&now);
	if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), now))
		fatal("ASN1_INTEGER_set(): %s", ssl_errno_s);

	/* Not before and not after dates. */
	if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
		fatal("X509_gmtime_adj(): %s", ssl_errno_s);
	if (!X509_gmtime_adj(X509_get_notAfter(x509),
	    (long)60 * 60 * 24 * 3000))
		fatal("X509_gmtime_adj(): %s", ssl_errno_s);

	/* Attach the pkey to the certificate. */
	if (!X509_set_pubkey(x509, pkey))
		fatal("X509_set_pubkey(): %s", ssl_errno_s);

	/* Set certificate information. */
	if ((name = X509_get_subject_name(x509)) == NULL)
		fatal("X509_get_subject_name(): %s", ssl_errno_s);

	(void)snprintf(issuer, sizeof(issuer), "kore autogen: %s", appl);
	if (!X509_NAME_add_entry_by_txt(name, "C",
	    MBSTRING_ASC, (const unsigned char *)"SE", -1, -1, 0))
		fatal("X509_NAME_add_entry_by_txt(): C %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "O",
	    MBSTRING_ASC, (const unsigned char *)issuer, -1, -1, 0))
		fatal("X509_NAME_add_entry_by_txt(): O %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0))
		fatal("X509_NAME_add_entry_by_txt(): CN %s", ssl_errno_s);

	if (!X509_set_issuer_name(x509, name))
		fatal("X509_set_issuer_name(): %s", ssl_errno_s);

	if (!X509_sign(x509, pkey, EVP_sha256()))
		fatal("X509_sign(): %s", ssl_errno_s);

	if ((fp = fopen("cert/key.pem", "w")) == NULL)
		fatal("fopen(cert/key.pem): %s", errno_s);
	if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
		fatal("PEM_write_PrivateKey(): %s", ssl_errno_s);
	fclose(fp);

	if ((fp = fopen("cert/server.pem", "w")) == NULL)
		fatal("fopen(cert/server.pem): %s", errno_s);
	if (!PEM_write_X509(fp, x509))
		fatal("PEM_write_X509(%s)", errno_s);
	fclose(fp);

	EVP_PKEY_free(pkey);
	X509_free(x509);
}
#endif

static void
cli_compile_source_file(void *arg)
{
	struct cfile		*cf;
	int			idx, i;
	char			**flags;
	char			*compiler;
	int			flags_count;
	char			*args[34 + CFLAGS_MAX];

	cf = arg;

	switch (cf->build) {
	case BUILD_C:
		compiler = compiler_c;
		flags = cflags;
		flags_count = cflags_count;
		break;
	case BUILD_CXX:
		compiler = compiler_cpp;
		flags = cxxflags;
		flags_count = cxxflags_count;
		break;
	default:
		fatal("cli_compile_file: unexpected file type: %d",
		    cf->build);
		break;
	}

	idx = 0;
	args[idx++] = compiler;

	for (i = 0; i < flags_count; i++)
		args[idx++] = flags[i];

	args[idx++] = "-I";
	args[idx++] = object_dir;
	args[idx++] = "-c";
	args[idx++] = cf->fpath;
	args[idx++] = "-o";
	args[idx++] = cf->opath;
	args[idx] = NULL;

	execvp(compiler, args);
	fatal("failed to start '%s': %s", compiler, errno_s);
}

static void
cli_link_application(void *arg)
{
	struct cfile		*cf;
	struct buildopt		*bopt;
	int			idx, i;
	char			*output;
	char			*args[source_files_count + 11 + LD_FLAGS_MAX];

	bopt = arg;

	if (bopt->single_binary)
		(void)cli_vasprintf(&output, "%s/%s", out_dir, appl);
	else
		(void)cli_vasprintf(&output, "%s/%s.so", out_dir, appl);

	idx = 0;
	args[idx++] = compiler_ld;

	TAILQ_FOREACH(cf, &source_files, list)
		args[idx++] = cf->opath;

	for (i = 0; i < ldflags_count; i++)
		args[idx++] = ldflags[i];

	args[idx++] = "-o";
	args[idx++] = output;
	args[idx] = NULL;

	execvp(compiler_ld, args);
	fatal("failed to start '%s': %s", compiler_ld, errno_s);
}

static void
cli_compile_kore(void *arg)
{
	struct buildopt		*bopt = arg;
	int			idx, i, fcnt;
	char			pwd[MAXPATHLEN], *obj, *args[20], *flavors[7];

	if (object_dir[0] != '/') {
		if (getcwd(pwd, sizeof(pwd)) == NULL)
			fatal("could not get cwd: %s", errno_s);
		(void)cli_vasprintf(&obj, "OBJDIR=%s/%s", pwd, object_dir);
	} else {
		(void)cli_vasprintf(&obj, "OBJDIR=%s", object_dir);
	}

	if (putenv(obj) != 0)
		fatal("cannot set OBJDIR for building kore");

	fcnt = cli_split_string(bopt->kore_flavor, " ", flavors, 7);

#if defined(OpenBSD) || defined(__FreeBSD_version) || \
    defined(NetBSD) || defined(__DragonFly_version)
	args[0] = "gmake";
#else
	args[0] = "make";
#endif

	args[1] = "-s";
	args[2] = "-C";
	args[3] = bopt->kore_source;
	args[4] = "objects";

	idx = 5;
	for (i = 0; i < fcnt; i++) {
		printf("using flavor %s\n", flavors[i]);
		args[idx++] = flavors[i];
	}

	args[idx++] = "KORE_SINGLE_BINARY=1";
	args[idx] = NULL;

	execvp(args[0], args);
	fatal("failed to start '%s': %s", args[0], errno_s);
}

static void
cli_run_kore_python(void)
{
	char		*args[5], *cmd;
	char		pwd[MAXPATHLEN];

	(void)cli_vasprintf(&cmd, "%s/bin/kore", prefix);

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("could not get cwd: %s", errno_s);

	args[0] = cmd;
	args[1] = pwd;
	args[2] = NULL;

	execvp(args[0], args);
	fatal("failed to start '%s': %s", args[0], errno_s);

}

static void
cli_run_kore(void)
{
	struct buildopt		*bopt;
	char			*args[4], *cpath, *cmd, *flags;

	bopt = cli_buildopt_default();

	if (bopt->single_binary) {
		cpath = NULL;
		flags = "-fnr";
		(void)cli_vasprintf(&cmd, "./%s", appl);
	} else {
		flags = "-fnrc";
		(void)cli_vasprintf(&cmd, "%s/bin/kore", prefix);
		(void)cli_vasprintf(&cpath, "conf/%s.conf", appl);
	}

	args[0] = cmd;
	args[1] = flags;

	if (cpath != NULL) {
		args[2] = cpath;
		args[3] = NULL;
	} else {
		args[2] = NULL;
	}

	execvp(args[0], args);
	fatal("failed to start '%s': %s", args[0], errno_s);
}

static void
cli_buildopt_parse(const char *path)
{
	FILE			*fp;
	const char		*env;
	struct buildopt		*bopt;
	char			buf[BUFSIZ], *p, *t;

	if ((fp = fopen(path, "r")) == NULL)
		fatal("cli_buildopt_parse: fopen(%s): %s", path, errno_s);

	bopt = NULL;

	while ((p = cli_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(p) == 0)
			continue;

		if (bopt != NULL && !strcmp(p, "}")) {
			bopt = NULL;
			continue;
		}

		if (bopt == NULL) {
			if ((t = strchr(p, '=')) != NULL)
				goto parse_option;
			if ((t = strchr(p, ' ')) == NULL)
				fatal("unexpected '%s'", p);
			*(t)++ = '\0';
			if (strcmp(t, "{"))
				fatal("expected '{', got '%s'", t);
			bopt = cli_buildopt_new(p);
			continue;
		}

		if ((t = strchr(p, '=')) == NULL) {
			printf("bad buildopt line: '%s'\n", p);
			continue;
		}

parse_option:
		*(t)++ = '\0';

		p = cli_text_trim(p, strlen(p));
		t = cli_text_trim(t, strlen(t));

		if (!strcasecmp(p, "cflags")) {
			cli_buildopt_cflags(bopt, t);
		} else if (!strcasecmp(p, "cxxflags")) {
			cli_buildopt_cxxflags(bopt, t);
		} else if (!strcasecmp(p, "ldflags")) {
			cli_buildopt_ldflags(bopt, t);
		} else if (!strcasecmp(p, "single_binary")) {
			cli_buildopt_single_binary(bopt, t);
		} else if (!strcasecmp(p, "kore_source")) {
			cli_buildopt_kore_source(bopt, t);
		} else if (!strcasecmp(p, "kore_flavor")) {
			cli_buildopt_kore_flavor(bopt, t);
		} else if (!strcasecmp(p, "mime_add")) {
			cli_buildopt_mime(bopt, t);
		} else {
			printf("ignoring unknown option '%s'\n", p);
		}
	}

	fclose(fp);

	if ((env = getenv("KORE_SOURCE")) != NULL)
		cli_buildopt_kore_source(NULL, env);

	if ((env = getenv("KORE_FLAVOR")) != NULL)
		cli_buildopt_kore_flavor(NULL, env);
}

static struct buildopt *
cli_buildopt_new(const char *name)
{
	struct buildopt		*bopt;

	bopt = cli_malloc(sizeof(*bopt));
	bopt->cflags = NULL;
	bopt->cxxflags = NULL;
	bopt->ldflags = NULL;
	bopt->flavor_nohttp = 0;
	bopt->single_binary = 0;
	bopt->kore_flavor = NULL;
	bopt->name = cli_strdup(name);

	(void)cli_vasprintf(&bopt->kore_source, "%s/share/kore/", prefix);

	TAILQ_INSERT_TAIL(&build_options, bopt, list);
	return (bopt);
}

static struct buildopt *
cli_buildopt_find(const char *name)
{
	struct buildopt		*bopt;

	TAILQ_FOREACH(bopt, &build_options, list) {
		if (!strcmp(bopt->name, name))
			return (bopt);
	}

	return (NULL);
}

static struct buildopt *
cli_buildopt_default(void)
{
	struct buildopt		*bopt;

	if ((bopt = cli_buildopt_find("_default")) == NULL)
		fatal("no _default buildopt options");

	return (bopt);
}

static void
cli_buildopt_cleanup(void)
{
	struct buildopt		*bopt, *next;
	struct mime_type	*mime, *mnext;

	for (bopt = TAILQ_FIRST(&build_options); bopt != NULL; bopt = next) {
		next = TAILQ_NEXT(bopt, list);
		TAILQ_REMOVE(&build_options, bopt, list);

		if (bopt->cflags != NULL)
			cli_buf_free(bopt->cflags);
		if (bopt->cxxflags != NULL)
			cli_buf_free(bopt->cxxflags);
		if (bopt->ldflags != NULL)
			cli_buf_free(bopt->ldflags);
		if (bopt->kore_source != NULL)
			free(bopt->kore_source);
		if (bopt->kore_flavor != NULL)
			free(bopt->kore_flavor);
		free(bopt);
	}

	for (mime = TAILQ_FIRST(&mime_types); mime != NULL; mime = mnext) {
		mnext = TAILQ_NEXT(mime, list);
		TAILQ_REMOVE(&mime_types, mime, list);
		free(mime->type);
		free(mime->ext);
		free(mime);
	}
}

static void
cli_buildopt_cflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->cflags == NULL)
		bopt->cflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->cflags, "%s ", string);
}

static void
cli_buildopt_cxxflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->cxxflags == NULL)
		bopt->cxxflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->cxxflags, "%s ", string);
}

static void
cli_buildopt_ldflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->ldflags == NULL)
		bopt->ldflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->ldflags, "%s ", string);
}

static void
cli_buildopt_single_binary(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		fatal("single_binary only supported in global context");

	if (!strcmp(string, "yes"))
		bopt->single_binary = 1;
	else
		bopt->single_binary = 0;
}

static void
cli_buildopt_kore_source(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		fatal("kore_source only supported in global context");

	if (bopt->kore_source != NULL)
		free(bopt->kore_source);

	bopt->kore_source = cli_strdup(string);
}

static void
cli_buildopt_kore_flavor(struct buildopt *bopt, const char *string)
{
	int		cnt, i;
	char		*p, *copy, *flavors[10];

	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		fatal("kore_flavor only supported in global context");

	if (bopt->kore_flavor != NULL)
		free(bopt->kore_flavor);

	copy = cli_strdup(string);
	cnt = cli_split_string(copy, " ", flavors, 10);

	for (i = 0; i < cnt; i++) {
		if ((p = strchr(flavors[i], '=')) == NULL)
			fatal("invalid flavor %s", string);

		*p = '\0';

		if (!strcmp(flavors[i], "NOHTTP"))
			bopt->flavor_nohttp = 1;
	}

	bopt->kore_flavor = cli_strdup(string);
	free(copy);
}

static void
cli_buildopt_mime(struct buildopt *bopt, const char *ext)
{
	struct mime_type	*mime;
	char			*type;

	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		fatal("mime_add only supported in global context");

	if ((type = strchr(ext, ':')) == NULL)
		fatal("no type given in %s", ext);

	*(type)++ = '\0';
	TAILQ_FOREACH(mime, &mime_types, list) {
		if (!strcmp(mime->ext, ext))
			fatal("duplicate extension %s found", ext);
	}

	mime = cli_malloc(sizeof(*mime));
	mime->ext = cli_strdup(ext);
	mime->type = cli_strdup(type);

	TAILQ_INSERT_TAIL(&mime_types, mime, list);
}

static void
cli_build_flags_common(struct buildopt *bopt, struct cli_buf *buf)
{
	size_t		len;
	char		*data;

	cli_buf_appendf(buf, "-fPIC ");

	if (bopt != NULL)
		cli_buf_appendf(buf, "-Isrc -Isrc/includes ");

	if (bopt == NULL || bopt->single_binary == 0)
		cli_buf_appendf(buf, "-I%s/include ", prefix);
	else
		cli_buf_appendf(buf, "-I%s/include ", bopt->kore_source);

	if (bopt == NULL || bopt->single_binary == 0) {
		cli_kore_load_file("features", bopt, &data, &len);
		cli_buf_append(buf, data, len);
		cli_buf_appendf(buf, " ");
		free(data);
	}
}

static void
cli_build_cflags(struct buildopt *bopt)
{
	size_t			len;
	struct buildopt		*obopt;
	char			*string, *buf, *env;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		fatal("no such build flavor: %s", flavor);

	if (bopt->cflags == NULL)
		bopt->cflags = cli_buf_alloc(128);

	cli_build_flags_common(bopt, bopt->cflags);

	if (obopt != NULL && obopt->cflags != NULL) {
		cli_buf_append(bopt->cflags, obopt->cflags->data,
		    obopt->cflags->offset);
	}

	if (bopt->single_binary) {
		cli_kore_load_file("features", bopt, &buf, &len);
		cli_buf_append(bopt->cflags, buf, len);
		cli_buf_appendf(bopt->cflags, " ");
		free(buf);
	}

	if ((env = getenv("CFLAGS")) != NULL)
		cli_buf_appendf(bopt->cflags, "%s", env);

	string = cli_buf_stringify(bopt->cflags, NULL);
	printf("CFLAGS=%s\n", string);
	cflags_count = cli_split_string(string, " ", cflags, CFLAGS_MAX);
}

static void
cli_build_cxxflags(struct buildopt *bopt)
{
	struct buildopt		*obopt;
	char			*string, *env;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		fatal("no such build flavor: %s", flavor);

	if (bopt->cxxflags == NULL)
		bopt->cxxflags = cli_buf_alloc(128);

	cli_build_flags_common(bopt, bopt->cxxflags);

	if (obopt != NULL && obopt->cxxflags != NULL) {
		cli_buf_append(bopt->cxxflags, obopt->cxxflags->data,
		    obopt->cxxflags->offset);
	}

	if ((env = getenv("CXXFLAGS")) != NULL)
		cli_buf_appendf(bopt->cxxflags, "%s", env);

	string = cli_buf_stringify(bopt->cxxflags, NULL);
	if (cxx_files_count > 0)
		printf("CXXFLAGS=%s\n", string);
	cxxflags_count = cli_split_string(string, " ", cxxflags, CXXFLAGS_MAX);
}

static void
cli_build_ldflags(struct buildopt *bopt)
{
	int			fd;
	size_t			len;
	struct buildopt		*obopt;
	char			*string, *buf, *env, *path;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		fatal("no such build flavor: %s", flavor);

	if (bopt->ldflags == NULL)
		bopt->ldflags = cli_buf_alloc(128);

	if (bopt->single_binary == 0) {
#if defined(__MACH__)
		cli_buf_appendf(bopt->ldflags,
		    "-dynamiclib -undefined suppress -flat_namespace ");
#else
		cli_buf_appendf(bopt->ldflags, "-shared ");
#endif
	} else {
		(void)cli_vasprintf(&path, "%s/ldflags", object_dir);
		cli_file_open(path, O_RDONLY, &fd);
		cli_file_read(fd, &buf, &len);
		cli_file_close(fd);
		if (len == 0)
			fatal("ldflags is empty");
		len--;

		cli_buf_append(bopt->ldflags, buf, len);
		cli_buf_appendf(bopt->ldflags, " ");
		free(buf);
	}

	if (obopt != NULL && obopt->ldflags != NULL) {
		cli_buf_append(bopt->ldflags, obopt->ldflags->data,
		    obopt->ldflags->offset);
	}

	if ((env = getenv("LDFLAGS")) != NULL)
		cli_buf_appendf(bopt->ldflags, "%s", env);

	string = cli_buf_stringify(bopt->ldflags, NULL);
	printf("LDFLAGS=%s\n", string);
	ldflags_count = cli_split_string(string, " ", ldflags, LD_FLAGS_MAX);
}

static void
cli_flavor_load(void)
{
	FILE		*fp;
	char		buf[BUFSIZ], pwd[MAXPATHLEN], *p, *conf, *env;

	if ((env = getenv("KORE_BUILD_FLAVOR")) != NULL) {
		flavor = cli_strdup(env);
		return;
	}

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);
	if (appl == NULL)
		fatal("basename: %s", errno_s);
	appl = cli_strdup(appl);
	(void)cli_vasprintf(&conf, "conf/%s.conf", appl);

	if (!cli_dir_exists("conf") || !cli_file_exists(conf))
		fatal("%s doesn't appear to be a kore app", appl);
	free(conf);

	if ((fp = fopen(".flavor", "r")) == NULL) {
		flavor = cli_strdup("dev");
		return;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL)
		fatal("failed to read flavor from file");

	if ((p = strchr(buf, '\n')) != NULL)
		*p = '\0';

	flavor = cli_strdup(buf);
	(void)fclose(fp);
}

static void
cli_kore_load_file(const char *name, struct buildopt *bopt,
    char **out, size_t *outlen)
{
	int		fd;
	size_t		len;
	char		*path, *data;

	if (bopt != NULL && bopt->single_binary) {
		(void)cli_vasprintf(&path, "%s/%s", object_dir, name);
	} else {
		(void)cli_vasprintf(&path, "%s/share/kore/%s", prefix, name);
	}

	cli_file_open(path, O_RDONLY, &fd);
	cli_file_read(fd, &data, &len);
	cli_file_close(fd);
	free(path);

	if (len == 0)
		fatal("%s is empty", name);

	len--;

	*out = data;
	*outlen = len;
}

static void
cli_flavor_change(const char *name)
{
	FILE			*fp;
	int			ret;
	struct buildopt		*bopt;

	if ((bopt = cli_buildopt_find(name)) == NULL)
		fatal("no such flavor: %s", name);

	if ((fp = fopen(".flavor.tmp", "w")) == NULL)
		fatal("failed to open temporary file to save flavor");

	ret = fprintf(fp, "%s\n", name);
	if (ret == -1 || (size_t)ret != (strlen(name) + 1))
		fatal("failed to write new build flavor");

	(void)fclose(fp);

	if (rename(".flavor.tmp", ".flavor") == -1)
		fatal("failed to replace build flavor");

	cli_clean(0, NULL);
}

static void
cli_spawn_proc(void (*cb)(void *), void *arg)
{
	pid_t		pid;
	int		status;

	pid = fork();
	switch (pid) {
	case -1:
		fatal("cli_compile_cfile: fork() %s", errno_s);
		/* NOTREACHED */
	case 0:
		cb(arg);
		fatal("cli_spawn_proc: %s", errno_s);
		/* NOTREACHED */
	default:
		break;
	}

	if (waitpid(pid, &status, 0) == -1)
		fatal("couldn't wait for child %d", pid);

	if (WEXITSTATUS(status) || WTERMSIG(status) || WCOREDUMP(status))
		fatal("subprocess trouble, check output");
}

static int
cli_vasprintf(char **out, const char *fmt, ...)
{
	int		l;
	va_list		args;

	va_start(args, fmt);
	l = vasprintf(out, fmt, args);
	va_end(args);

	if (l == -1)
		fatal("cli_vasprintf");

	return (l);
}

static void
cli_cleanup_files(const char *spath)
{
	cli_find_files(spath, cli_file_remove);

	if (rmdir(spath) == -1 && errno != ENOENT)
		printf("couldn't rmdir %s\n", spath);
}

static void *
cli_malloc(size_t len)
{
	void		*ptr;

	if ((ptr = calloc(1, len)) == NULL)
		fatal("calloc: %s", errno_s);

	return (ptr);
}

static void *
cli_realloc(void *ptr, size_t len)
{
	void		*nptr;

	if ((nptr = realloc(ptr, len)) == NULL)
		fatal("realloc: %s", errno_s);

	return (nptr);
}

static char *
cli_strdup(const char *string)
{
	char		*copy;

	if ((copy = strdup(string)) == NULL)
		fatal("strdup: %s", errno_s);

	return (copy);
}

struct cli_buf *
cli_buf_alloc(size_t initial)
{
	struct cli_buf		*buf;

	buf = cli_malloc(sizeof(*buf));

	if (initial > 0)
		buf->data = cli_malloc(initial);
	else
		buf->data = NULL;

	buf->length = initial;
	buf->offset = 0;

	return (buf);
}

void
cli_buf_free(struct cli_buf *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->offset = 0;
	buf->length = 0;
	free(buf);
}

void
cli_buf_append(struct cli_buf *buf, const void *d, size_t len)
{
	if ((buf->offset + len) < len)
		fatal("overflow in cli_buf_append");

	if ((buf->offset + len) > buf->length) {
		buf->length += len;
		buf->data = cli_realloc(buf->data, buf->length);
	}

	memcpy((buf->data + buf->offset), d, len);
	buf->offset += len;
}

void
cli_buf_appendv(struct cli_buf *buf, const char *fmt, va_list args)
{
	int		l;
	va_list		copy;
	char		*b, sb[BUFSIZ];

	va_copy(copy, args);

	l = vsnprintf(sb, sizeof(sb), fmt, args);
	if (l == -1)
		fatal("cli_buf_appendv(): vsnprintf error");

	if ((size_t)l >= sizeof(sb)) {
		l = vasprintf(&b, fmt, copy);
		if (l == -1)
			fatal("cli_buf_appendv(): error or truncation");
	} else {
		b = sb;
	}

	cli_buf_append(buf, b, l);
	if (b != sb)
		free(b);

	va_end(copy);
}

void
cli_buf_appendf(struct cli_buf *buf, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	cli_buf_appendv(buf, fmt, args);
	va_end(args);
}

char *
cli_buf_stringify(struct cli_buf *buf, size_t *len)
{
	char		c;

	if (len != NULL)
		*len = buf->offset;

	c = '\0';
	cli_buf_append(buf, &c, sizeof(c));

	return ((char *)buf->data);
}

static int
cli_split_string(char *input, const char *delim, char **out, size_t ele)
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

static char *
cli_read_line(FILE *fp, char *in, size_t len)
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

static char *
cli_text_trim(char *string, size_t len)
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

static long long
cli_strtonum(const char *str, long long min, long long max)
{
	long long	l;
	char		*ep;

	if (min > max)
		fatal("cli_strtonum: min > max");

	errno = 0;
	l = strtoll(str, &ep, 10);
	if (errno != 0 || str == ep || *ep != '\0')
		fatal("strtoll(): %s", errno_s);

	if (l < min)
		fatal("cli_strtonum: value < min");

	if (l > max)
		fatal("cli_strtonum: value > max");

	return (l);
}

static void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (command != NULL)
		printf("kore %s: %s\n", command->name, buf);
	else
		printf("kore: %s\n", buf);

	exit(1);
}
