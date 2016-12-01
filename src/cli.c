/*
 * Copyright (c) 2014 Joris Vink <joris@coders.se>
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

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>

#include "kore.h"

#if defined(OpenBSD) || defined(__FreeBSD_version) || \
    defined(NetBSD) || defined(__DragonFly_version)
#define PRI_TIME_T		"d"
#endif

#if defined(__linux__)
#if defined(__x86_64__)
#define PRI_TIME_T		PRIu64
#else
#define PRI_TIME_T		"ld"
#endif
#endif

#if defined(__MACH__)
#define PRI_TIME_T		"ld"
#endif

#define LD_FLAGS_MAX		30
#define CFLAGS_MAX		30
#define CXXFLAGS_MAX		CFLAGS_MAX

#define BUILD_NOBUILD		0
#define BUILD_C			1
#define BUILD_CXX		2

struct buildopt {
	char			*name;
	char			*kore_source;
	char			*kore_flavor;
	int			single_binary;
	struct kore_buf		*cflags;
	struct kore_buf		*cxxflags;
	struct kore_buf		*ldflags;
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

static void		cli_fatal(const char *, ...) __attribute__((noreturn));
static void		cli_file_close(int);
static void		cli_run_kore(void);
static void		cli_generate_certs(void);
static void		cli_link_library(void *);
static void		cli_compile_kore(void *);
static void		cli_compile_source_file(void *);
static void		cli_mkdir(const char *, int);
static int		cli_dir_exists(const char *);
static int		cli_file_exists(const char *);
static void		cli_cleanup_files(const char *);
static void		cli_build_cflags(struct buildopt *);
static void		cli_build_cxxflags(struct buildopt *);
static void		cli_build_ldflags(struct buildopt *);
static void		cli_file_writef(int, const char *, ...);
static void		cli_file_open(const char *, int, int *);
static void		cli_file_remove(char *, struct dirent *);
static void		cli_build_asset(char *, struct dirent *);
static void		cli_file_write(int, const void *, size_t);
static int		cli_vasprintf(char **, const char *, ...);
static void		cli_spawn_proc(void (*cb)(void *), void *);
static void		cli_write_asset(const char *, const char *);
static void		cli_register_kore_file(char *, struct dirent *);
static void		cli_register_source_file(char *, struct dirent *);
static void		cli_file_create(const char *, const char *, size_t);
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

static void		cli_flavor_load(void);
static void		cli_flavor_change(const char *);

static void		cli_run(int, char **);
static void		cli_help(int, char **);
static void		cli_build(int, char **);
static void		cli_clean(int, char **);
static void		cli_create(int, char **);
static void		cli_flavor(int, char **);

static void		file_create_src(void);
static void		file_create_config(void);
static void		file_create_gitignore(void);

static struct cmd cmds[] = {
	{ "help",	"this help text",			cli_help },
	{ "run",	"run an application (-fnr implied)",	cli_run },
	{ "build",	"build an application",			cli_build },
	{ "clean",	"cleanup the build files",		cli_clean },
	{ "create",	"create a new application skeleton",	cli_create },
	{ "flavor",	"switch build flavor",			cli_flavor },
	{ NULL,		NULL,					NULL }
};

static struct filegen gen_files[] = {
	{ file_create_src },
	{ file_create_config },
	{ file_create_gitignore },
	{ NULL }
};

static const char *gen_dirs[] = {
	"src",
#if !defined(KORE_NO_TLS)
	"cert",
#endif
	"conf",
	"assets",
	NULL
};

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
	"bind\t\t127.0.0.1 8888\n"
	"load\t\t./%s.so\n"
#if !defined(KORE_NO_TLS)
	"tls_dhparam\tdh2048.pem\n"
#endif
	"\n"
	"domain * {\n"
#if !defined(KORE_NO_TLS)
	"\tcertfile\tcert/server.crt\n"
	"\tcertkey\t\tcert/server.key\n"
#endif
	"\tstatic\t/\tpage\n"
	"}\n";

static const char *build_data =
	"# %s build config\n"
	"# You can switch flavors using: kore flavor [newflavor]\n"
	"\n"
	"# Set to yes if you wish to produce a single binary instead\n"
	"# of a dynamic library. If you set this to yes you must also\n"
	"# set kore_source together with kore_flavor and update ldflags\n"
	"# to include the appropriate libraries you will be linking with.\n"
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

#if !defined(KORE_NO_TLS)
static const char *dh2048_data =
	"-----BEGIN DH PARAMETERS-----\n"
	"MIIBCAKCAQEAn4f4Qn5SudFjEYPWTbUaOTLUH85YWmmPFW1+b5bRa9ygr+1wfamv\n"
	"VKVT7jO8c4msSNikUf6eEfoH0H4VTCaj+Habwu+Sj+I416r3mliMD4SjNsUJrBrY\n"
	"Y0QV3ZUgZz4A8ARk/WwQcRl8+ZXJz34IaLwAcpyNhoV46iHVxW0ty8ND0U4DIku/\n"
	"PNayKimu4BXWXk4RfwNVP59t8DQKqjshZ4fDnbotskmSZ+e+FHrd+Kvrq/WButvV\n"
	"Bzy9fYgnUlJ82g/bziCI83R2xAdtH014fR63MpElkqdNeChb94pPbEdFlNUvYIBN\n"
	"xx2vTUQMqRbB4UdG2zuzzr5j98HDdblQ+wIBAg==\n"
	"-----END DH PARAMETERS-----";
#endif

static const char *gitignore = "*.o\n.flavor\n.objs\n%s.so\nassets.h\ncert\n";

static int			s_fd = -1;
static char			*appl = NULL;
static int			run_after = 0;
static char			*rootdir = NULL;
static char			*compiler_c = "gcc";
static char			*compiler_cpp = "g++";
static char			*compiler_ld = "gcc";
static struct cfile_list	source_files;
static struct buildopt_list	build_options;
static int			source_files_count;
static int			cxx_files_count;
static struct cmd		*command = NULL;
static int			cflags_count = 0;
static int			cxxflags_count = 0;
static int			ldflags_count = 0;
static char			*flavor = NULL;
static char			*cflags[CFLAGS_MAX];
static char			*cxxflags[CXXFLAGS_MAX];
static char			*ldflags[LD_FLAGS_MAX];

void
kore_cli_usage(int local)
{
	int		i;

	if (local)
		fprintf(stderr, "Usage: kore [command]\n");

	fprintf(stderr, "\nAvailable commands:\n");
	for (i = 0; cmds[i].name != NULL; i++)
		printf("\t%s\t%s\n", cmds[i].name, cmds[i].descr);

	fprintf(stderr, "\nThe commands mostly exist for your convenience\n");
	fprintf(stderr, "when hacking on your Kore applications.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Production servers should be started using ");
	fprintf(stderr, "the options.\n");

	fprintf(stderr, "\nFind more information on https://kore.io\n");
	exit(1);
}

int
kore_cli_main(int argc, char **argv)
{
	int		i;

	if (argc < 1)
		kore_cli_usage(1);

	(void)umask(S_IWGRP|S_IWOTH);

	if ((flavor = strchr(argv[0], ':')) != NULL)
		*(flavor)++ = '\0';

	for (i = 0; cmds[i].name != NULL; i++) {
		if (!strcmp(argv[0], cmds[i].name)) {
			argc--;
			argv++;
			command = &cmds[i];
			cmds[i].cb(argc, argv);
			break;
		}
	}

	if (cmds[i].name == NULL) {
		fprintf(stderr, "No such command: %s\n", argv[0]);
		kore_cli_usage(1);
	}

	return (0);
}

static void
cli_help(int argc, char **argv)
{
	kore_cli_usage(1);
}

static void
cli_create(int argc, char **argv)
{
	int		i;
	char		*fpath;

	if (argc != 1)
		cli_fatal("missing application name");

	appl = argv[0];
	cli_mkdir(appl, 0755);
	rootdir = appl;

	for (i = 0; gen_dirs[i] != NULL; i++) {
		(void)cli_vasprintf(&fpath, "%s/%s", appl, gen_dirs[i]);
		cli_mkdir(fpath, 0755);
		free(fpath);
	}

	for (i = 0; gen_files[i].cb != NULL; i++)
		gen_files[i].cb();

	cli_generate_certs();

	printf("%s created successfully!\n", appl);

#if !defined(KORE_NO_TLS)
	printf("note: do NOT use the created DH parameters/certificates in production\n");
#endif
}

static void
cli_flavor(int argc, char **argv)
{
	struct buildopt		*bopt;
	char			pwd[MAXPATHLEN], *conf;

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		cli_fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);
	(void)cli_vasprintf(&conf, "conf/%s.conf", appl);
	if (!cli_dir_exists("conf") || !cli_file_exists(conf))
		cli_fatal("%s doesn't appear to be a kore app", appl);
	free(conf);

	TAILQ_INIT(&build_options);
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
	struct dirent		dp;
	struct cfile		*cf;
	struct buildopt		*bopt;
	struct timeval		times[2];
	char			*build_path;
	int			requires_relink, l;
	char			*sofile, *config, *data;
	char			*assets_path, *p, *obj_path, *cpath;
	char			pwd[PATH_MAX], *src_path, *assets_header;

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		cli_fatal("could not get cwd: %s", errno_s);

	rootdir = ".";
	appl = basename(pwd);

	if ((p = getenv("CC")) != NULL)
		compiler_c = p;

	if ((p = getenv("CXX")) != NULL)
		compiler_cpp = p;

	source_files_count = 0;
	cxx_files_count = 0;
	TAILQ_INIT(&source_files);
	TAILQ_INIT(&build_options);

	(void)cli_vasprintf(&src_path, "%s/src", rootdir);
	(void)cli_vasprintf(&assets_path, "%s/assets", rootdir);
	(void)cli_vasprintf(&config, "%s/conf/%s.conf", rootdir, appl);
	(void)cli_vasprintf(&assets_header, "%s/src/assets.h", rootdir);
	(void)cli_vasprintf(&build_path, "%s/conf/build.conf", rootdir);

	if (!cli_dir_exists(src_path) || !cli_file_exists(config))
		cli_fatal("%s doesn't appear to be a kore app", appl);

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");
	if (!cli_file_exists(build_path)) {
		l = cli_vasprintf(&data, build_data, appl);
		cli_file_create("conf/build.conf", data, l);
		free(data);
	}

	cli_find_files(src_path, cli_register_source_file);
	free(src_path);

	cli_buildopt_parse(build_path);
	free(build_path);

	(void)cli_vasprintf(&obj_path, "%s/.objs", rootdir);
	if (!cli_dir_exists(obj_path))
		cli_mkdir(obj_path, 0755);
	free(obj_path);

	if (bopt->single_binary) {
		if (bopt->kore_source == NULL)
			cli_fatal("single_binary set but not kore_source");

		printf("building kore (%s)\n", bopt->kore_source);
		cli_spawn_proc(cli_compile_kore, bopt);

		(void)cli_vasprintf(&src_path, "%s/src", bopt->kore_source);
		cli_find_files(src_path, cli_register_kore_file);
		free(src_path);
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

	(void)unlink(assets_header);
	free(assets_header);

	(void)cli_vasprintf(&cpath, "%s/cert", rootdir);
	if (!cli_dir_exists(cpath)) {
		cli_mkdir(cpath, 0700);
		cli_generate_certs();
	}
	free(cpath);

	if (bopt->single_binary) {
		requires_relink++;
		(void)cli_vasprintf(&sofile, "%s", appl);
	} else {
		(void)cli_vasprintf(&sofile, "%s.so", appl);
	}

	if (!cli_file_exists(sofile))
		requires_relink++;
	free(sofile);

	if (requires_relink) {
		cli_spawn_proc(cli_link_library, bopt);
		printf("%s built successfully!\n", appl);
	} else {
		printf("nothing to be done!\n");
	}

	if (run_after == 0)
		cli_buildopt_cleanup();
}

static void
cli_clean(int argc, char **argv)
{
	char		pwd[PATH_MAX], *sofile;

	if (cli_dir_exists(".objs"))
		cli_cleanup_files(".objs");

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		cli_fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);
	(void)cli_vasprintf(&sofile, "%s.so", appl);
	if (unlink(sofile) == -1 && errno != ENOENT)
		printf("couldn't unlink %s: %s", sofile, errno_s);

	free(sofile);
}

static void
cli_run(int argc, char **argv)
{
	run_after = 1;
	cli_build(argc, argv);

	if (chdir(rootdir) == -1)
		cli_fatal("couldn't change directory to %s", rootdir);

	/*
	 * We are exec()'ing kore again, while we could technically set
	 * the right cli options manually and just continue running.
	 */
	cli_run_kore();
}

static void
file_create_src(void)
{
	char		*name;

	(void)cli_vasprintf(&name, "src/%s.c", appl);
	cli_file_create(name, src_data, strlen(src_data));
	free(name);
}

static void
file_create_config(void)
{
	int		l;
	char		*name, *data;

	(void)cli_vasprintf(&name, "conf/%s.conf", appl);
	l = cli_vasprintf(&data, config_data, appl, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);

	l = cli_vasprintf(&data, build_data, appl);
	cli_file_create("conf/build.conf", data, l);
	free(data);
}

static void
file_create_gitignore(void)
{
	int		l;
	char		*data;

	l = cli_vasprintf(&data, gitignore, appl);
	cli_file_create(".gitignore", data, l);
	free(data);
}

static void
cli_mkdir(const char *fpath, int mode)
{
	if (mkdir(fpath, mode) == -1)
		cli_fatal("cli_mkdir(%s): %s", fpath, errno_s);
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
		cli_fatal("stat(%s): %s", opath, errno_s);
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
		cli_fatal("cli_file_open(%s): %s", fpath, errno_s);
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
		cli_fatal("cli_file_writef");

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
			cli_fatal("cli_file_write: %s", errno_s);
		}

		written += r;
	}
}

static void
cli_file_create(const char *name, const char *data, size_t len)
{
	int		fd;
	char		*fpath;

	(void)cli_vasprintf(&fpath, "%s/%s", rootdir, name);

	cli_file_open(fpath, O_CREAT | O_TRUNC | O_WRONLY, &fd);
	cli_file_write(fd, data, len);
	cli_file_close(fd);

	printf("created %s\n", fpath);
	free(fpath);
}

static void
cli_write_asset(const char *n, const char *e)
{
	cli_file_writef(s_fd, "extern u_int8_t asset_%s_%s[];\n", n, e);
	cli_file_writef(s_fd, "extern u_int32_t asset_len_%s_%s;\n", n, e);
	cli_file_writef(s_fd, "extern time_t asset_mtime_%s_%s;\n", n, e);
}

static void
cli_build_asset(char *fpath, struct dirent *dp)
{
	struct stat		st;
	u_int8_t		*d;
	off_t			off;
	void			*base;
	int			in, out;
	char			*cpath, *ext, *opath, *p, *name;

	name = kore_strdup(dp->d_name);

	/* Grab the extension as we're using it in the symbol name. */
	if ((ext = strrchr(name, '.')) == NULL)
		cli_fatal("couldn't find ext in %s", name);

	/* Replace dots, spaces, etc etc with underscores. */
	for (p = name; *p != '\0'; p++) {
		if (*p == '.' || isspace(*p) || *p == '-')
			*p = '_';
	}

	/* Grab inode information. */
	if (stat(fpath, &st) == -1)
		cli_fatal("stat: %s %s", fpath, errno_s);

	/* If this file was empty, skip it. */
	if (st.st_size == 0) {
		printf("skipping empty asset %s\n", name);
		return;
	}

	(void)cli_vasprintf(&opath, "%s/.objs/%s.o", rootdir, name);
	(void)cli_vasprintf(&cpath, "%s/.objs/%s.c", rootdir, name);

	/* Check if the file needs to be built. */
	if (!cli_file_requires_build(&st, opath)) {
		*(ext)++ = '\0';
		cli_write_asset(name, ext);
		*ext = '_';

		cli_add_source_file(name, cpath, opath, &st, BUILD_NOBUILD);
		kore_free(name);
		return;
	}

	/* Open the file we're converting. */
	cli_file_open(fpath, O_RDONLY, &in);

	/* mmap our in file. */
	if ((base = mmap(NULL, st.st_size,
	    PROT_READ, MAP_PRIVATE, in, 0)) == MAP_FAILED)
		cli_fatal("mmap: %s %s", fpath, errno_s);

	/* Create the c file where we will write too. */
	cli_file_open(cpath, O_CREAT | O_TRUNC | O_WRONLY, &out);

	/* No longer need name so cut off the extension. */
	printf("building asset %s\n", dp->d_name);
	*(ext)++ = '\0';

	/* Start generating the file. */
	cli_file_writef(out, "/* Auto generated */\n");
	cli_file_writef(out, "#include <sys/types.h>\n\n");

	/* Write the file data as a byte array. */
	cli_file_writef(out, "u_int8_t asset_%s_%s[] = {\n", name, ext);
	d = base;
	for (off = 0; off < st.st_size; off++)
		cli_file_writef(out, "0x%02x,", *d++);

	/*
	 * Always NUL-terminate the asset, even if this NUL is not included in
	 * the actual length. This way assets can be cast to char * without
	 * any additional thinking for the developer.
	 */
	cli_file_writef(out, "0x00");

	/* Add the meta data. */
	cli_file_writef(out, "};\n\n");
	cli_file_writef(out, "u_int32_t asset_len_%s_%s = %" PRIu32 ";\n",
	    name, ext, (u_int32_t)st.st_size);
	cli_file_writef(out, "time_t asset_mtime_%s_%s = %" PRI_TIME_T ";\n",
	    name, ext, st.st_mtime);

	/* Write the file symbols into assets.h so they can be used. */
	cli_write_asset(name, ext);

	/* Cleanup static file source. */
	if (munmap(base, st.st_size) == -1)
		cli_fatal("munmap: %s %s", fpath, errno_s);

	/* Cleanup fds */
	cli_file_close(in);
	cli_file_close(out);

	/* Restore the original name */
	*--ext = '.';

	/* Register the .c file now (cpath is free'd later). */
	cli_add_source_file(name, cpath, opath, &st, BUILD_C);
	kore_free(name);
}

static void
cli_add_source_file(char *name, char *fpath, char *opath, struct stat *st,
    int build)
{
	struct cfile		*cf;

	source_files_count++;
	cf = kore_malloc(sizeof(*cf));

	cf->st = *st;
	cf->build = build;
	cf->fpath = fpath;
	cf->opath = opath;
	cf->name = kore_strdup(name);

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
		cli_fatal("stat(%s): %s", fpath, errno_s);

	if (!strcmp(ext, ".cpp"))
		cxx_files_count++;

	(void)cli_vasprintf(&opath, "%s/.objs/%s.o", rootdir, dp->d_name);
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
		cli_fatal("stat(%s): %s", fpath, errno_s);

	*ext = '\0';
	if ((fname = basename(fpath)) == NULL)
		cli_fatal("basename failed");

	(void)cli_vasprintf(&opath, "%s/.objs/%s.o", rootdir, fname);

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
		cli_fatal("cli_find_files: opendir(%s): %s", path, errno_s);

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

static void
cli_generate_certs(void)
{
#if !defined(KORE_NO_TLS)
	BIGNUM			*e;
	FILE			*fp;
	time_t			now;
	X509_NAME		*name;
	EVP_PKEY		*pkey;
	X509			*x509;
	RSA			*kpair;
	char			*fpath, issuer[64];

	/* Write out DH parameters. */
	cli_file_create("dh2048.pem", dh2048_data, strlen(dh2048_data));

	/* Create new certificate. */
	if ((x509 = X509_new()) == NULL)
		cli_fatal("X509_new(): %s", ssl_errno_s);

	/* Generate version 3. */
	if (!X509_set_version(x509, 2))
		cli_fatal("X509_set_version(): %s", ssl_errno_s);

	/* Generate RSA keys. */
	if ((pkey = EVP_PKEY_new()) == NULL)
		cli_fatal("EVP_PKEY_new(): %s", ssl_errno_s);
	if ((kpair = RSA_new()) == NULL)
		cli_fatal("RSA_new(): %s", ssl_errno_s);
	if ((e = BN_new()) == NULL)
		cli_fatal("BN_new(): %s", ssl_errno_s);

	if (!BN_set_word(e, 65537))
		cli_fatal("BN_set_word(): %s", ssl_errno_s);
	if (!RSA_generate_key_ex(kpair, 2048, e, NULL))
		cli_fatal("RSA_generate_key_ex(): %s", ssl_errno_s);

	BN_free(e);

	if (!EVP_PKEY_assign_RSA(pkey, kpair))
		cli_fatal("EVP_PKEY_assign_RSA(): %s", ssl_errno_s);

	/* Set serial number to current timestamp. */
	time(&now);
	if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), now))
		cli_fatal("ASN1_INTEGER_set(): %s", ssl_errno_s);

	/* Not before and not after dates. */
	if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
		cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);
	if (!X509_gmtime_adj(X509_get_notAfter(x509),
	    (long)60 * 60 * 24 * 3000))
		cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);

	/* Attach the pkey to the certificate. */
	if (!X509_set_pubkey(x509, pkey))
		cli_fatal("X509_set_pubkey(): %s", ssl_errno_s);

	/* Set certificate information. */
	if ((name = X509_get_subject_name(x509)) == NULL)
		cli_fatal("X509_get_subject_name(): %s", ssl_errno_s);

	(void)snprintf(issuer, sizeof(issuer), "kore autogen: %s", appl);
	if (!X509_NAME_add_entry_by_txt(name, "C",
	    MBSTRING_ASC, (const unsigned char *)"SE", -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): C %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "O",
	    MBSTRING_ASC, (const unsigned char *)issuer, -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): O %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): CN %s", ssl_errno_s);

	if (!X509_set_issuer_name(x509, name))
		cli_fatal("X509_set_issuer_name(): %s", ssl_errno_s);

	if (!X509_sign(x509, pkey, EVP_sha256()))
		cli_fatal("X509_sign(): %s", ssl_errno_s);

	(void)cli_vasprintf(&fpath, "%s/cert/server.key", rootdir);
	if ((fp = fopen(fpath, "w")) == NULL)
		cli_fatal("fopen(%s): %s", fpath, errno_s);
	free(fpath);

	if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
		cli_fatal("PEM_write_PrivateKey(): %s", ssl_errno_s);
	fclose(fp);

	(void)cli_vasprintf(&fpath, "%s/cert/server.crt", rootdir);
	if ((fp = fopen(fpath, "w")) == NULL)
		cli_fatal("fopen(%s): %s", fpath, errno_s);
	free(fpath);

	if (!PEM_write_X509(fp, x509))
		cli_fatal("PEM_write_X509(%s)", errno_s);
	fclose(fp);

	EVP_PKEY_free(pkey);
	X509_free(x509);
#endif
}

static void
cli_compile_source_file(void *arg)
{
	int		idx, i;
	struct cfile	*cf = arg;
	char		*args[32 + CFLAGS_MAX];
	char		*compiler;
	char		**flags;
	int		flags_count;

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
		cli_fatal("cli_compile_file: unexpected file type: %d",
		    cf->build);
		break;
	}

	idx = 0;
	args[idx++] = compiler;

	for (i = 0; i < flags_count; i++)
		args[idx++] = flags[i];

	args[idx++] = "-c";
	args[idx++] = cf->fpath;
	args[idx++] = "-o";
	args[idx++] = cf->opath;
	args[idx] = NULL;

	execvp(compiler, args);
	cli_fatal("failed to start '%s': %s", compiler, errno_s);
}

static void
cli_link_library(void *arg)
{
	struct cfile		*cf;
	struct buildopt		*bopt;
	int			idx, i;
	char			*output;
	char			*args[source_files_count + 11 + LD_FLAGS_MAX];

	bopt = arg;

	if (bopt->single_binary)
		(void)cli_vasprintf(&output, "%s/%s", rootdir, appl);
	else
		(void)cli_vasprintf(&output, "%s/%s.so", rootdir, appl);

	idx = 0;
	args[idx++] = compiler_ld;

	TAILQ_FOREACH(cf, &source_files, list)
		args[idx++] = cf->opath;

	for (i = 0; i < ldflags_count; i++)
		args[idx++] = ldflags[i];

	if (bopt->single_binary) {
		args[idx++] = "-rdynamic";
#if defined(__linux__)
		args[idx++] = "-ldl";
#endif
	}

	args[idx++] = "-o";
	args[idx++] = output;
	args[idx] = NULL;

	execvp(compiler_ld, args);
	cli_fatal("failed to start '%s': %s", compiler_ld, errno_s);
}

static void
cli_compile_kore(void *arg)
{
	struct buildopt		*bopt = arg;
	int			idx, i, fcnt;
	char			*obj, *args[16], pwd[MAXPATHLEN], *flavors[7];

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		cli_fatal("could not get cwd: %s", errno_s);

	(void)cli_vasprintf(&obj, "OBJDIR=%s/.objs", pwd);

	if (putenv(obj) != 0)
		cli_fatal("cannot set OBJDIR for building kore");

	if (putenv("CFLAGS=-DKORE_SINGLE_BINARY") != 0)
		cli_fatal("cannot set CFLAGS for building kore");

	fcnt = kore_split_string(bopt->kore_flavor, " ", flavors, 7);

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

	args[idx] = NULL;

	execvp(args[0], args);
	cli_fatal("failed to start '%s': %s", args[0], errno_s);
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
		cmd = "kore";
		flags = "-fnrc";
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
	cli_fatal("failed to start '%s': %s", args[0], errno_s);
}

static void
cli_buildopt_parse(const char *path)
{
	FILE			*fp;
	struct buildopt		*bopt;
	char			buf[BUFSIZ], *p, *t;

	if ((fp = fopen(path, "r")) == NULL)
		cli_fatal("cli_buildopt_parse: fopen(%s): %s", path, errno_s);

	bopt = NULL;

	while ((p = kore_read_line(fp, buf, sizeof(buf))) != NULL) {
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
				cli_fatal("unexpected '%s'", p);
			*(t)++ = '\0';
			if (strcmp(t, "{"))
				cli_fatal("expected '{', got '%s'", t);
			bopt = cli_buildopt_new(p);
			continue;
		}

		if ((t = strchr(p, '=')) == NULL) {
			printf("bad buildopt line: '%s'\n", p);
			continue;
		}

parse_option:
		*(t)++ = '\0';

		p = kore_text_trim(p, strlen(p));
		t = kore_text_trim(t, strlen(t));

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
		} else {
			printf("ignoring unknown option '%s'\n", p);
		}
	}

	fclose(fp);
}

static struct buildopt *
cli_buildopt_new(const char *name)
{
	struct buildopt		*bopt;

	bopt = kore_malloc(sizeof(*bopt));
	bopt->cflags = NULL;
	bopt->cxxflags = NULL;
	bopt->ldflags = NULL;
	bopt->single_binary = 0;
	bopt->kore_source = NULL;
	bopt->kore_flavor = NULL;
	bopt->name = kore_strdup(name);

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

	for (bopt = TAILQ_FIRST(&build_options); bopt != NULL; bopt = next) {
		next = TAILQ_NEXT(bopt, list);
		TAILQ_REMOVE(&build_options, bopt, list);

		if (bopt->cflags != NULL)
			kore_buf_free(bopt->cflags);
		if (bopt->cxxflags != NULL)
			kore_buf_free(bopt->cxxflags);
		if (bopt->ldflags != NULL)
			kore_buf_free(bopt->ldflags);
		if (bopt->kore_source != NULL)
			kore_free(bopt->kore_source);
		if (bopt->kore_flavor != NULL)
			kore_free(bopt->kore_flavor);
		kore_free(bopt);
	}
}

static void
cli_buildopt_cflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->cflags == NULL)
		bopt->cflags = kore_buf_alloc(128);

	kore_buf_appendf(bopt->cflags, "%s ", string);
}

static void
cli_buildopt_cxxflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->cxxflags == NULL)
		bopt->cxxflags = kore_buf_alloc(128);

	kore_buf_appendf(bopt->cxxflags, "%s ", string);
}

static void
cli_buildopt_ldflags(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();

	if (bopt->ldflags == NULL)
		bopt->ldflags = kore_buf_alloc(128);

	kore_buf_appendf(bopt->ldflags, "%s ", string);
}

static void
cli_buildopt_single_binary(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		cli_fatal("single_binary only supported in global context");

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
		cli_fatal("kore_source only supported in global context");

	if (bopt->kore_source != NULL)
		kore_free(bopt->kore_source);

	bopt->kore_source = kore_strdup(string);
}

static void
cli_buildopt_kore_flavor(struct buildopt *bopt, const char *string)
{
	if (bopt == NULL)
		bopt = cli_buildopt_default();
	else
		cli_fatal("kore_flavor only supported in global context");

	if (bopt->kore_flavor != NULL)
		kore_free(bopt->kore_flavor);

	bopt->kore_flavor = kore_strdup(string);
}

static void
cli_build_flags_common(struct kore_buf* buf)
{
	kore_buf_appendf(buf,
	    "-fPIC -I%s/src -I%s/src/includes ", rootdir, rootdir);
#if defined(PREFIX)
	kore_buf_appendf(buf, "-I%s/include ", PREFIX);
#else
	kore_buf_appendf(buf, "-I/usr/local/include ");
#endif
#if defined(__MACH__)
	/* Add default openssl include path from homebrew / ports under OSX. */
	kore_buf_appendf(buf, "-I/opt/local/include ");
	kore_buf_appendf(buf, "-I/usr/local/opt/openssl/include ");
#endif
#if defined(KORE_USE_PGSQL)
	kore_buf_appendf(buf, "-I%s ", PGSQL_INCLUDE_PATH);
#endif
#if defined(KORE_NO_HTTP)
	kore_buf_appendf(buf, "-DKORE_NO_HTTP ");
#endif
#if defined(KORE_NO_TLS)
	kore_buf_appendf(buf, "-DKORE_NO_TLS ");
#endif
}

static void
cli_build_cflags(struct buildopt *bopt)
{
	struct buildopt		*obopt;
	char			*string;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		cli_fatal("no such build flavor: %s", flavor);

	if (bopt->cflags == NULL)
		bopt->cflags = kore_buf_alloc(128);

	cli_build_flags_common(bopt->cflags);

	if (obopt != NULL && obopt->cflags != NULL) {
		kore_buf_append(bopt->cflags, obopt->cflags->data,
		    obopt->cflags->offset);
	}

	if (bopt->single_binary)
		kore_buf_appendf(bopt->cflags, "-DKORE_SINGLE_BINARY");

	string = kore_buf_stringify(bopt->cflags, NULL);
	printf("CFLAGS=%s\n", string);
	cflags_count = kore_split_string(string, " ", cflags, CFLAGS_MAX);
}

static void
cli_build_cxxflags(struct buildopt *bopt)
{
	struct buildopt		*obopt;
	char			*string;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		cli_fatal("no such build flavor: %s", flavor);

	if (bopt->cxxflags == NULL)
		bopt->cxxflags = kore_buf_alloc(128);

	cli_build_flags_common(bopt->cxxflags);

	if (obopt != NULL && obopt->cxxflags != NULL) {
		kore_buf_append(bopt->cxxflags, obopt->cxxflags->data,
		    obopt->cxxflags->offset);
	}

	string = kore_buf_stringify(bopt->cxxflags, NULL);
	if (cxx_files_count > 0)
		printf("CXXFLAGS=%s\n", string);
	cxxflags_count = kore_split_string(string, " ", cxxflags, CXXFLAGS_MAX);
}

static void
cli_build_ldflags(struct buildopt *bopt)
{
	struct buildopt		*obopt;
	char			*string;

	if ((obopt = cli_buildopt_find(flavor)) == NULL)
		cli_fatal("no such build flavor: %s", flavor);

	if (bopt->ldflags == NULL)
		bopt->ldflags = kore_buf_alloc(128);

	if (bopt->single_binary == 0) {
#if defined(__MACH__)
		kore_buf_appendf(bopt->ldflags,
		    "-dynamiclib -undefined suppress -flat_namespace ");
#else
		kore_buf_appendf(bopt->ldflags, "-shared ");
#endif
	}

	if (obopt != NULL && obopt->ldflags != NULL) {
		kore_buf_append(bopt->ldflags, obopt->ldflags->data,
		    obopt->ldflags->offset);
	}

	string = kore_buf_stringify(bopt->ldflags, NULL);
	printf("LDFLAGS=%s\n", string);
	ldflags_count = kore_split_string(string, " ", ldflags, LD_FLAGS_MAX);
}

static void
cli_flavor_load(void)
{
	FILE		*fp;
	char		buf[BUFSIZ], pwd[MAXPATHLEN], *p, *conf;

	if (getcwd(pwd, sizeof(pwd)) == NULL)
		cli_fatal("could not get cwd: %s", errno_s);

	appl = basename(pwd);
	if (appl == NULL)
		cli_fatal("basename: %s", errno_s);
	appl = kore_strdup(appl);
	(void)cli_vasprintf(&conf, "conf/%s.conf", appl);

	if (!cli_dir_exists("conf") || !cli_file_exists(conf))
		cli_fatal("%s doesn't appear to be a kore app", appl);
	free(conf);

	if ((fp = fopen(".flavor", "r")) == NULL) {
		flavor = kore_strdup("dev");
		return;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL)
		cli_fatal("failed to read flavor from file");

	if ((p = strchr(buf, '\n')) != NULL)
		*p = '\0';

	flavor = kore_strdup(buf);
	(void)fclose(fp);
}

static void
cli_flavor_change(const char *name)
{
	FILE			*fp;
	int			ret;
	struct buildopt		*bopt;

	if ((bopt = cli_buildopt_find(name)) == NULL)
		cli_fatal("no such flavor: %s", name);

	if ((fp = fopen(".flavor.tmp", "w")) == NULL)
		cli_fatal("failed to open temporary file to save flavor");

	ret = fprintf(fp, "%s\n", name);
	if (ret == -1 || (size_t)ret != (strlen(name) + 1))
		cli_fatal("failed to write new build flavor");

	(void)fclose(fp);

	if (rename(".flavor.tmp", ".flavor") == -1)
		cli_fatal("failed to replace build flavor");

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
		cli_fatal("cli_compile_cfile: fork() %s", errno_s);
		/* NOTREACHED */
	case 0:
		cb(arg);
		cli_fatal("cli_spawn_proc: %s", errno_s);
		/* NOTREACHED */
	default:
		break;
	}

	if (waitpid(pid, &status, 0) == -1)
		cli_fatal("couldn't wait for child %d", pid);

	if (WEXITSTATUS(status) || WTERMSIG(status) || WCOREDUMP(status))
		cli_fatal("subprocess trouble, check output");
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
		cli_fatal("cli_vasprintf");

	return (l);
}

static void
cli_cleanup_files(const char *spath)
{
	cli_find_files(spath, cli_file_remove);

	if (rmdir(spath) == -1 && errno != ENOENT)
		printf("couldn't rmdir %s\n", spath);
}

static void
cli_fatal(const char *fmt, ...)
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
