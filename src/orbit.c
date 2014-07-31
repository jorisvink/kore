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

#define _GNU_SOURCE

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define errno_s		strerror(errno)

struct cmd {
	const char		*name;
	const char		*descr;
	void			(*cb)(int, char **);
};

struct filegen {
	void			(*cb)(void);
};

struct cfile {
	char			*fpath;
	char			*opath;
	TAILQ_ENTRY(cfile)	list;
};

TAILQ_HEAD(cfile_list, cfile);

static void		usage(void);
static void		fatal(const char *, ...);

static void		*orbit_malloc(size_t);
static void		orbit_run_kore(void *);
static void		orbit_link_library(void *);
static void		orbit_compile_cfile(void *);
static void		orbit_mkdir(const char *, int);
static int		orbit_dir_exists(const char *);
static void		orbit_find_cfiles(const char *);
static void		orbit_file_open(const char *, int *);
static void		orbit_file_write(int, const void *, size_t);
static int		orbit_vasprintf(char **, const char *, ...);
static void		orbit_spawn_proc(void (*cb)(void *), void *);
static void		orbit_file_create(const char *, const char *, size_t);

static void		orbit_run(int, char **);
static void		orbit_build(int, char **);
static void		orbit_create(int, char **);

static void		file_create_src(void);
static void		file_create_config(void);
static void		file_create_gitignore(void);

static struct cmd cmds[] = {
	{ "create",	"Create a new application",	orbit_create },
	{ "run",	"Run an application",		orbit_run },
	{ "build",	"Builds an application",	orbit_build },
	{ NULL,		NULL,				NULL }
};

static struct filegen gen_files[] = {
	{ file_create_src },
	{ file_create_config },
	{ file_create_gitignore },
	{ NULL }
};

static const char *gen_dirs[] = {
	"src",
	"conf",
	".objs",
	"static",
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
	"# Placeholder configuration\n"
	"\n"
	"bind\t\t127.0.0.1 8888\n"
	"pidfile\t\tkore.pid\n"
	"load\t\t./%s.so\n"
	"\n"
	"domain 127.0.0.1 {\n"
	"\tstatic\t/\tpage\n"
	"}\n";

static const char *gitignore_data = "*.o\n.objs\n%s.so\n";

static char			*appl = NULL;
static char			*rootdir = NULL;
static struct cfile_list	source_files;
static int			cfiles_count;
static struct cmd		*command = NULL;

static void
usage(void)
{
	int		i;

	fprintf(stderr, "Usage: orbit [command]\n");
	for (i = 0; cmds[i].name != NULL; i++)
		printf("\t%s - %s\n", cmds[i].name, cmds[i].descr);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int		i;

	if (argc < 2)
		usage();

	argc--;
	argv++;

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
		usage();
	}

	return (0);
}

static void
orbit_create(int argc, char **argv)
{
	int		i;
	char		*fpath;

	if (argc != 1)
		fatal("missing application name");

	appl = argv[0];
	orbit_mkdir(appl, 0755);
	for (i = 0; gen_dirs[i] != NULL; i++) {
		orbit_vasprintf(&fpath, "%s/%s", appl, gen_dirs[i]);
		orbit_mkdir(fpath, 0755);
		free(fpath);
	}

	for (i = 0; gen_files[i].cb != NULL; i++)
		gen_files[i].cb();
}

static void
orbit_build(int argc, char **argv)
{
	struct cfile	*cf;
	char		pwd[PATH_MAX], *spath;

	if (argc == 0) {
		if (getcwd(pwd, sizeof(pwd)) == NULL)
			fatal("could not get cwd: %s", errno_s);

		rootdir = ".";
		appl = basename(pwd);
		orbit_vasprintf(&spath, "./src");
	} else {
		appl = argv[0];
		rootdir = appl;
		orbit_vasprintf(&spath, "%s/src", appl);

		if (!orbit_dir_exists(spath))
			fatal("%s doesn't appear to be an app", appl);
	}

	cfiles_count = 0;
	TAILQ_INIT(&source_files);

	/* orbit_build_statics("static"); */
	orbit_find_cfiles(spath);
	free(spath);

	TAILQ_FOREACH(cf, &source_files, list) {
		printf("compiling %s\n", cf->fpath);
		orbit_spawn_proc(orbit_compile_cfile, cf);
	}

	orbit_spawn_proc(orbit_link_library, NULL);

	TAILQ_FOREACH(cf, &source_files, list) {
		if (unlink(cf->opath) == -1)
			printf("couldnt unlink %s\n", cf->opath);
	}
}

static void
orbit_run(int argc, char **argv)
{
	orbit_build(argc, argv);
	orbit_spawn_proc(orbit_run_kore, NULL);
}

static void
file_create_src(void)
{
	char		*name;

	(void)orbit_vasprintf(&name, "src/%s.c", appl);
	orbit_file_create(name, src_data, strlen(src_data));
	free(name);
}

static void
file_create_config(void)
{
	int		l;
	char		*name, *data;

	(void)orbit_vasprintf(&name, "conf/%s.conf", appl);
	l = orbit_vasprintf(&data, config_data, appl);
	orbit_file_create(name, data, l);

	free(name);
	free(data);
}

static void
file_create_gitignore(void)
{
	int		l;
	char		*data;

	l = orbit_vasprintf(&data, gitignore_data, appl);
	orbit_file_create(".gitignore", data, l);
	free(data);
}

static void
orbit_mkdir(const char *fpath, int mode)
{
	if (mkdir(fpath, mode) == -1)
		fatal("orbit_mkdir(%s): %s", fpath, errno_s);
}

static int
orbit_dir_exists(const char *fpath)
{
	struct stat		st;

	if (stat(fpath, &st) == -1)
		return (0);

	if (!S_ISDIR(st.st_mode))
		return (0);

	return (1);
}

static void
orbit_file_open(const char *fpath, int *fd)
{
	if ((*fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, 0755)) == -1)
		fatal("orbit_file_open(%s): %s", fpath, errno_s);
}

static void
orbit_file_close(int fd)
{
	if (close(fd) == -1)
		printf("warning: close() %s\n", errno_s);
}

static void
orbit_file_write(int fd, const void *buf, size_t len)
{
	ssize_t		r;
	size_t		written;

	written = 0;
	while (written != len) {
		r = write(fd, buf + written, len - written);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fatal("orbit_file_write: %s", errno_s);
		}

		written += r;
	}
}

static void
orbit_file_create(const char *name, const char *data, size_t len)
{
	int		fd;
	char		*fpath;

	orbit_vasprintf(&fpath, "%s/%s", appl, name);

	orbit_file_open(fpath, &fd);
	orbit_file_write(fd, data, len);
	orbit_file_close(fd);

	printf("created %s\n", fpath);
	free(fpath);
}

static void
orbit_find_cfiles(const char *path)
{
	DIR			*d;
	struct cfile		*cf;
	struct dirent		*dp;
	char			*fpath;

	if ((d = opendir(path)) == NULL)
		fatal("orbit_find_cfiles: opendir(%s): %s", path, errno_s);

	while ((dp = readdir(d)) != NULL) {
		if (!strcmp(dp->d_name, ".") ||
		    !strcmp(dp->d_name, ".."))
			continue;

		orbit_vasprintf(&fpath, "%s/%s", path, dp->d_name);

		if (dp->d_type == DT_DIR) {
			orbit_find_cfiles(fpath);
			free(fpath);
		} else {
			cfiles_count++;
			cf = orbit_malloc(sizeof(*cf));
			cf->fpath = fpath;
			orbit_vasprintf(&(cf->opath),
			    "%s/.objs/%s.o", rootdir, dp->d_name);
			TAILQ_INSERT_TAIL(&source_files, cf, list);
		}
	}
}

static void
orbit_compile_cfile(void *arg)
{
	struct cfile	*cf = arg;
	char		*args[18], *ipath;

	orbit_vasprintf(&ipath, "-I%s/src", appl);

	args[0] = "gcc";
	args[1] = ipath;
	args[2] = "-I/usr/local/include";
	args[3] = "-Wall";
	args[4] = "-Wstrict-prototypes";
	args[5] = "-Wmissing-prototypes";
	args[6] = "-Wmissing-declarations";
	args[7] = "-Wshadow";
	args[8] = "-Wpointer-arith";
	args[9] = "-Wcast-qual";
	args[10] = "-Wsign-compare";
	args[11] = "-fPIC";
	args[12] = "-g";

	args[13] = "-c";
	args[14] = cf->fpath;
	args[15] = "-o";
	args[16] = cf->opath;
	args[17] = NULL;

	execvp("gcc", args);
}

static void
orbit_link_library(void *arg)
{
	int			idx;
	struct cfile		*cf;
	char			*args[cfiles_count + 10], *libname;

	orbit_vasprintf(&libname, "%s/%s.so", rootdir, appl);

	idx = 0;
	args[idx++] = "gcc";

#if defined(__MACH__)
	args[idx++] = "-dynamiclib";
	args[idx++] = "-undefined";
	args[idx++] = "suppress";
	args[idx++] = "-flat_namespace";
#else
	args[idx++] = "-shared";
#endif

	TAILQ_FOREACH(cf, &source_files, list)
		args[idx++] = cf->opath;

	args[idx++] = "-o";
	args[idx++] = libname;
	args[idx] = NULL;

	execvp("gcc", args);
}

static void
orbit_run_kore(void *arg)
{
	char		*args[4], *cpath;

	orbit_vasprintf(&cpath, "%s/conf/%s.conf", rootdir, appl);

	args[0] = "kore";
	args[1] = "-fnc";
	args[2] = cpath;
	args[3] = NULL;

	execvp("kore", args);
}

static void
orbit_spawn_proc(void (*cb)(void *), void *arg)
{
	pid_t		pid;
	int		status;

	pid = fork();
	switch (pid) {
	case -1:
		fatal("orbit_compile_cfile: fork() %s", errno_s);
		/* NOTREACHED */
	case 0:
		cb(arg);
		fatal("orbit_spawn_proc: %s", errno_s);
		/* NOTREACHED */
	default:
		break;
	}

	if (waitpid(pid, &status, 0) == -1)
		fatal("couldn't wait for child %d", pid);

	if (WEXITSTATUS(status) || WTERMSIG(status) || WCOREDUMP(status))
		fatal("subprocess trouble, check output");
}

static void *
orbit_malloc(size_t len)
{
	void		*ptr;

	if ((ptr = malloc(len)) == NULL)
		fatal("orbit_malloc: %s", errno_s);

	return (ptr);
}

static int
orbit_vasprintf(char **out, const char *fmt, ...)
{
	int		l;
	va_list		args;

	va_start(args, fmt);
	l = vasprintf(out, fmt, args);
	va_end(args);

	if (l == -1)
		fatal("orbit_vasprintf");

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
		printf("orbit %s: %s\n", command->name, buf);
	else
		printf("orbit: %s\n", buf);
	exit(1);
}
