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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kore.h"

#if defined(OpenBSD) || defined(__FreeBSD_version)
#define PRI_TIME_T		"d"
#endif

#if defined(linux)
#if defined(__x86_64__)
#define PRI_TIME_T		PRIu64
#else
#define PRI_TIME_T		"ld"
#endif
#endif

#if defined(__MACH__)
#define PRI_TIME_T		"ld"
#endif

struct cmd {
	const char		*name;
	const char		*descr;
	void			(*cb)(int, char **);
};

struct filegen {
	void			(*cb)(void);
};

struct cfile {
	char			*name;
	char			*fpath;
	char			*opath;
	int			is_static;
	TAILQ_ENTRY(cfile)	list;
};

TAILQ_HEAD(cfile_list, cfile);

static void		cli_fatal(const char *, ...);

static void		cli_file_close(int);
static void		cli_run_kore(void *);
static void		cli_generate_certs(void);
static void		cli_link_library(void *);
static void		cli_compile_cfile(void *);
static void		cli_mkdir(const char *, int);
static int		cli_dir_exists(const char *);
static void		cli_cleanup_files(const char *);
static void		cli_file_writef(int, const char *, ...);
static void		cli_file_open(const char *, int, int *);
static void		cli_build_static(char *, struct dirent *);
static void		cli_file_write(int, const void *, size_t);
static int		cli_vasprintf(char **, const char *, ...);
static void		cli_spawn_proc(void (*cb)(void *), void *);
static void		cli_register_cfile(char *, struct dirent *);
static void		cli_file_create(const char *, const char *, size_t);
static void		cli_find_files(const char *,
			    void (*cb)(char *, struct dirent *));

static void		cli_run(int, char **);
static void		cli_help(int, char **);
static void		cli_build(int, char **);
static void		cli_create(int, char **);

static void		file_create_src(void);
static void		file_create_config(void);
static void		file_create_gitignore(void);

static struct cmd cmds[] = {
	{ "help",	"This help text",			cli_help },
	{ "run",	"Run an application (-fn implied)",	cli_run },
	{ "build",	"Build an application",			cli_build },
	{ "create",	"Create a new application skeleton",	cli_create },
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
#if !defined(KORE_BENCHMARK)
	"cert",
#endif
	"conf",
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
#if !defined(KORE_BENCHMARK)
	"\tcertfile\tcert/server.crt\n"
	"\tcertkey\t\tcert/server.key\n"
#endif
	"\tstatic\t/\tpage\n"
	"}\n";

static const char *gitignore_data = "*.o\n.objs\n%s.so\nstatic.h\ncert\n";

static int			s_fd = -1;
static char			*appl = NULL;
static char			*rootdir = NULL;
static char			*compiler = "gcc";
static struct cfile_list	source_files;
static int			cfiles_count;
static struct cmd		*command = NULL;

void
kore_cli_usage(int local)
{
	int		i;

	if (local)
		fprintf(stderr, "Usage: kore [command]\n");

	fprintf(stderr, "\nAvailable commands:\n");
	for (i = 0; cmds[i].name != NULL; i++)
		printf("\t%s\t%s\n", cmds[i].name, cmds[i].descr);

	fprintf(stderr, "\nThe commands mostly exist for your convinience\n");
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
	for (i = 0; gen_dirs[i] != NULL; i++) {
		(void)cli_vasprintf(&fpath, "%s/%s", appl, gen_dirs[i]);
		cli_mkdir(fpath, 0755);
		free(fpath);
	}

	for (i = 0; gen_files[i].cb != NULL; i++)
		gen_files[i].cb();

	rootdir = appl;
	cli_generate_certs();

	printf("%s created succesfully!\n", appl);

#if !defined(KORE_BENCHMARK)
	printf("note: do not use the generated certificates for production\n");
#endif
}

static void
cli_build(int argc, char **argv)
{
	struct cfile	*cf;
	char		*static_path, *p, *obj_path;
	char		pwd[PATH_MAX], *src_path, *static_header;

	if (argc == 0) {
		if (getcwd(pwd, sizeof(pwd)) == NULL)
			cli_fatal("could not get cwd: %s", errno_s);

		rootdir = ".";
		appl = basename(pwd);
	} else {
		appl = argv[0];
		rootdir = appl;
	}

	if ((p = getenv("KORE_COMPILER")) != NULL)
		compiler = p;

	cfiles_count = 0;
	TAILQ_INIT(&source_files);

	(void)cli_vasprintf(&obj_path, "%s/.objs", rootdir);
	if (!cli_dir_exists(obj_path))
		cli_mkdir(obj_path, 0755);

	(void)cli_vasprintf(&src_path, "%s/src", rootdir);
	(void)cli_vasprintf(&static_path, "%s/static", rootdir);
	(void)cli_vasprintf(&static_header, "%s/src/static.h", rootdir);
	if (!cli_dir_exists(src_path))
		cli_fatal("%s doesn't appear to be an app", appl);

	(void)unlink(static_header);

	/* Generate the static files. */
	if (cli_dir_exists(static_path)) {
		cli_file_open(static_header,
		    O_CREAT | O_TRUNC | O_WRONLY, &s_fd);
		cli_find_files(static_path, cli_build_static);
		cli_file_close(s_fd);
	}

	free(static_path);

	/* Build all source files. */
	cli_find_files(src_path, cli_register_cfile);
	free(src_path);

	TAILQ_FOREACH(cf, &source_files, list) {
		printf("compiling %s\n", cf->name);
		cli_spawn_proc(cli_compile_cfile, cf);
	}

	(void)unlink(static_header);
	free(static_header);

	cli_spawn_proc(cli_link_library, NULL);
	cli_cleanup_files(obj_path);
	free(obj_path);

	printf("%s built succesfully!\n", appl);
}

static void
cli_run(int argc, char **argv)
{
	cli_build(argc, argv);

	if (chdir(rootdir) == -1)
		cli_fatal("couldn't change directory to %s", rootdir);

	/*
	 * We are exec()'ing kore again, while we could technically set
	 * the right cli options manually and just continue running.
	 */
	cli_run_kore(NULL);
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
	l = cli_vasprintf(&data, config_data, appl);
	cli_file_create(name, data, l);

	free(name);
	free(data);
}

static void
file_create_gitignore(void)
{
	int		l;
	char		*data;

	l = cli_vasprintf(&data, gitignore_data, appl);
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
	if ((*fd = open(fpath, flags, 0755)) == -1)
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

	(void)cli_vasprintf(&fpath, "%s/%s", appl, name);

	cli_file_open(fpath, O_CREAT | O_TRUNC | O_WRONLY, &fd);
	cli_file_write(fd, data, len);
	cli_file_close(fd);

	printf("created %s\n", fpath);
	free(fpath);
}

static void
cli_build_static(char *fpath, struct dirent *dp)
{
	struct stat		st;
	u_int8_t		*d;
	struct cfile		*cf;
	off_t			off;
	void			*base;
	int			in, out;
	char			*cpath, *ext;

	/* Grab the extension as we're using it in the symbol name. */
	if ((ext = strrchr(dp->d_name, '.')) == NULL)
		cli_fatal("couldn't find ext in %s", dp->d_name);

	/* Open the file we're convering. */
	cli_file_open(fpath, O_RDONLY, &in);

	/* Grab the inode info on it and mmap it. */
	if (fstat(in, &st) == -1)
		cli_fatal("stat: %s %s", fpath, errno_s);
	if ((base = mmap(NULL, st.st_size,
	    PROT_READ, MAP_PRIVATE, in, 0)) == MAP_FAILED)
		cli_fatal("mmap: %s %s", fpath, errno_s);

	/* Create the c file where we will write too. */
	(void)cli_vasprintf(&cpath, "%s/.objs/%s.c", rootdir, dp->d_name);
	cli_file_open(cpath, O_CREAT | O_TRUNC | O_WRONLY, &out);

	/* No longer need dp->d_name so cut off the extension. */
	printf("converting %s\n", dp->d_name);
	*(ext)++ = '\0';

	/* Start generating the file. */
	cli_file_writef(out, "/* Auto generated */\n");
	cli_file_writef(out, "#include <sys/param.h>\n\n");
	cli_file_writef(out, "u_int8_t static_%s_%s[] = {\n", dp->d_name, ext);

	/* Copy all data into a buf and write it out afterwards. */
	d = base;
	for (off = 0; off < st.st_size; off++)
		cli_file_writef(out, "0x%02x,", *d++);

	/* Add the meta data. */
	cli_file_writef(out, "};\n\n");
	cli_file_writef(out, "u_int32_t static_len_%s_%s = %" PRIu32 ";\n",
	    dp->d_name, ext, (u_int32_t)st.st_size);
	cli_file_writef(out, "time_t static_mtime_%s_%s = %" PRI_TIME_T ";\n",
	    dp->d_name, ext, st.st_mtime);

	/* Write the file symbols into static.h so they can be used. */
	cli_file_writef(s_fd, "extern u_int8_t static_%s_%s[];\n",
	    dp->d_name, ext);
	cli_file_writef(s_fd, "extern u_int32_t static_len_%s_%s;\n",
	    dp->d_name, ext);
	cli_file_writef(s_fd, "extern time_t static_mtime_%s_%s;\n",
	    dp->d_name, ext);

	/* Cleanup static file source. */
	if (munmap(base, st.st_size) == -1)
		cli_fatal("munmap: %s %s", fpath, errno_s);

	/* Cleanup fds */
	cli_file_close(in);
	cli_file_close(out);

	/* Restore the original dp->d_name */
	*--ext = '.';

	/* Register the .c file now (cpath is free'd later). */
	cfiles_count++;
	cf = kore_malloc(sizeof(*cf));
	cf->is_static = 1;
	cf->fpath = cpath;
	cf->name = kore_strdup(dp->d_name);

	(void)cli_vasprintf(&(cf->opath), "%s/.objs/%s.o", rootdir, dp->d_name);
	TAILQ_INSERT_TAIL(&source_files, cf, list);
}

static void
cli_register_cfile(char *fpath, struct dirent *dp)
{
	struct cfile		*cf;
	char			*ext;

	if ((ext = strrchr(fpath, '.')) == NULL || strcmp(ext, ".c"))
		return;

	cfiles_count++;
	cf = kore_malloc(sizeof(*cf));
	cf->is_static = 0;
	cf->fpath = fpath;
	cf->name = kore_strdup(dp->d_name);

	(void)cli_vasprintf(&(cf->opath), "%s/.objs/%s.o", rootdir, dp->d_name);
	TAILQ_INSERT_TAIL(&source_files, cf, list);
}

static void
cli_find_files(const char *path, void (*cb)(char *, struct dirent *))
{
	DIR			*d;
	struct dirent		*dp;
	char			*fpath;

	if ((d = opendir(path)) == NULL)
		cli_fatal("cli_find_files: opendir(%s): %s", path, errno_s);

	while ((dp = readdir(d)) != NULL) {
		if (!strcmp(dp->d_name, ".") ||
		    !strcmp(dp->d_name, ".."))
			continue;

		(void)cli_vasprintf(&fpath, "%s/%s", path, dp->d_name);

		if (dp->d_type == DT_DIR) {
			cli_find_files(fpath, cb);
			free(fpath);
		} else {
			cb(fpath, dp);
		}
	}
}

static void
cli_generate_certs(void)
{
#if !defined(KORE_BENCHMARK)
	BIGNUM			*e;
	FILE			*fp;
	X509_NAME		*name;
	EVP_PKEY		*pkey;
	X509			*x509;
	RSA			*kpair;
	char			*fpath;

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

	/* Set serial number to 0. */
	if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), 0))
		cli_fatal("ASN1_INTEGER_set(): %s", ssl_errno_s);

	/* Not before and not after dates. */
	if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
		cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);
	if (!X509_gmtime_adj(X509_get_notAfter(x509), (long)60 *60 * 24 * 3000))
		cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);

	/* Attach the pkey to the certificate. */
	if (!X509_set_pubkey(x509, pkey))
		cli_fatal("X509_set_pubkey(): %s", ssl_errno_s);

	/* Set certificate information. */
	if ((name = X509_get_subject_name(x509)) == NULL)
		cli_fatal("X509_get_subject_name(): %s", ssl_errno_s);

	if (!X509_NAME_add_entry_by_txt(name, "C",
	    MBSTRING_ASC, (const unsigned char *)"SE", -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): C %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "O",
	    MBSTRING_ASC, (const unsigned char *)"kore autogen", -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): O %s", ssl_errno_s);
	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0))
		cli_fatal("X509_NAME_add_entry_by_txt(): CN %s", ssl_errno_s);

	if (!X509_set_issuer_name(x509, name))
		cli_fatal("X509_set_issuer_name(): %s", ssl_errno_s);

	if (!X509_sign(x509, pkey, EVP_sha1()))
		cli_fatal("X509_sign(): %s", ssl_errno_s);

	(void)cli_vasprintf(&fpath, "%s/cert/server.key", rootdir);
	if ((fp = fopen(fpath, "w+")) == NULL)
		cli_fatal("fopen(%s): %s", fpath, errno_s);
	free(fpath);

	if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
		cli_fatal("PEM_write_PrivateKey(): %s", ssl_errno_s);
	fclose(fp);

	(void)cli_vasprintf(&fpath, "%s/cert/server.crt", rootdir);
	if ((fp = fopen(fpath, "w+")) == NULL)
		cli_fatal("fopen(%s): %s", fpath, errno_s);
	free(fpath);

	if (!PEM_write_X509(fp, x509))
		cli_fatal("fopen(%s): %s", fpath, errno_s);

	EVP_PKEY_free(pkey);
	X509_free(x509);
#endif
}

static void
cli_compile_cfile(void *arg)
{
	struct cfile	*cf = arg;
	char		*args[18], *ipath;

	(void)cli_vasprintf(&ipath, "-I%s/src", appl);

	/*
	 * These compiler options should be settable
	 * somehow by the user if they so choose.
	 */
	args[0] = compiler;
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

	execvp(compiler, args);
}

static void
cli_link_library(void *arg)
{
	int			idx;
	struct cfile		*cf;
	char			*args[cfiles_count + 10], *libname;

	(void)cli_vasprintf(&libname, "%s/%s.so", rootdir, appl);

	idx = 0;
	args[idx++] = compiler;

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

	execvp(compiler, args);
}

static void
cli_run_kore(void *arg)
{
	char		*args[4], *cpath;

	(void)cli_vasprintf(&cpath, "conf/%s.conf", appl);

	args[0] = "kore";
	args[1] = "-fnc";
	args[2] = cpath;
	args[3] = NULL;

	execvp("kore", args);
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
	struct cfile		*cf;

	TAILQ_FOREACH(cf, &source_files, list) {
		if (unlink(cf->opath) == -1 && errno != ENOENT)
			printf("couldnt unlink %s\n", cf->opath);

		if (cf->is_static &&
		    (unlink(cf->fpath) == -1) && errno != ENOENT)
			printf("couldnt unlink %s\n", cf->fpath);
	}

	if (rmdir(spath) == -1)
		printf("couldn't rmdir %s\n", spath);
}

static void
cli_fatal(const char *fmt, ...)
{
	int		l;
	va_list		args;
	char		buf[2048], spath[MAXPATHLEN];

	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (rootdir != NULL) {
		l = snprintf(spath, sizeof(spath), "%s/.objs", rootdir);
		if (l == -1 || (size_t)l >= sizeof(spath)) {
			printf("couldn't create spath for cleanup: %s\n",
			    errno_s);
		} else {
			cli_cleanup_files(spath);
		}
	}

	if (command != NULL)
		printf("kore %s: %s\n", command->name, buf);
	else
		printf("kore: %s\n", buf);
	exit(1);
}
