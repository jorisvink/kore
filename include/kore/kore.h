/*
 * Copyright (c) 2013-2020 Joris Vink <joris@coders.se>
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

#ifndef __H_KORE_H
#define __H_KORE_H

#if defined(__APPLE__)
#define daemon portability_is_king
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__APPLE__)
#undef daemon
extern int daemon(int, int);
#define st_mtim		st_mtimespec
#endif

#if !defined(KORE_NO_SENDFILE)
#if defined(__MACH__) || defined(__FreeBSD_version) || defined(__linux__)
#define KORE_USE_PLATFORM_SENDFILE	1
#endif
#endif

/*
 * Figure out what type of OpenSSL API we are dealing with.
 */
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x3000000fL
#define KORE_OPENSSL_NEWER_API		1
#endif
#else
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define KORE_OPENSSL_NEWER_API		1
#endif
#endif

#if defined(__OpenBSD__)
#define KORE_USE_PLATFORM_PLEDGE	1
#endif

#define KORE_RSAKEY_BITS	4096

#define KORE_RESULT_ERROR	0
#define KORE_RESULT_OK		1
#define KORE_RESULT_RETRY	2

#define KORE_TLS_VERSION_1_3	0
#define KORE_TLS_VERSION_1_2	1
#define KORE_TLS_VERSION_BOTH	2

#define KORE_BASE64_RAW		0x0001

#define KORE_WAIT_INFINITE	(u_int64_t)-1
#define KORE_RESEED_TIME	(1800 * 1000)

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define KORE_DOMAINNAME_LEN		255
#define KORE_PIDFILE_DEFAULT		"kore.pid"
#define KORE_DEFAULT_CIPHER_LIST	"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!kRSA:!kDSA"

#define KORE_CONFIG_HOOK	"kore_parent_configure"
#define KORE_TEARDOWN_HOOK	"kore_parent_teardown"
#define KORE_DAEMONIZED_HOOK	"kore_parent_daemonized"

#if defined(KORE_DEBUG)
#define kore_debug(...)		\
	if (kore_debug)		\
		kore_debug_internal(__FILE__, __LINE__, __VA_ARGS__)
#else
#define kore_debug(...)
#endif

#define NETBUF_RECV			0
#define NETBUF_SEND			1
#define NETBUF_SEND_PAYLOAD_MAX		8192
#define SENDFILE_PAYLOAD_MAX		(1024 * 1024 * 10)

#define NETBUF_LAST_CHAIN		0
#define NETBUF_BEFORE_CHAIN		1

#define NETBUF_CALL_CB_ALWAYS	0x01
#define NETBUF_FORCE_REMOVE	0x02
#define NETBUF_MUST_RESEND	0x04
#define NETBUF_IS_STREAM	0x10
#define NETBUF_IS_FILEREF	0x20

#define KORE_X509_COMMON_NAME_ONLY	0x0001

#define KORE_PEM_CERT_CHAIN	1
#define KORE_DER_CERT_DATA	2

/* XXX hackish. */
#if !defined(KORE_NO_HTTP)
struct http_request;
struct http_redirect;
#endif

#define KORE_FILEREF_SOFT_REMOVED	0x1000

struct kore_fileref {
	int				cnt;
	int				flags;
	int				ontls;
	off_t				size;
	char				*path;
	u_int64_t			mtime;
	time_t				mtime_sec;
	u_int64_t			expiration;
	void				*base;
	int				fd;
	TAILQ_ENTRY(kore_fileref)	list;
};

struct netbuf {
	u_int8_t		*buf;
	size_t			s_off;
	size_t			b_len;
	size_t			m_len;
	u_int8_t		type;
	u_int8_t		flags;

	struct kore_fileref	*file_ref;
	off_t			fd_off;
	off_t			fd_len;

	struct connection	*owner;
	void			*extra;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_head, netbuf);

#define KORE_TYPE_LISTENER	1
#define KORE_TYPE_CONNECTION	2
#define KORE_TYPE_PGSQL_CONN	3
#define KORE_TYPE_TASK		4
#define KORE_TYPE_PYSOCKET	5
#define KORE_TYPE_CURL_HANDLE	6

#define CONN_STATE_UNKNOWN		0
#define CONN_STATE_TLS_SHAKE		1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_DISCONNECTING	3

#define CONN_PROTO_UNKNOWN	0
#define CONN_PROTO_HTTP		1
#define CONN_PROTO_WEBSOCKET	2
#define CONN_PROTO_MSG		3
#define CONN_PROTO_ACME_ALPN	200

#define KORE_EVENT_READ		0x01
#define KORE_EVENT_WRITE	0x02
#define KORE_EVENT_ERROR	0x04

#define CONN_IDLE_TIMER_ACT	0x0001
#define CONN_CLOSE_EMPTY	0x0002
#define CONN_WS_CLOSE_SENT	0x0004
#define CONN_IS_BUSY		0x0008
#define CONN_LOG_TLS_FAILURE	0x0020
#define CONN_TLS_ALPN_ACME_SEEN	0x0040
#define CONN_TLS_SNI_SEEN	0x0080

#define KORE_IDLE_TIMER_MAX	5000

#define WEBSOCKET_OP_CONT	0x00
#define WEBSOCKET_OP_TEXT	0x01
#define WEBSOCKET_OP_BINARY	0x02
#define WEBSOCKET_OP_CLOSE	0x08
#define WEBSOCKET_OP_PING	0x09
#define WEBSOCKET_OP_PONG	0x0a

#define WEBSOCKET_BROADCAST_LOCAL	1
#define WEBSOCKET_BROADCAST_GLOBAL	2

#define KORE_TIMER_ONESHOT	0x01
#define KORE_TIMER_FLAGS	(KORE_TIMER_ONESHOT)

#define KORE_CONNECTION_PRUNE_DISCONNECT	0
#define KORE_CONNECTION_PRUNE_ALL		1

struct kore_event {
	int		type;
	int		flags;
	void		(*handle)(void *, int);
} __attribute__((packed));

struct connection {
	struct kore_event	evt;
	int			fd;
	u_int8_t		state;
	u_int8_t		proto;
	struct listener		*owner;
	X509			*cert;
	SSL			*ssl;
	char			*tls_sni;
	int			tls_reneg;
	u_int16_t		flags;
	void			*hdlr_extra;

	int			(*handle)(struct connection *);
	void			(*disconnect)(struct connection *);
	int			(*read)(struct connection *, size_t *);
	int			(*write)(struct connection *, size_t, size_t *);

	int			family;
	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
		struct sockaddr_un	sun;
	} addr;

	struct {
		u_int64_t	length;
		u_int64_t	start;
	} idle_timer;

	struct netbuf_head	send_queue;
	struct netbuf		*snb;
	struct netbuf		*rnb;

#if !defined(KORE_NO_HTTP)
	u_int64_t			http_start;
	u_int64_t			http_timeout;
	struct kore_runtime_call	*ws_connect;
	struct kore_runtime_call	*ws_message;
	struct kore_runtime_call	*ws_disconnect;
	TAILQ_HEAD(, http_request)	http_requests;
#endif

	TAILQ_ENTRY(connection)	list;
};

TAILQ_HEAD(connection_list, connection);
extern struct connection_list	connections;
extern struct connection_list	disconnected;

#define KORE_RUNTIME_NATIVE	0
#define KORE_RUNTIME_PYTHON	1

struct kore_runtime {
	int	type;
#if !defined(KORE_NO_HTTP)
	int	(*http_request)(void *, struct http_request *);
	int	(*validator)(void *, struct http_request *, const void *);
	void	(*wsconnect)(void *, struct connection *);
	void	(*wsdisconnect)(void *, struct connection *);
	void	(*wsmessage)(void *, struct connection *,
		    u_int8_t, const void *, size_t);
#endif
	void	(*execute)(void *);
	int	(*onload)(void *, int);
	void	(*connect)(void *, struct connection *);
	void	(*configure)(void *, int, char **);
};

struct kore_runtime_call {
	void			*addr;
	struct kore_runtime	*runtime;
};

struct kore_domain {
	u_int16_t				id;
	int					logerr;
	u_int64_t				logwarn;
	int					accesslog;

	char					*domain;
	struct kore_buf				*logbuf;
	struct kore_server			*server;

#if defined(KORE_USE_ACME)
	int					acme;
	int					acme_challenge;
	void					*acme_cert;
	size_t					acme_cert_len;
#endif
	char					*cafile;
	char					*crlfile;
	char					*certfile;
	char					*certkey;
	SSL_CTX					*ssl_ctx;
	int					x509_verify_depth;
#if !defined(KORE_NO_HTTP)
	TAILQ_HEAD(, kore_module_handle)	handlers;
	TAILQ_HEAD(, http_redirect)		redirects;
#endif
	TAILQ_ENTRY(kore_domain)		list;
};

TAILQ_HEAD(kore_domain_h, kore_domain);

extern struct kore_runtime	kore_native_runtime;

struct listener {
	struct kore_event		evt;
	int				fd;
	int				family;
	char				*port;
	char				*host;
	struct kore_server		*server;
	struct kore_runtime_call	*connect;

	LIST_ENTRY(listener)		list;
};

struct kore_server {
	int				tls;
	char				*name;
	struct kore_domain_h		domains;
	LIST_HEAD(, listener)		listeners;
	LIST_ENTRY(kore_server)		list;
};

LIST_HEAD(kore_server_list, kore_server);

#if !defined(KORE_NO_HTTP)

#define KORE_PARAMS_QUERY_STRING	0x0001

struct kore_handler_params {
	char			*name;
	int			flags;
	u_int8_t		method;
	struct kore_validator	*validator;

	TAILQ_ENTRY(kore_handler_params)	list;
};

#define KORE_AUTH_TYPE_COOKIE		1
#define KORE_AUTH_TYPE_HEADER		2
#define KORE_AUTH_TYPE_REQUEST		3

struct kore_auth {
	u_int8_t		type;
	char			*name;
	char			*value;
	char			*redirect;
	struct kore_validator	*validator;

	TAILQ_ENTRY(kore_auth)	list;
};

#define HANDLER_TYPE_STATIC	1
#define HANDLER_TYPE_DYNAMIC	2

#endif /* !KORE_NO_HTTP */

#define KORE_MODULE_LOAD	1
#define KORE_MODULE_UNLOAD	2

#define KORE_MODULE_NATIVE	0
#define KORE_MODULE_PYTHON	1

struct kore_module;

struct kore_module_functions {
	void			(*free)(struct kore_module *);
	void			(*reload)(struct kore_module *);
	int			(*callback)(struct kore_module *, int);
	void			(*load)(struct kore_module *);
	void			*(*getsym)(struct kore_module *, const char *);
};

struct kore_module {
	void				*handle;
	char				*path;
	char				*onload;
	int				type;
	struct kore_runtime_call	*ocb;

	struct kore_module_functions	*fun;
	struct kore_runtime		*runtime;

	TAILQ_ENTRY(kore_module)	list;
};

#if !defined(KORE_NO_HTTP)

struct kore_module_handle {
	char					*path;
	char					*func;
	int					type;
	int					errors;
	regex_t					rctx;
	struct kore_domain			*dom;
	struct kore_runtime_call		*rcall;
	struct kore_auth			*auth;
	int					methods;
	TAILQ_HEAD(, kore_handler_params)	params;
	TAILQ_ENTRY(kore_module_handle)		list;
};
#endif

/*
 * The workers get a 128KB log buffer per worker, and parent will fetch their
 * logs when it reached at least 75% of that or if its been > 1 second since
 * it was last synced.
 */
#define KORE_ACCESSLOG_BUFLEN		131072U
#define KORE_ACCESSLOG_SYNC		98304U

struct kore_alog_header {
	u_int16_t		domain;
	u_int16_t		loglen;
} __attribute__((packed));

struct kore_worker {
	u_int16_t			id;
	u_int16_t			cpu;
	int				running;
#if defined(__linux__)
	int				tracing;
#endif
	pid_t				pid;
	int				pipe[2];
	struct connection		*msg[2];
	u_int8_t			has_lock;
	int				restarted;
	u_int64_t			time_locked;
	struct kore_module_handle	*active_hdlr;

	/* Used by the workers to store accesslogs. */
	struct {
		int			lock;
		size_t			offset;
		char			buf[KORE_ACCESSLOG_BUFLEN];
	} lb;
};

#if !defined(KORE_NO_HTTP)

#define KORE_VALIDATOR_TYPE_REGEX	1
#define KORE_VALIDATOR_TYPE_FUNCTION	2

struct kore_validator {
	u_int8_t			type;
	char				*name;
	char				*arg;
	regex_t				rctx;
	struct kore_runtime_call	*rcall;

	TAILQ_ENTRY(kore_validator)	list;
};
#endif /* !KORE_NO_HTTP */

#define KORE_BUF_OWNER_API	0x0001

struct kore_buf {
	u_int8_t		*data;
	int			flags;
	size_t			length;
	size_t			offset;
};

#define KORE_JSON_TYPE_OBJECT		0x0001
#define KORE_JSON_TYPE_ARRAY		0x0002
#define KORE_JSON_TYPE_STRING		0x0004
#define KORE_JSON_TYPE_NUMBER		0x0008
#define KORE_JSON_TYPE_LITERAL		0x0010
#define KORE_JSON_TYPE_INTEGER		0x0020
#define KORE_JSON_TYPE_INTEGER_U64	0x0040

#define KORE_JSON_FALSE			0
#define KORE_JSON_TRUE			1
#define KORE_JSON_NULL			2

#define KORE_JSON_DEPTH_MAX		10

#define KORE_JSON_ERR_NONE		0
#define KORE_JSON_ERR_INVALID_OBJECT	1
#define KORE_JSON_ERR_INVALID_ARRAY	2
#define KORE_JSON_ERR_INVALID_STRING	3
#define KORE_JSON_ERR_INVALID_NUMBER	4
#define KORE_JSON_ERR_INVALID_LITERAL	5
#define KORE_JSON_ERR_DEPTH		6
#define KORE_JSON_ERR_EOF		7
#define KORE_JSON_ERR_INVALID_JSON	8
#define KORE_JSON_ERR_INVALID_SEARCH	9
#define KORE_JSON_ERR_NOT_FOUND		10
#define KORE_JSON_ERR_TYPE_MISMATCH	11
#define KORE_JSON_ERR_LAST		KORE_JSON_ERR_TYPE_MISMATCH

#define kore_json_find_object(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_OBJECT)

#define kore_json_find_array(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_ARRAY)

#define kore_json_find_string(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_STRING)

#define kore_json_find_number(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_NUMBER)

#define kore_json_find_integer(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_INTEGER)

#define kore_json_find_integer_u64(j, p)	\
    kore_json_find(j, p, KORE_JSON_TYPE_INTEGER_U64)

#define kore_json_find_literal(j, p)		\
    kore_json_find(j, p, KORE_JSON_TYPE_LITERAL)

#define kore_json_create_object(o, n)				\
    kore_json_create_item(o, n, KORE_JSON_TYPE_OBJECT)

#define kore_json_create_array(o, n)				\
    kore_json_create_item(o, n, KORE_JSON_TYPE_ARRAY)

#define kore_json_create_string(o, n, v)			\
    kore_json_create_item(o, n, KORE_JSON_TYPE_STRING, v)

#define kore_json_create_number(o, n, v)			\
    kore_json_create_item(o, n, KORE_JSON_TYPE_NUMBER, v)

#define kore_json_create_integer(o, n, v)			\
    kore_json_create_item(o, n, KORE_JSON_TYPE_INTEGER, v)

#define kore_json_create_integer_u64(o, n, v)			\
    kore_json_create_item(o, n, KORE_JSON_TYPE_INTEGER_U64, v)

#define kore_json_create_literal(o, n, v)			\
    kore_json_create_item(o, n, KORE_JSON_TYPE_LITERAL, v)

struct kore_json {
	const u_int8_t			*data;
	int				depth;
	int				error;
	size_t				length;
	size_t				offset;

	struct kore_buf			tmpbuf;
	struct kore_json_item		*root;
};

struct kore_json_item {
	u_int32_t			type;
	char				*name;
	struct kore_json_item		*parent;

	union {
		TAILQ_HEAD(, kore_json_item)	items;
		char				*string;
		double				number;
		int				literal;
		int64_t				s64;
		u_int64_t			u64;
	} data;

	int				(*parse)(struct kore_json *,
					    struct kore_json_item *);

	TAILQ_ENTRY(kore_json_item)	list;
};

struct kore_pool_region {
	void				*start;
	size_t				length;
	LIST_ENTRY(kore_pool_region)	list;
};

struct kore_pool_entry {
	u_int8_t			state;
	struct kore_pool_region		*region;
	LIST_ENTRY(kore_pool_entry)	list;
};

struct kore_pool {
	size_t			elen;
	size_t			slen;
	size_t			elms;
	size_t			inuse;
	size_t			growth;
	volatile int		lock;
	char			*name;

	LIST_HEAD(, kore_pool_region)	regions;
	LIST_HEAD(, kore_pool_entry)	freelist;
};

struct kore_timer {
	u_int64_t	nextrun;
	u_int64_t	interval;
	int		flags;
	void		*arg;
	void		(*cb)(void *, u_int64_t);

	TAILQ_ENTRY(kore_timer)	list;
};

/*
 * Keymgr process is worker index 0, but id 2000.
 * Acme process is worker index 1, but id 2001.
 */
#define KORE_WORKER_KEYMGR_IDX		0
#define KORE_WORKER_ACME_IDX		1
#define KORE_WORKER_BASE		2
#define KORE_WORKER_KEYMGR		2000
#define KORE_WORKER_ACME		2001
#define KORE_WORKER_MAX			UCHAR_MAX

#define KORE_WORKER_POLICY_RESTART	1
#define KORE_WORKER_POLICY_TERMINATE	2

/* Reserved message ids, registered on workers. */
#define KORE_MSG_WEBSOCKET		1
#define KORE_MSG_KEYMGR_REQ		2
#define KORE_MSG_KEYMGR_RESP		3
#define KORE_MSG_SHUTDOWN		4
#define KORE_MSG_ENTROPY_REQ		5
#define KORE_MSG_ENTROPY_RESP		6
#define KORE_MSG_CERTIFICATE		7
#define KORE_MSG_CERTIFICATE_REQ	8
#define KORE_MSG_CRL			9
#define KORE_MSG_ACCEPT_AVAILABLE	10
#define KORE_PYTHON_SEND_OBJ		11
#define KORE_MSG_ACME_BASE		100

/* messages for applications should start at 201. */
#define KORE_MSG_APP_BASE		200

/* Predefined message targets. */
#define KORE_MSG_PARENT		1000
#define KORE_MSG_WORKER_ALL	1001

struct kore_msg {
	u_int8_t	id;
	u_int16_t	src;
	u_int16_t	dst;
	size_t		length;
};

struct kore_keyreq {
	int		padding;
	char		domain[KORE_DOMAINNAME_LEN + 1];
	size_t		data_len;
	u_int8_t	data[];
};

struct kore_x509_msg {
	char		domain[KORE_DOMAINNAME_LEN + 1];
	size_t		data_len;
	u_int8_t	data[];
};

#if !defined(KORE_SINGLE_BINARY)
extern char	*config_file;
#endif

extern pid_t	kore_pid;
extern int	kore_quiet;
extern int	kore_debug;
extern int	skip_chroot;
extern int	skip_runas;
extern int	kore_foreground;

extern char	*kore_pidfile;
extern char	*kore_root_path;
extern char	*kore_runas_user;
extern char	*kore_tls_cipher_list;

extern volatile sig_atomic_t	sig_recv;

extern int	tls_version;
extern DH	*tls_dhparam;
extern char	*rand_file;
extern int	keymgr_active;
extern char	*keymgr_runas_user;
extern char	*keymgr_root_path;
extern char	*acme_runas_user;
extern char	*acme_root_path;

extern u_int8_t			nlisteners;
extern u_int16_t		cpu_count;
extern u_int8_t			worker_count;
extern const char		*kore_version;
extern int			worker_policy;
extern u_int8_t			worker_set_affinity;
extern u_int32_t		worker_rlimit_nofiles;
extern u_int32_t		worker_max_connections;
extern u_int32_t		worker_active_connections;
extern u_int32_t		worker_accept_threshold;
extern u_int64_t		kore_websocket_maxframe;
extern u_int64_t		kore_websocket_timeout;
extern u_int32_t		kore_socket_backlog;

extern struct kore_worker	*worker;
extern struct kore_pool		nb_pool;
extern struct kore_domain	*primary_dom;
extern struct kore_server_list	kore_servers;

void		kore_signal(int);
void		kore_shutdown(void);
void		kore_signal_setup(void);
void		kore_proctitle(const char *);
void		kore_default_getopt(int, char **);

void		kore_worker_reap(void);
void		kore_worker_init(void);
void		kore_worker_make_busy(void);
void		kore_worker_shutdown(void);
void		kore_worker_dispatch_signal(int);
void		kore_worker_privdrop(const char *, const char *);
void		kore_worker_spawn(u_int16_t, u_int16_t, u_int16_t);
int		kore_worker_keymgr_response_verify(struct kore_msg *,
		    const void *, struct kore_domain **);

void	kore_worker_entry(struct kore_worker *) __attribute__((noreturn));

struct kore_worker	*kore_worker_data(u_int8_t);

void		kore_platform_init(void);
void		kore_platform_sandbox(void);
void		kore_platform_event_init(void);
void		kore_platform_event_cleanup(void);
void		kore_platform_disable_read(int);
void		kore_platform_disable_write(int);
void		kore_platform_enable_accept(void);
void		kore_platform_disable_accept(void);
void		kore_platform_event_wait(u_int64_t);
void		kore_platform_event_all(int, void *);
void		kore_platform_event_level_all(int, void *);
void		kore_platform_event_level_read(int, void *);
void		kore_platform_proctitle(const char *);
void		kore_platform_schedule_read(int, void *);
void		kore_platform_schedule_write(int, void *);
void		kore_platform_event_schedule(int, int, int, void *);
void		kore_platform_worker_setcpu(struct kore_worker *);

#if defined(KORE_USE_PLATFORM_SENDFILE)
int		kore_platform_sendfile(struct connection *, struct netbuf *);
#endif

#if defined(KORE_USE_PLATFORM_PLEDGE)
void		kore_platform_pledge(void);
void		kore_platform_add_pledge(const char *);
#endif

void		kore_accesslog_init(u_int16_t);
void		kore_accesslog_worker_init(void);
void		kore_accesslog_run(void *, u_int64_t);
void		kore_accesslog_gather(void *, u_int64_t, int);

#if !defined(KORE_NO_HTTP)
int		kore_auth_run(struct http_request *, struct kore_auth *);
int		kore_auth_cookie(struct http_request *, struct kore_auth *);
int		kore_auth_header(struct http_request *, struct kore_auth *);
int		kore_auth_request(struct http_request *, struct kore_auth *);
void		kore_auth_init(void);
int		kore_auth_new(const char *);
struct kore_auth	*kore_auth_lookup(const char *);
#endif

void		kore_timer_init(void);
void		kore_timer_run(u_int64_t);
u_int64_t	kore_timer_next_run(u_int64_t);
void		kore_timer_remove(struct kore_timer *);
struct kore_timer	*kore_timer_add(void (*cb)(void *, u_int64_t),
			    u_int64_t, void *, int);

void		kore_server_closeall(void);
void		kore_server_cleanup(void);
void		kore_server_free(struct kore_server *);
void		kore_server_finalize(struct kore_server *);

struct kore_server	*kore_server_create(const char *);
struct kore_server	*kore_server_lookup(const char *);

void		kore_listener_accept(void *, int);
struct listener	*kore_listener_lookup(const char *);
void		kore_listener_free(struct listener *);
struct listener	*kore_listener_create(struct kore_server *);
int		kore_listener_init(struct listener *, int, const char *);

int		kore_sockopt(int, int, int);
int		kore_server_bind_unix(struct kore_server *,
		    const char *, const char *);
int		kore_server_bind(struct kore_server *,
		    const char *, const char *, const char *);

int		kore_tls_sni_cb(SSL *, int *, void *);
void		kore_tls_info_callback(const SSL *, int, int);

void			kore_connection_init(void);
void			kore_connection_cleanup(void);
void			kore_connection_prune(int);
struct connection	*kore_connection_new(void *);
void			kore_connection_event(void *, int);
int			kore_connection_nonblock(int, int);
void			kore_connection_check_timeout(u_int64_t);
int			kore_connection_handle(struct connection *);
void			kore_connection_remove(struct connection *);
void			kore_connection_disconnect(struct connection *);
void			kore_connection_start_idletimer(struct connection *);
void			kore_connection_stop_idletimer(struct connection *);
void			kore_connection_check_idletimer(u_int64_t,
			    struct connection *);
int			kore_connection_accept(struct listener *,
			    struct connection **);

u_int64_t	kore_time_ms(void);
void		kore_log_init(void);

#if defined(KORE_USE_PYTHON)
int		kore_configure_setting(const char *, char *);
#endif

void		*kore_malloc(size_t);
void		kore_parse_config(void);
void		kore_parse_config_file(FILE *);
void		*kore_calloc(size_t, size_t);
void		*kore_realloc(void *, size_t);
void		kore_free(void *);
void		kore_mem_init(void);
void		kore_mem_cleanup(void);
void		kore_mem_untag(void *);
void		*kore_mem_lookup(u_int32_t);
void		kore_mem_tag(void *, u_int32_t);
void		*kore_malloc_tagged(size_t, u_int32_t);

void		*kore_pool_get(struct kore_pool *);
void		kore_pool_put(struct kore_pool *, void *);
void		kore_pool_init(struct kore_pool *, const char *,
		    size_t, size_t);
void		kore_pool_cleanup(struct kore_pool *);

char		*kore_time_to_date(time_t);
char		*kore_strdup(const char *);
time_t		kore_date_to_time(const char *);
void		kore_log(int, const char *, ...)
		    __attribute__((format (printf, 2, 3)));
u_int64_t	kore_strtonum64(const char *, int, int *);
size_t		kore_strlcpy(char *, const char *, const size_t);
void		kore_server_disconnect(struct connection *);
int		kore_split_string(char *, const char *, char **, size_t);
void		kore_strip_chars(char *, const char, char **);
int		kore_snprintf(char *, size_t, int *, const char *, ...);
long long	kore_strtonum(const char *, int, long long, long long, int *);
double		kore_strtodouble(const char *, long double, long double, int *);
int		kore_base64_encode(const void *, size_t, char **);
int		kore_base64_decode(const char *, u_int8_t **, size_t *);
int		kore_base64url_encode(const void *, size_t, char **, int);
int		kore_base64url_decode(const char *, u_int8_t **, size_t *, int);
void		*kore_mem_find(void *, size_t, const void *, size_t);
char		*kore_text_trim(char *, size_t);
char		*kore_read_line(FILE *, char *, size_t);

EVP_PKEY	*kore_rsakey_load(const char *);
EVP_PKEY	*kore_rsakey_generate(const char *);
int		kore_x509_subject_name(struct connection *, char **, int);

#if !defined(KORE_NO_HTTP)
void		kore_websocket_handshake(struct http_request *,
		    const char *, const char *, const char *);
int		kore_websocket_send_clean(struct netbuf *);
void		kore_websocket_send(struct connection *,
		    u_int8_t, const void *, size_t);
void		kore_websocket_broadcast(struct connection *,
		    u_int8_t, const void *, size_t, int);
#endif

void		kore_msg_init(void);
void		kore_msg_worker_init(void);
void		kore_msg_parent_init(void);
void		kore_msg_unregister(u_int8_t);
void		kore_msg_parent_add(struct kore_worker *);
void		kore_msg_parent_remove(struct kore_worker *);
void		kore_msg_send(u_int16_t, u_int8_t, const void *, size_t);
int		kore_msg_register(u_int8_t,
		    void (*cb)(struct kore_msg *, const void *));

#if !defined(KORE_NO_HTTP)
void		kore_filemap_init(void);
void		kore_filemap_resolve_paths(void);
int		kore_filemap_create(struct kore_domain *, const char *,
		    const char *);
extern char	*kore_filemap_ext;
extern char	*kore_filemap_index;
#endif

void			kore_fileref_init(void);
struct kore_fileref	*kore_fileref_get(const char *, int);
struct kore_fileref	*kore_fileref_create(struct kore_server *,
			    const char *, int, off_t, struct timespec *);
void			kore_fileref_release(struct kore_fileref *);

struct kore_domain	*kore_domain_new(const char *);

void		kore_domain_init(void);
void		kore_domain_cleanup(void);
void		kore_domain_free(struct kore_domain *);
void		kore_module_init(void);
void		kore_module_cleanup(void);
void		kore_module_reload(int);
void		kore_module_onload(void);
int		kore_module_loaded(void);
void		kore_domain_closelogs(void);
void		*kore_module_getsym(const char *, struct kore_runtime **);
void		kore_domain_load_crl(void);
void		kore_domain_keymgr_init(void);
void		kore_domain_callback(void (*cb)(struct kore_domain *));
int		kore_domain_attach(struct kore_domain *, struct kore_server *);
void		kore_domain_tlsinit(struct kore_domain *, int,
		    const void *, size_t);
void		kore_domain_crl_add(struct kore_domain *, const void *, size_t);
#if !defined(KORE_NO_HTTP)
int		kore_module_handler_new(struct kore_domain *, const char *,
		    const char *, const char *, int);
void		kore_module_handler_free(struct kore_module_handle *);
struct kore_module_handle	*kore_module_handler_find(struct http_request *,
				    struct kore_domain *);
#endif

struct kore_runtime_call	*kore_runtime_getcall(const char *);
struct kore_module		*kore_module_load(const char *,
				    const char *, int);

void	kore_runtime_execute(struct kore_runtime_call *);
int	kore_runtime_onload(struct kore_runtime_call *, int);
void	kore_runtime_configure(struct kore_runtime_call *, int, char **);
void	kore_runtime_connect(struct kore_runtime_call *, struct connection *);
#if !defined(KORE_NO_HTTP)
int	kore_runtime_http_request(struct kore_runtime_call *,
	    struct http_request *);
int	kore_runtime_validator(struct kore_runtime_call *,
	    struct http_request *, const void *);
void	kore_runtime_wsconnect(struct kore_runtime_call *, struct connection *);
void	kore_runtime_wsdisconnect(struct kore_runtime_call *,
	    struct connection *);
void	kore_runtime_wsmessage(struct kore_runtime_call *,
	    struct connection *, u_int8_t, const void *, size_t);
#endif

struct kore_domain	*kore_domain_byid(u_int16_t);
struct kore_domain	*kore_domain_lookup(struct kore_server *, const char *);

#if !defined(KORE_NO_HTTP)
void		kore_validator_init(void);
void		kore_validator_reload(void);
int		kore_validator_add(const char *, u_int8_t, const char *);
int		kore_validator_run(struct http_request *, const char *, char *);
int		kore_validator_check(struct http_request *,
		    struct kore_validator *, const void *);
struct kore_validator	*kore_validator_lookup(const char *);
#endif

void		fatal(const char *, ...) __attribute__((noreturn));
void		fatalx(const char *, ...) __attribute__((noreturn));

const char	*kore_worker_name(int);
void		kore_debug_internal(char *, int, const char *, ...);

u_int16_t	net_read16(u_int8_t *);
u_int32_t	net_read32(u_int8_t *);
u_int64_t	net_read64(u_int8_t *);
void		net_write16(u_int8_t *, u_int16_t);
void		net_write32(u_int8_t *, u_int32_t);
void		net_write64(u_int8_t *, u_int64_t);

void		net_init(void);
void		net_cleanup(void);
struct netbuf	*net_netbuf_get(void);
int		net_send(struct connection *);
int		net_send_flush(struct connection *);
int		net_recv_flush(struct connection *);
int		net_read(struct connection *, size_t *);
int		net_read_tls(struct connection *, size_t *);
int		net_write(struct connection *, size_t, size_t *);
int		net_write_tls(struct connection *, size_t, size_t *);
void		net_recv_reset(struct connection *, size_t,
		    int (*cb)(struct netbuf *));
void		net_remove_netbuf(struct connection *, struct netbuf *);
void		net_recv_queue(struct connection *, size_t, int,
		    int (*cb)(struct netbuf *));
void		net_recv_expand(struct connection *c, size_t,
		    int (*cb)(struct netbuf *));
void		net_send_queue(struct connection *, const void *, size_t);
void		net_send_stream(struct connection *, void *,
		    size_t, int (*cb)(struct netbuf *), struct netbuf **);
void		net_send_fileref(struct connection *, struct kore_fileref *);

void		kore_buf_free(struct kore_buf *);
struct kore_buf	*kore_buf_alloc(size_t);
void		kore_buf_init(struct kore_buf *, size_t);
void		kore_buf_append(struct kore_buf *, const void *, size_t);
u_int8_t	*kore_buf_release(struct kore_buf *, size_t *);
void		kore_buf_reset(struct kore_buf *);
void		kore_buf_cleanup(struct kore_buf *);

char	*kore_buf_stringify(struct kore_buf *, size_t *);
void	kore_buf_appendf(struct kore_buf *, const char *, ...);
void	kore_buf_appendv(struct kore_buf *, const char *, va_list);
void	kore_buf_replace_string(struct kore_buf *,
	    const char *, const void *, size_t);

int	kore_json_parse(struct kore_json *);
void	kore_json_cleanup(struct kore_json *);
void	kore_json_item_free(struct kore_json_item *);
void	kore_json_init(struct kore_json *, const void *, size_t);
void	kore_json_item_tobuf(struct kore_json_item *, struct kore_buf *);

const char		*kore_json_strerror(struct kore_json *);
struct kore_json_item	*kore_json_find(struct kore_json_item *,
			    const char *, u_int32_t);
struct kore_json_item	*kore_json_create_item(struct kore_json_item *,
			    const char *, u_int32_t, ...);

void	kore_keymgr_run(void);
void	kore_keymgr_cleanup(int);

void	kore_seccomp_hook(void);
void	kore_worker_teardown(void);
void	kore_parent_teardown(void);
void	kore_worker_configure(void);
void	kore_parent_daemonized(void);
void	kore_parent_configure(int, char **);

#if defined(__cplusplus)
}
#endif

#endif /* !__H_KORE_H */
