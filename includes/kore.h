/*
 * Copyright (c) 2013-2016 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#if !defined(KORE_NO_TLS)
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#endif

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
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
#endif

#define KORE_RESULT_ERROR	0
#define KORE_RESULT_OK		1
#define KORE_RESULT_RETRY	2

#define KORE_VERSION_MAJOR	2
#define KORE_VERSION_MINOR	1
#define KORE_VERSION_PATCH	0
#define KORE_VERSION_STATE	"devel"

#define KORE_TLS_VERSION_1_2	0
#define KORE_TLS_VERSION_1_0	1
#define KORE_TLS_VERSION_BOTH	2

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define KORE_DOMAINNAME_LEN		255
#define KORE_PIDFILE_DEFAULT		"kore.pid"
#define KORE_DEFAULT_CIPHER_LIST	"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!kRSA:!kDSA"

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

#define NETBUF_LAST_CHAIN		0
#define NETBUF_BEFORE_CHAIN		1

#define NETBUF_CALL_CB_ALWAYS	0x01
#define NETBUF_FORCE_REMOVE	0x02
#define NETBUF_MUST_RESEND	0x04
#define NETBUF_IS_STREAM	0x10

#define X509_GET_CN(c, o, l)					\
	X509_NAME_get_text_by_NID(X509_get_subject_name(c),	\
	    NID_commonName, o, l)

#define X509_CN_LENGTH		(ub_common_name + 1)

/* XXX hackish. */
#if !defined(KORE_NO_HTTP)
struct http_request;
#endif

struct netbuf {
	u_int8_t		*buf;
	size_t			s_off;
	size_t			b_len;
	size_t			m_len;
	u_int8_t		type;
	u_int8_t		flags;

	void			*owner;

	void			*extra;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_head, netbuf);

#define KORE_TYPE_LISTENER	1
#define KORE_TYPE_CONNECTION	2
#define KORE_TYPE_PGSQL_CONN	3
#define KORE_TYPE_TASK		4

#define CONN_STATE_UNKNOWN		0
#define CONN_STATE_SSL_SHAKE		1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_DISCONNECTING	3

#define CONN_PROTO_UNKNOWN	0
#define CONN_PROTO_HTTP		1
#define CONN_PROTO_WEBSOCKET	2
#define CONN_PROTO_MSG		3

#define CONN_READ_POSSIBLE	0x01
#define CONN_WRITE_POSSIBLE	0x02
#define CONN_WRITE_BLOCK	0x04
#define CONN_IDLE_TIMER_ACT	0x10
#define CONN_READ_BLOCK		0x20
#define CONN_CLOSE_EMPTY	0x40

#define KORE_IDLE_TIMER_MAX	20000

#define WEBSOCKET_OP_CONT	0x00
#define WEBSOCKET_OP_TEXT	0x01
#define WEBSOCKET_OP_BINARY	0x02
#define WEBSOCKET_OP_CLOSE	0x08
#define WEBSOCKET_OP_PING	0x09
#define WEBSOCKET_OP_PONG	0x10

#define WEBSOCKET_BROADCAST_LOCAL	1
#define WEBSOCKET_BROADCAST_GLOBAL	2

#define KORE_TIMER_ONESHOT	0x01

#define KORE_CONNECTION_PRUNE_DISCONNECT	0
#define KORE_CONNECTION_PRUNE_ALL		1

struct connection {
	u_int8_t		type;
	int			fd;
	u_int8_t		state;
	u_int8_t		proto;
	void			*owner;
#if !defined(KORE_NO_TLS)
	X509			*cert;
	SSL			*ssl;
	int			tls_reneg;
#endif
	u_int8_t		flags;
	void			*hdlr_extra;

	int			(*handle)(struct connection *);
	void			(*disconnect)(struct connection *);
	int			(*read)(struct connection *, int *);
	int			(*write)(struct connection *, int, int *);

	u_int8_t		addrtype;
	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
	} addr;

	struct {
		u_int64_t	length;
		u_int64_t	start;
	} idle_timer;

	struct netbuf_head	send_queue;
	struct netbuf		*snb;
	struct netbuf		*rnb;

#if !defined(KORE_NO_HTTP)
	void				*wscbs;
	TAILQ_HEAD(, http_request)	http_requests;
#endif

	TAILQ_ENTRY(connection)	list;
};

TAILQ_HEAD(connection_list, connection);
extern struct connection_list	connections;
extern struct connection_list	disconnected;

struct listener {
	u_int8_t		type;
	u_int8_t		addrtype;
	int			fd;
	void			(*connect)(struct connection *);

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
	} addr;

	LIST_ENTRY(listener)	list;
};

LIST_HEAD(listener_head, listener);

#if !defined(KORE_NO_HTTP)

struct kore_handler_params {
	char			*name;
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

#endif

#define KORE_MODULE_LOAD	1
#define KORE_MODULE_UNLOAD	2

struct kore_module {
	void			*handle;
	char			*path;
	char			*onload;
	int			(*ocb)(int);

	time_t			mtime;

	TAILQ_ENTRY(kore_module)	list;
};

struct kore_module_handle {
	char			*path;
	char			*func;
	void			*addr;
	int			type;
	int			errors;
	regex_t			rctx;
	struct kore_domain	*dom;
#if !defined(KORE_NO_HTTP)
	struct kore_auth	*auth;
	TAILQ_HEAD(, kore_handler_params)	params;
#endif
	TAILQ_ENTRY(kore_module_handle)		list;
};

struct kore_worker {
	u_int8_t			id;
	u_int8_t			cpu;
	pid_t				pid;
	int				pipe[2];
	struct connection		*msg[2];
	u_int8_t			has_lock;
	struct kore_module_handle	*active_hdlr;
};

struct kore_domain {
	char					*domain;
	int					accesslog;
#if !defined(KORE_NO_TLS)
	char					*cafile;
	char					*crlfile;
	char					*certfile;
	char					*certkey;
	SSL_CTX					*ssl_ctx;
#endif
	TAILQ_HEAD(, kore_module_handle)	handlers;
	TAILQ_ENTRY(kore_domain)		list;
};

TAILQ_HEAD(kore_domain_h, kore_domain);

#if !defined(KORE_NO_HTTP)

#define KORE_VALIDATOR_TYPE_REGEX	1
#define KORE_VALIDATOR_TYPE_FUNCTION	2

struct kore_validator {
	u_int8_t		type;
	char			*name;
	char			*arg;
	regex_t			rctx;
	int			(*func)(struct http_request *, char *);

	TAILQ_ENTRY(kore_validator)	list;
};
#endif

#define KORE_BUF_OWNER_API	0x0001

struct kore_buf {
	u_int8_t		*data;
	int			flags;
	size_t			length;
	size_t			offset;
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
	volatile int		lock;
	char			*name;

	LIST_HEAD(, kore_pool_region)	regions;
	LIST_HEAD(, kore_pool_entry)	freelist;
};

struct kore_wscbs {
	void		(*connect)(struct connection *);
	void		(*message)(struct connection *, u_int8_t,
			    void *, size_t);
	void		(*disconnect)(struct connection *);
};

struct kore_timer {
	u_int64_t	nextrun;
	u_int64_t	interval;
	int		flags;
	void		*arg;
	void		(*cb)(void *, u_int64_t);

	TAILQ_ENTRY(kore_timer)	list;
};

#define KORE_WORKER_KEYMGR	0

/* Reserved message ids, registered on workers. */
#define KORE_MSG_ACCESSLOG	1
#define KORE_MSG_WEBSOCKET	2
#define KORE_MSG_KEYMGR_REQ	3
#define KORE_MSG_KEYMGR_RESP	4

/* Predefined message targets. */
#define KORE_MSG_PARENT		1000
#define KORE_MSG_WORKER_ALL	1001

struct kore_msg {
	u_int8_t	id;
	u_int16_t	src;
	u_int16_t	dst;
	u_int32_t	length;
};

#if !defined(KORE_NO_TLS)
struct kore_keyreq {
	int		padding;
	char		domain[KORE_DOMAINNAME_LEN];
	u_int8_t	domain_len;
	u_int16_t	data_len;
	u_int8_t	data[];
};
#endif

#if !defined(KORE_SINGLE_BINARY)
extern char	*config_file;
#endif

extern pid_t	kore_pid;
extern int	foreground;
extern int	kore_debug;
extern int	skip_chroot;
extern char	*chroot_path;
extern int	skip_runas;
extern char	*runas_user;
extern char	*kore_pidfile;
extern char	*kore_tls_cipher_list;
extern int	tls_version;

#if !defined(KORE_NO_TLS)
extern DH	*tls_dhparam;
#endif

extern u_int8_t			nlisteners;
extern u_int16_t		cpu_count;
extern u_int8_t			worker_count;
extern u_int8_t			worker_set_affinity;
extern u_int32_t		worker_rlimit_nofiles;
extern u_int32_t		worker_max_connections;
extern u_int32_t		worker_active_connections;
extern u_int32_t		worker_accept_threshold;
extern u_int64_t		kore_websocket_maxframe;
extern u_int64_t		kore_websocket_timeout;
extern u_int32_t		kore_socket_backlog;

extern struct listener_head	listeners;
extern struct kore_worker	*worker;
extern struct kore_domain_h	domains;
extern struct kore_domain	*primary_dom;
extern struct kore_pool		nb_pool;

void		kore_cli_usage(int);
int		kore_cli_main(int, char **);

void		kore_signal(int);
void		kore_worker_wait(int);
void		kore_worker_init(void);
void		kore_worker_shutdown(void);
void		kore_worker_privdrop(void);
void		kore_worker_dispatch_signal(int);
void		kore_worker_spawn(u_int16_t, u_int16_t);
void		kore_worker_entry(struct kore_worker *);

struct kore_worker	*kore_worker_data(u_int8_t);

void		kore_platform_init(void);
void		kore_platform_event_init(void);
void		kore_platform_event_cleanup(void);
void		kore_platform_proctitle(char *);
void		kore_platform_disable_read(int);
void		kore_platform_enable_accept(void);
void		kore_platform_disable_accept(void);
int		kore_platform_event_wait(u_int64_t);
void		kore_platform_event_all(int, void *);
void		kore_platform_schedule_read(int, void *);
void		kore_platform_schedule_write(int, void *);
void		kore_platform_event_schedule(int, int, int, void *);
void		kore_platform_worker_setcpu(struct kore_worker *);

void		kore_accesslog_init(void);
void		kore_accesslog_worker_init(void);
int		kore_accesslog_write(const void *, u_int32_t);

#if !defined(KORE_NO_HTTP)
int		kore_auth_run(struct http_request *, struct kore_auth *);
void		kore_auth_init(void);
int		kore_auth_new(const char *);
struct kore_auth	*kore_auth_lookup(const char *);
#endif

void		kore_timer_init(void);
u_int64_t	kore_timer_run(u_int64_t);
void		kore_timer_remove(struct kore_timer *);
struct kore_timer	*kore_timer_add(void (*cb)(void *, u_int64_t),
			    u_int64_t, void *, int);

void		kore_listener_cleanup(void);
int		kore_server_bind(const char *, const char *, const char *);
#if !defined(KORE_NO_TLS)
int		kore_tls_sni_cb(SSL *, int *, void *);
void		kore_tls_info_callback(const SSL *, int, int);
#endif

void			kore_connection_init(void);
void			kore_connection_cleanup(void);
void			kore_connection_prune(int);
struct connection	*kore_connection_new(void *);
void			kore_connection_check_timeout(void);
int			kore_connection_nonblock(int, int);
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

void		*kore_malloc(size_t);
void		kore_parse_config(void);
void		*kore_calloc(size_t, size_t);
void		*kore_realloc(void *, size_t);
void		kore_free(void *);
void		kore_mem_init(void);

void		*kore_pool_get(struct kore_pool *);
void		kore_pool_put(struct kore_pool *, void *);
void		kore_pool_init(struct kore_pool *, const char *,
		    size_t, size_t);
void		kore_pool_cleanup(struct kore_pool *);

time_t		kore_date_to_time(char *);
char		*kore_time_to_date(time_t);
char		*kore_strdup(const char *);
void		kore_log(int, const char *, ...);
u_int64_t	kore_strtonum64(const char *, int, int *);
size_t		kore_strlcpy(char *, const char *, const size_t);
void		kore_server_disconnect(struct connection *);
int		kore_split_string(char *, const char *, char **, size_t);
void		kore_strip_chars(char *, const char, char **);
int		kore_snprintf(char *, size_t, int *, const char *, ...);
long long	kore_strtonum(const char *, int, long long, long long, int *);
int		kore_base64_encode(u_int8_t *, size_t, char **);
int		kore_base64_decode(char *, u_int8_t **, size_t *);
void		*kore_mem_find(void *, size_t, void *, size_t);
char		*kore_text_trim(char *, size_t);
char		*kore_read_line(FILE *, char *, size_t);

#if !defined(KORE_NO_HTTP)
void		kore_websocket_handshake(struct http_request *,
		    struct kore_wscbs *);
void		kore_websocket_send(struct connection *,
		    u_int8_t, const void *, size_t);
void		kore_websocket_broadcast(struct connection *,
		    u_int8_t, const void *, size_t, int);
#endif

void		kore_msg_init(void);
void		kore_msg_worker_init(void);
void		kore_msg_parent_init(void);
void		kore_msg_parent_add(struct kore_worker *);
void		kore_msg_parent_remove(struct kore_worker *);
void		kore_msg_send(u_int16_t, u_int8_t, const void *, u_int32_t);
int		kore_msg_register(u_int8_t,
		    void (*cb)(struct kore_msg *, const void *));

void		kore_domain_init(void);
void		kore_domain_cleanup(void);
int		kore_domain_new(char *);
void		kore_domain_free(struct kore_domain *);
void		kore_module_init(void);
void		kore_module_cleanup(void);
void		kore_module_reload(int);
void		kore_module_onload(void);
int		kore_module_loaded(void);
void		kore_domain_closelogs(void);
void		*kore_module_getsym(const char *);
void		kore_domain_load_crl(void);
void		kore_domain_keymgr_init(void);
void		kore_module_load(const char *, const char *);
void		kore_domain_sslstart(struct kore_domain *);
void		kore_domain_callback(void (*cb)(struct kore_domain *));
int		kore_module_handler_new(const char *, const char *,
		    const char *, const char *, int);
void		kore_module_handler_free(struct kore_module_handle *);

struct kore_domain		*kore_domain_lookup(const char *);
struct kore_module_handle	*kore_module_handler_find(const char *,
				    const char *);

#if !defined(KORE_NO_HTTP)
void		kore_validator_init(void);
void		kore_validator_reload(void);
int		kore_validator_add(const char *, u_int8_t, const char *);
int		kore_validator_run(struct http_request *, const char *, char *);
int		kore_validator_check(struct http_request *,
		    struct kore_validator *, void *);
struct kore_validator	*kore_validator_lookup(const char *);
#endif

void		fatal(const char *, ...) __attribute__((noreturn));
void		kore_debug_internal(char *, int, const char *, ...);

u_int16_t	net_read16(u_int8_t *);
u_int32_t	net_read32(u_int8_t *);
u_int64_t	net_read64(u_int8_t *);
void		net_write16(u_int8_t *, u_int16_t);
void		net_write32(u_int8_t *, u_int32_t);
void		net_write64(u_int8_t *, u_int64_t);

void		net_init(void);
void		net_cleanup(void);
int		net_send(struct connection *);
int		net_send_flush(struct connection *);
int		net_recv_flush(struct connection *);
int		net_read(struct connection *, int *);
int		net_read_ssl(struct connection *, int *);
int		net_write(struct connection *, int, int *);
int		net_write_ssl(struct connection *, int, int *);
void		net_recv_reset(struct connection *, size_t,
		    int (*cb)(struct netbuf *));
void		net_remove_netbuf(struct netbuf_head *, struct netbuf *);
void		net_recv_queue(struct connection *, size_t, int,
		    int (*cb)(struct netbuf *));
void		net_recv_expand(struct connection *c, size_t,
		    int (*cb)(struct netbuf *));
void		net_send_queue(struct connection *, const void *, size_t);
void		net_send_stream(struct connection *, void *,
		    size_t, int (*cb)(struct netbuf *), struct netbuf **);

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
void	kore_buf_replace_string(struct kore_buf *, char *, void *, size_t);

void	kore_keymgr_run(void);
void	kore_keymgr_cleanup(void);

#if defined(KORE_SINGLE_BINARY)
void	kore_preload(void);
void	kore_onload(void);
#endif

#if defined(__cplusplus)
}
#endif

#endif /* !__H_KORE_H */
