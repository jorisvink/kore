/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <regex.h>
#include <syslog.h>
#include <unistd.h>
#include <zlib.h>

#include "spdy.h"

#define KORE_RESULT_ERROR	0
#define KORE_RESULT_OK		1
#define KORE_RESULT_RETRY	2

#define KORE_NAME_STRING	"kore"

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define KORE_DOMAINNAME_LEN		254
#define KORE_PIDFILE_DEFAULT		"/var/run/kore.pid"
#define KORE_DEFAULT_CIPHER_LIST	"HIGH:!aNULL:!MD5;"

#define KORE_DEBUG		1

#if defined(KORE_DEBUG)
#define kore_debug(fmt, ...)	\
	if (kore_debug)		\
		kore_debug_internal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define kore_debug(fmt, ...)
#endif

#define NETBUF_RECV		0
#define NETBUF_SEND		1

#define NETBUF_CALL_CB_ALWAYS	0x01
#define NETBUF_FORCE_REMOVE	0x02

struct netbuf {
	u_int8_t		*buf;
	u_int32_t		offset;
	u_int32_t		len;
	u_int8_t		type;
	u_int8_t		flags;

	void			*owner;
	void			*extra;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

#define KORE_TYPE_LISTENER	1
#define KORE_TYPE_CONNECTION	2

struct listener {
	u_int8_t		type;

	int			fd;
	u_int8_t		addrtype;

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
	} addr;

	LIST_ENTRY(listener)	list;
};

LIST_HEAD(listener_head, listener);

#define CONN_STATE_UNKNOWN		0
#define CONN_STATE_SSL_SHAKE		1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_DISCONNECTING	3

#define CONN_PROTO_UNKNOWN	0
#define CONN_PROTO_SPDY		1
#define CONN_PROTO_HTTP		2

#define CONN_READ_POSSIBLE	0x01
#define CONN_WRITE_POSSIBLE	0x02
#define CONN_WRITE_BLOCK	0x04
#define CONN_IDLE_TIMER_ACT	0x10
#define CONN_READ_BLOCK		0x20

#define KORE_IDLE_TIMER_MAX	20000

struct connection {
	u_int8_t		type;
	int			fd;
	u_int8_t		state;
	u_int8_t		proto;
	void			*owner;
	SSL			*ssl;
	u_int8_t		flags;

	u_int8_t		addrtype;
	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
	} addr;

	struct {
		u_int64_t	length;
		u_int64_t	start;
	} idle_timer;

	u_int8_t		inflate_started;
	z_stream		z_inflate;
	u_int8_t		deflate_started;
	z_stream		z_deflate;
	u_int32_t		wsize_initial;

	TAILQ_HEAD(, netbuf)	send_queue;
	TAILQ_HEAD(, netbuf)	recv_queue;

	u_int32_t			client_stream_id;
	TAILQ_HEAD(, spdy_stream)	spdy_streams;

	TAILQ_ENTRY(connection)	list;
};

#define HANDLER_TYPE_STATIC	1
#define HANDLER_TYPE_DYNAMIC	2

struct kore_module_handle {
	char			*path;
	char			*func;
	void			*addr;
	int			type;
	int			errors;
	regex_t			rctx;

	TAILQ_ENTRY(kore_module_handle)		list;
};

struct kore_worker {
	u_int8_t			id;
	u_int8_t			cpu;
	u_int16_t			load;
	pid_t				pid;
	u_int8_t			has_lock;
	u_int16_t			accepted;
	u_int16_t			accept_treshold;
	struct kore_module_handle	*active_hdlr;
};

struct kore_domain {
	char					*domain;
	char					*certfile;
	char					*certkey;
	int					accesslog;
	SSL_CTX					*ssl_ctx;
	TAILQ_HEAD(, kore_module_handle)	handlers;
	TAILQ_ENTRY(kore_domain)		list;
};

TAILQ_HEAD(kore_domain_h, kore_domain);

#define KORE_BUF_INITIAL	128
#define KORE_BUF_INCREMENT	KORE_BUF_INITIAL

struct kore_buf {
	u_int8_t		*data;
	u_int32_t		length;
	u_int32_t		offset;
};

struct buf_vec {
	u_int8_t		*data;
	u_int32_t		length;
};

struct kore_pool_region {
	void			*start;

	LIST_ENTRY(kore_pool_region)	list;
} __attribute__((__packed__));

struct kore_pool_entry {
	u_int8_t			state;
	struct kore_pool_region		*region;
	LIST_ENTRY(kore_pool_entry)	list;
} __attribute__((__packed__));

struct kore_pool {
	u_int32_t		elen;
	u_int32_t		slen;
	u_int32_t		elms;
	u_int32_t		inuse;
	char			*name;

	LIST_HEAD(, kore_pool_region)	regions;
	LIST_HEAD(, kore_pool_entry)	freelist;
} __attribute__((__packed__));

extern pid_t	kore_pid;
extern int	kore_debug;
extern char	*chroot_path;
extern char	*runas_user;
extern char	*kore_module_onload;
extern char	*kore_pidfile;
extern char	*config_file;
extern char	*kore_ssl_cipher_list;

extern u_int8_t			nlisteners;
extern u_int64_t		spdy_idle_time;
extern u_int16_t		cpu_count;
extern u_int8_t			worker_count;
extern u_int32_t		worker_max_connections;
extern u_int32_t		worker_active_connections;

extern struct listener_head	listeners;
extern struct kore_worker	*worker;
extern struct kore_domain_h	domains;
extern struct kore_domain	*primary_dom;
extern struct passwd		*pw;
extern struct kore_pool		nb_pool;

void		kore_signal(int);
void		kore_worker_wait(int);
void		kore_worker_init(void);
void		kore_worker_shutdown(void);
void		kore_worker_dispatch_signal(int);
void		kore_worker_spawn(u_int16_t, u_int16_t);
void		kore_worker_entry(struct kore_worker *);
void		kore_worker_connection_add(struct connection *);
void		kore_worker_connection_move(struct connection *);
void		kore_worker_connection_remove(struct connection *);

void		kore_platform_init(void);
void		kore_platform_event_init(void);
void		kore_platform_event_wait(void);
void		kore_platform_proctitle(char *);
void		kore_platform_enable_accept(void);
void		kore_platform_disable_accept(void);
void		kore_platform_event_schedule(int, int, int, void *);
void		kore_platform_worker_setcpu(struct kore_worker *);

void		kore_accesslog_init(void);
int		kore_accesslog_wait(void);
void		kore_accesslog_worker_init(void);

int		kore_ssl_sni_cb(SSL *, int *, void *);
int		kore_server_bind(const char *, const char *);
int		kore_ssl_npn_cb(SSL *, const u_char **, unsigned int *, void *);

void		kore_connection_init(void);
int		kore_connection_nonblock(int);
int		kore_connection_handle(struct connection *);
void		kore_connection_remove(struct connection *);
void		kore_connection_disconnect(struct connection *);
void		kore_connection_start_idletimer(struct connection *);
void		kore_connection_stop_idletimer(struct connection *);
void		kore_connection_check_idletimer(u_int64_t, struct connection *);
int		kore_connection_accept(struct listener *, struct connection **);

u_int64_t	kore_time_ms(void);
void		kore_log_init(void);

void		*kore_malloc(size_t);
void		kore_parse_config(void);
void		*kore_calloc(size_t, size_t);
void		*kore_realloc(void *, size_t);
void		kore_mem_free(void *);
void		kore_mem_init(void);

void		*kore_pool_get(struct kore_pool *);
void		kore_pool_put(struct kore_pool *, void *);
void		kore_pool_init(struct kore_pool *, char *,
		    u_int32_t, u_int32_t);

time_t		kore_date_to_time(char *);
char		*kore_time_to_date(time_t);
char		*kore_strdup(const char *);
void		kore_log(int, const char *, ...);
void		kore_strlcpy(char *, const char *, size_t);
void		kore_server_disconnect(struct connection *);
int		kore_split_string(char *, char *, char **, size_t);
long long	kore_strtonum(const char *, long long, long long, int *);
int		kore_base64_encode(u_int8_t *, u_int32_t, char **);
int		kore_base64_decode(char *, u_int8_t **, u_int32_t *);

void		kore_domain_init(void);
int		kore_domain_new(char *);
void		kore_module_load(char *);
void		kore_module_reload(void);
int		kore_module_loaded(void);
void		kore_domain_closelogs(void);
void		kore_domain_sslstart(struct kore_domain *);
int		kore_module_handler_new(char *, char *, char *, int);
struct kore_domain		*kore_domain_lookup(const char *);
struct kore_module_handle	*kore_module_handler_find(char *, char *);

void		fatal(const char *, ...);
void		kore_debug_internal(char *, int, const char *, ...);

u_int16_t	net_read16(u_int8_t *);
u_int32_t	net_read32(u_int8_t *);
void		net_write16(u_int8_t *, u_int16_t);
void		net_write32(u_int8_t *, u_int32_t);
void		net_init(void);
int		net_recv(struct connection *);
int		net_send(struct connection *);
int		net_send_flush(struct connection *);
int		net_recv_flush(struct connection *);
void		net_recv_queue(struct connection *, size_t, int,
		    struct netbuf **, int (*cb)(struct netbuf *));
int		net_recv_expand(struct connection *c, struct netbuf *, size_t,
		    int (*cb)(struct netbuf *));
void		net_send_queue(struct connection *, u_int8_t *, size_t, int,
		    struct netbuf **, int (*cb)(struct netbuf *));

void		kore_buf_free(struct kore_buf *);
struct kore_buf	*kore_buf_create(u_int32_t);
void		kore_buf_append(struct kore_buf *, u_int8_t *, u_int32_t);
u_int8_t	*kore_buf_release(struct kore_buf *, u_int32_t *);
void	kore_buf_appendf(struct kore_buf *, const char *, ...);
void	kore_buf_appendv(struct kore_buf *, struct buf_vec *, u_int16_t);
void	kore_buf_appendb(struct kore_buf *, struct kore_buf *);

struct spdy_header_block	*spdy_header_block_create(int);
struct spdy_stream	*spdy_stream_lookup(struct connection *, u_int32_t);
int			spdy_frame_data_done(struct netbuf *);
int			spdy_stream_get_header(struct spdy_header_block *,
			    char *, char **);

int		spdy_frame_recv(struct netbuf *);
void		spdy_session_teardown(struct connection *c, u_int8_t);
void		spdy_frame_send(struct connection *, u_int16_t,
		    u_int8_t, u_int32_t, struct spdy_stream *, u_int32_t);
void		spdy_header_block_add(struct spdy_header_block *,
		    char *, char *);
u_int8_t	*spdy_header_block_release(struct connection *,
		    struct spdy_header_block *, u_int32_t *);

#endif /* !__H_KORE_H */
