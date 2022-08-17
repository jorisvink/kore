/*
 * Copyright (c) 2019-2022 Joris Vink <joris@coders.se>
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

/*
 * ACMEv2 protocol implementation.
 *
 * The acme process is responsible for talking to the acme servers, parsing
 * their JSON responses and requesting signed data / a csr from the keymgr
 * process.
 *
 * The acme process does not hold your account or domain keys, so anything
 * that needs to be signed is sent to the keymgr process instead.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>

#include "kore.h"
#include "acme.h"
#include "curl.h"

#define ACME_CREATE_ACCOUNT	0
#define ACME_RESOLVE_ACCOUNT	1

#define ACME_STATUS_PENDING	1
#define ACME_STATUS_PROCESSING	2
#define ACME_STATUS_VALID	3
#define ACME_STATUS_INVALID	4
#define ACME_STATUS_READY	5
#define ACME_STATUS_EXPIRED	6
#define ACME_STATUS_REVOKED	7

/*
 * The default provider is letsencrypt, can be overwritten via the config
 * file its acme_provider setting.
 */
#define ACME_DEFAULT_PROVIDER	"https://acme-v02.api.letsencrypt.org/directory"

#if defined(__linux__)
#include "seccomp.h"

/*
 * The syscalls our acme worker is allowed to perform, only.
 *
 * Since we drop all previously loaded seccomp rules to apply our own
 * we will have to reinclude the ones curl does.
 */
static struct sock_filter filter_acme[] = {
	KORE_SYSCALL_ALLOW(prctl),
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
	KORE_SYSCALL_ALLOW(ppoll),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(recvfrom),
#if defined(SYS_epoll_wait)
	KORE_SYSCALL_ALLOW(epoll_wait),
#endif
	KORE_SYSCALL_ALLOW(epoll_pwait),
	KORE_SYSCALL_ALLOW(recvmsg),
	KORE_SYSCALL_ALLOW(sendmsg),
	KORE_SYSCALL_ALLOW(sendmmsg),
	KORE_SYSCALL_ALLOW(getpeername),

	KORE_SYSCALL_ALLOW(gettid),
	KORE_SYSCALL_ALLOW(exit),

	KORE_SYSCALL_ALLOW(brk),
#if defined(SYS_mmap)
	KORE_SYSCALL_ALLOW(mmap),
#endif
#if defined(SYS_mmap2)
	KORE_SYSCALL_ALLOW(mmap2),
#endif
	KORE_SYSCALL_ALLOW(ioctl),
	KORE_SYSCALL_ALLOW(uname),
	KORE_SYSCALL_ALLOW(munmap),
	KORE_SYSCALL_ALLOW(madvise),
	KORE_SYSCALL_ALLOW(faccessat),
	KORE_SYSCALL_ALLOW(newfstatat),
	KORE_SYSCALL_ALLOW(clock_gettime),

	KORE_SYSCALL_ALLOW(bind),
	KORE_SYSCALL_ALLOW(ioctl),
	KORE_SYSCALL_ALLOW(connect),
	KORE_SYSCALL_ALLOW(getsockopt),
	KORE_SYSCALL_ALLOW(socketpair),
	KORE_SYSCALL_ALLOW(getsockname),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET6),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_UNIX),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_NETLINK),

	KORE_SYSCALL_ALLOW(clone),
	KORE_SYSCALL_ALLOW(membarrier),
	KORE_SYSCALL_ALLOW(set_robust_list),
};
#endif

struct acme_request {
	struct kore_curl	curl;
};

struct acme_sign_op {
	u_int32_t			id;
	struct kore_timer		*t;
	void				*udata;
	char				*nonce;
	char				*payload;
	char				*protected;
	void				(*cb)(struct acme_sign_op *,
					    struct kore_buf *);
	LIST_ENTRY(acme_sign_op)	list;
};

#define ACME_AUTH_STATE_DOWNLOAD		1
#define ACME_AUTH_STATE_CHALLENGE		2

struct acme_auth {
	char				*url;
	struct acme_order		*order;
	int				status;
	struct acme_challenge		*challenge;
	LIST_ENTRY(acme_auth)		list;
};

#define ACME_ORDER_STATE_RUNNING		1
#define ACME_ORDER_STATE_ERROR			2
#define ACME_ORDER_STATE_CANCELLED		3
#define ACME_ORDER_STATE_UPDATE			4
#define ACME_ORDER_STATE_UPDATE_AUTH		5
#define ACME_ORDER_STATE_WAITING		6
#define ACME_ORDER_STATE_FETCH_CERT		7
#define ACME_ORDER_STATE_COMPLETE		8
#define ACME_ORDER_TICK				1000
#define ACME_ORDER_TIMEOUT			120000

#define ACME_ORDER_CSR_REQUESTED		0x1000

struct acme_order {
	int				state;
	int				status;
	int				flags;
	int				auths;
	u_int64_t			start;
	char				*id;
	char				*final;
	char				*domain;
	char				*certloc;
	struct acme_auth		*curauth;
	LIST_HEAD(, acme_auth)		auth;
	LIST_ENTRY(acme_order)		list;
};

static LIST_HEAD(, acme_order)		orders;

#define ACME_FLAG_CHALLENGE_CREATED	0x0001
#define ACME_CHALLENGE_TOKEN_MAXLEN	64

struct acme_challenge {
	int		status;
	int		flags;
	char		*url;
	char		*type;
	char		*token;
	char		*error_type;
	char		*error_detail;
	int		(*process)(struct acme_order *,
			    struct acme_challenge *);
};

static LIST_HEAD(, acme_sign_op)	signops;

static int	acme_status_type(const char *);
static int	acme_request_run(struct acme_request *);
static void	acme_request_cleanup(struct acme_request *);
static void	acme_request_prepare(struct acme_request *,
		    int, const char *, const void *, size_t);
static void	acme_request_json(struct kore_buf *, const char *,
		    const char *, const char *);

static char	*acme_nonce_fetch(void);
static char	*acme_thumbprint_component(void);
static char	*acme_base64url(const void *, size_t);
static char	*acme_protected_component(const char *, const char *);
static void	acme_keymgr_key_req(const char *, const void *, size_t, int);

static void	acme_parse_directory(void);
static void	acme_directory_set(struct kore_json *, const char *, char **);

static void	acme_sign_expire(void *, u_int64_t);
static void	acme_sign_result(struct kore_msg *, const void *);
static void	acme_sign_submit(struct kore_json_item *, const char *, void *,
		    void (*cb)(struct acme_sign_op *, struct kore_buf *));

static void	acme_rsakey_exp(struct kore_msg *, const void *);
static void	acme_rsakey_mod(struct kore_msg *, const void *);

static void	acme_account_reg(int);
static void	acme_account_create(struct kore_msg *, const void *);
static void	acme_account_resolve(struct kore_msg *, const void *);
static void	acme_generic_submit(struct acme_sign_op *, struct kore_buf *);
static void	acme_account_reg_submit(struct acme_sign_op *,
		    struct kore_buf *);

static void	acme_order_retry(const char *);
static void	acme_order_process(void *, u_int64_t);
static void	acme_order_update(struct acme_order *);
static void	acme_order_update_submit(struct acme_sign_op *,
		    struct kore_buf *);
static void	acme_order_request_csr(struct acme_order *);
static void	acme_order_fetch_certificate(struct acme_order *);
static void	acme_order_fetch_certificate_submit(struct acme_sign_op *,
		    struct kore_buf *);
static void	acme_order_create(struct kore_msg *, const void *);
static void	acme_order_remove(struct acme_order *, const char *);
static void	acme_order_csr_response(struct kore_msg *, const void *);
static void	acme_order_create_submit(struct acme_sign_op *,
		    struct kore_buf *);

static void	acme_order_auth_log_error(struct acme_order *);
static void	acme_order_auth_deactivate(struct acme_order *);
static int	acme_order_auth_process(struct acme_order *,
		    struct acme_auth *);
static void	acme_order_auth_update(struct acme_order *,
		    struct acme_auth *);
static void	acme_order_auth_update_submit(struct acme_sign_op *,
		    struct kore_buf *);

static int	acme_challenge_tls_alpn_01(struct acme_order *,
		    struct acme_challenge *);
static void	acme_challenge_tls_alpn_01_create(struct acme_order *,
		    struct acme_challenge *);

static void	acme_challenge_respond(struct acme_order *,
		    const char *, const char *);

static int		signop_id = 0;
static char		*rsakey_n = NULL;
static char		*rsakey_e = NULL;
static char		*nonce_url = NULL;
static char		*order_url = NULL;
static char		*revoke_url = NULL;
static char		*account_id = NULL;
static char		*account_url = NULL;

struct kore_privsep	acme_privsep;
int			acme_domains = 0;
char			*acme_email = NULL;
char			*acme_provider = NULL;
u_int32_t		acme_request_timeout = 8;

void
kore_acme_init(void)
{
	acme_provider = kore_strdup(ACME_DEFAULT_PROVIDER);
}

void
kore_acme_run(void)
{
	int		quit;
	u_int64_t	now, netwait;

	quit = 0;

	kore_server_closeall();
	kore_module_cleanup();

	net_init();
	kore_timer_init();
	kore_connection_init();
	kore_platform_event_init();
	kore_msg_worker_init();

	kore_msg_register(KORE_ACME_RSAKEY_E, acme_rsakey_exp);
	kore_msg_register(KORE_ACME_RSAKEY_N, acme_rsakey_mod);
	kore_msg_register(KORE_ACME_SIGN_RESULT, acme_sign_result);
	kore_msg_register(KORE_ACME_ORDER_CREATE, acme_order_create);
	kore_msg_register(KORE_ACME_ACCOUNT_CREATE, acme_account_create);
	kore_msg_register(KORE_ACME_ACCOUNT_RESOLVE, acme_account_resolve);
	kore_msg_register(KORE_ACME_CSR_RESPONSE, acme_order_csr_response);

#if defined(__linux__)
	/* Drop all enabled seccomp filters, and add only ours. */
	kore_seccomp_drop();
	kore_seccomp_filter("acme", filter_acme, KORE_FILTER_LEN(filter_acme));
#endif
#if defined(KORE_USE_PYTHON)
	kore_msg_unregister(KORE_PYTHON_SEND_OBJ);
#endif
	kore_worker_privsep();

#if defined(__OpenBSD__)
	if (unveil("/etc/ssl/", "r") == -1)
		fatal("unveil: %s", errno_s);
	if (pledge("stdio inet dns rpath", NULL) == -1)
		fatal("pledge acme process: %s", errno_s);
#endif

	http_init();

	LIST_INIT(&orders);
	LIST_INIT(&signops);

	kore_worker_started();
	acme_parse_directory();

	while (quit != 1) {
		now = kore_time_ms();
		netwait = kore_timer_next_run(now);
		kore_platform_event_wait(netwait);

		if (sig_recv != 0) {
			switch (sig_recv) {
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;
			default:
				break;
			}
			sig_recv = 0;
		}

		if (quit)
			break;

		now = kore_time_ms();
		kore_timer_run(now);
		kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	}

	kore_platform_event_cleanup();
	kore_connection_cleanup();
	net_cleanup();
}

void
kore_acme_get_paths(const char *domain, char **key, char **cert)
{
	int		len;
	char		path[MAXPATHLEN];

	len = snprintf(path, sizeof(path), "%s/%s/fullchain.pem",
	    KORE_ACME_CERTDIR, domain);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to create certfile path");

	*cert = kore_strdup(path);

	len = snprintf(path, sizeof(path), "%s/%s/key.pem",
	    KORE_ACME_CERTDIR, domain);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to create certkey path");

	*key = kore_strdup(path);
}

static void
acme_parse_directory(void)
{
	struct acme_request	req;
	size_t			len;
	struct kore_json	json;
	const u_int8_t		*body;

	acme_request_prepare(&req, HTTP_METHOD_GET, acme_provider, NULL, 0);

	if (!acme_request_run(&req)) {
		acme_request_cleanup(&req);
		return;
	}

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "request to '%s' failed: got %ld - expected 200",
		    req.curl.url, req.curl.http.status);
		acme_request_cleanup(&req);
		return;
	}

	kore_curl_response_as_bytes(&req.curl, &body, &len);

	kore_json_init(&json, body, len);

	if (!kore_json_parse(&json)) {
		kore_log(LOG_NOTICE,
		    "failed to parse directory payload from ACME server (%s)",
		    kore_json_strerror());
		goto cleanup;
	}

	acme_directory_set(&json, "newNonce", &nonce_url);
	acme_directory_set(&json, "newOrder", &order_url);
	acme_directory_set(&json, "newAccount", &account_url);
	acme_directory_set(&json, "revokeCert", &revoke_url);

cleanup:
	kore_json_cleanup(&json);
	acme_request_cleanup(&req);
}

static char *
acme_nonce_fetch(void)
{
	struct acme_request	req;
	char			*ret;
	const char		*nonce;

	ret = NULL;
	acme_request_prepare(&req, HTTP_METHOD_HEAD, nonce_url, NULL, 0);

	if (!acme_request_run(&req))
		goto cleanup;

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "request to '%s' failed: got %ld - expected 200",
		    req.curl.url, req.curl.http.status);
		goto cleanup;
	}

	if (!kore_curl_http_get_header(&req.curl, "replay-nonce", &nonce)) {
		kore_log(LOG_NOTICE, "new-nonce: no replay-nonce header found");
		goto cleanup;
	}

	ret = kore_strdup(nonce);

cleanup:
	acme_request_cleanup(&req);

	return (ret);
}

static void
acme_account_create(struct kore_msg *msg, const void *data)
{
	acme_account_reg(ACME_CREATE_ACCOUNT);
}

static void
acme_account_resolve(struct kore_msg *msg, const void *data)
{
	acme_account_reg(ACME_RESOLVE_ACCOUNT);
}

static void
acme_account_reg(int resolve_only)
{
	int			len;
	char			mail[1024];
	struct kore_json_item	*json, *contact;

	if (account_url == NULL)
		return;

	kore_free(account_id);
	account_id = NULL;

	kore_log(LOG_INFO, "%s account with ACME provider",
	    resolve_only ? "resolving" : "creating");

	json = kore_json_create_object(NULL, NULL);
	kore_json_create_literal(json, "termsOfServiceAgreed", KORE_JSON_TRUE);

	if (acme_email) {
		len = snprintf(mail, sizeof(mail), "mailto:%s", acme_email);
		if (len == -1 || (size_t)len >= sizeof(mail))
			fatalx("mail contact '%s' too large", acme_email);

		contact = kore_json_create_array(json, "contact");
		kore_json_create_string(contact, NULL, mail);
	}

	if (resolve_only) {
		kore_json_create_literal(json,
		    "onlyReturnExisting", KORE_JSON_TRUE);
	}

	acme_sign_submit(json, account_url, NULL, acme_account_reg_submit);
	kore_json_item_free(json);
}

static void
acme_account_reg_submit(struct acme_sign_op *op, struct kore_buf *payload)
{
	struct acme_request	req;
	const char		*header;

	acme_request_prepare(&req, HTTP_METHOD_POST, account_url,
	    payload->data, payload->offset);

	if (!acme_request_run(&req))
		goto cleanup;

	switch (req.curl.http.status) {
	case HTTP_STATUS_OK:
	case HTTP_STATUS_CREATED:
		break;
	default:
		kore_log(LOG_NOTICE,
		    "request to '%s' failed: status %ld - body '%s'",
		    req.curl.url, req.curl.http.status,
		    kore_curl_response_as_string(&req.curl));
		goto cleanup;
	}

	if (!kore_curl_http_get_header(&req.curl, "location", &header)) {
		kore_log(LOG_NOTICE, "new-acct: no location header found");
		goto cleanup;
	}

	account_id = kore_strdup(header);
	kore_log(LOG_INFO, "account_id =  %s", account_id);
	kore_msg_send(KORE_WORKER_KEYMGR, KORE_ACME_PROC_READY, NULL, 0);

cleanup:
	acme_request_cleanup(&req);
}

static void
acme_order_create(struct kore_msg *msg, const void *data)
{
	char			*domain;
	struct kore_json_item	*json, *identifiers, *identifier;

	domain = kore_calloc(1, msg->length + 1);
	memcpy(domain, data, msg->length);
	domain[msg->length] = '\0';

	kore_log(LOG_INFO, "[%s] creating order", domain);

	json = kore_json_create_object(NULL, NULL);
	identifiers = kore_json_create_array(json, "identifiers");

	identifier = kore_json_create_object(identifiers, NULL);
	kore_json_create_string(identifier, "type", "dns");
	kore_json_create_string(identifier, "value", domain);

	acme_sign_submit(json, order_url, domain, acme_order_create_submit);
	kore_json_item_free(json);
}

static void
acme_order_create_submit(struct acme_sign_op *op, struct kore_buf *payload)
{
	struct acme_request		req;
	size_t				len;
	struct kore_json		json;
	int				stval;
	const u_int8_t			*body;
	struct acme_auth		*auth;
	struct acme_order		*order;
	const char			*header;
	const char			*domain;
	struct kore_json_item		*item, *array, *final, *status;

	order = NULL;
	domain = op->udata;
	acme_request_prepare(&req, HTTP_METHOD_POST, order_url,
	    payload->data, payload->offset);

	if (!acme_request_run(&req)) {
		acme_request_cleanup(&req);
		acme_order_retry(domain);
		return;
	}

	if (req.curl.http.status != HTTP_STATUS_CREATED) {
		kore_log(LOG_NOTICE,
		    "[%s] - request to '%s' failed: status %ld - body '%s'",
		    domain, req.curl.url, req.curl.http.status,
		    kore_curl_response_as_string(&req.curl));
		acme_request_cleanup(&req);
		acme_order_retry(domain);
		return;
	}

	if (!kore_curl_http_get_header(&req.curl, "location", &header)) {
		kore_log(LOG_NOTICE,
		    "[%s] new-order: no order id found", domain);
		acme_request_cleanup(&req);
		acme_order_retry(domain);
		return;
	}

	kore_curl_response_as_bytes(&req.curl, &body, &len);
	kore_json_init(&json, body, len);

	if (!kore_json_parse(&json)) {
		kore_log(LOG_NOTICE,
		    "[%s] failed to parse order payload from ACME server (%s)",
		    domain, kore_json_strerror());
		goto cleanup;
	}

	array = kore_json_find_array(json.root, "authorizations");
	if (array == NULL) {
		kore_log(LOG_NOTICE, "[%s] body has no 'authorizations' array",
		    domain);
		goto cleanup;
	}

	if (TAILQ_EMPTY(&array->data.items)) {
		kore_log(LOG_NOTICE, "[%s] no authoritization URLs in payload",
		    domain);
		goto cleanup;
	}

	if ((status = kore_json_find_string(json.root, "status")) == NULL) {
		kore_log(LOG_NOTICE, "[%s] order has no 'status' string",
		    domain);
		goto cleanup;
	}

	if ((final = kore_json_find_string(json.root, "finalize")) == NULL) {
		kore_log(LOG_NOTICE, "[%s] order has no 'finalize' string",
		    domain);
		goto cleanup;
	}

	if ((stval = acme_status_type(status->data.string)) == -1) {
		kore_log(LOG_NOTICE, "[%s] order has invalid status",
		    domain);
		goto cleanup;
	}

	order = kore_calloc(1, sizeof(*order));
	LIST_INSERT_HEAD(&orders, order, list);

	LIST_INIT(&order->auth);

	order->status = stval;
	order->start = kore_time_ms();
	order->id = kore_strdup(header);
	order->domain = kore_strdup(domain);
	order->state = ACME_ORDER_STATE_UPDATE;
	order->final = kore_strdup(final->data.string);

	kore_timer_add(acme_order_process, ACME_ORDER_TICK,
	    order, KORE_TIMER_ONESHOT);

	TAILQ_FOREACH(item, &array->data.items, list) {
		if (item->type != KORE_JSON_TYPE_STRING)
			continue;

		auth = kore_calloc(1, sizeof(*auth));
		auth->order = order;
		auth->url = kore_strdup(item->data.string);
		LIST_INSERT_HEAD(&order->auth, auth, list);
	}

	order->curauth = LIST_FIRST(&order->auth);
	kore_log(LOG_INFO, "[%s] order_id =  %s", order->domain, order->id);

cleanup:
	if (order == NULL)
		acme_order_retry(domain);

	kore_json_cleanup(&json);
	acme_request_cleanup(&req);
}

static void
acme_order_update(struct acme_order *order)
{
	acme_sign_submit(NULL, order->id, order, acme_order_update_submit);
}

static void
acme_order_update_submit(struct acme_sign_op *op, struct kore_buf *payload)
{
	struct acme_request		req;
	size_t				len;
	struct kore_json		json;
	struct acme_order		*order;
	const u_int8_t			*body;
	int				stval, ret;
	struct kore_json_item		*status, *cert;

	order = op->udata;
	op->udata = NULL;

	acme_request_prepare(&req, HTTP_METHOD_POST, order->id,
	    payload->data, payload->offset);

	if (!acme_request_run(&req)) {
		acme_request_cleanup(&req);
		order->state = ACME_ORDER_STATE_ERROR;
		return;
	}

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "[%s] - request to '%s' failed: status %ld - body '%s'",
		    order->domain, req.curl.url, req.curl.http.status,
		    kore_curl_response_as_string(&req.curl));
		acme_request_cleanup(&req);
		order->state = ACME_ORDER_STATE_ERROR;
		return;
	}

	ret = KORE_RESULT_ERROR;
	kore_curl_response_as_bytes(&req.curl, &body, &len);

	kore_json_init(&json, body, len);

	if (!kore_json_parse(&json)) {
		kore_log(LOG_NOTICE,
		    "[%s] failed to parse order payload from ACME server (%s)",
		    order->domain, kore_json_strerror());
		goto cleanup;
	}

	if ((status = kore_json_find_string(json.root, "status")) == NULL) {
		kore_log(LOG_NOTICE, "[%s] order has no 'status' string",
		    order->domain);
		goto cleanup;
	}

	if ((stval = acme_status_type(status->data.string)) == -1) {
		kore_log(LOG_NOTICE, "[%s] order has invalid status",
		    order->domain);
		goto cleanup;
	}

	order->status = stval;

	if (order->status == ACME_STATUS_VALID) {
		cert = kore_json_find_string(json.root, "certificate");
		if (cert == NULL) {
			kore_log(LOG_NOTICE,
			    "[%s] order has 'certificate' member",
			    order->domain);
			goto cleanup;
		}

		order->certloc = kore_strdup(cert->data.string);
	}

	ret = KORE_RESULT_OK;

cleanup:
	if (ret == KORE_RESULT_ERROR)
		order->state = ACME_ORDER_STATE_ERROR;
	else
		order->state = ACME_ORDER_STATE_UPDATE_AUTH;

	kore_json_cleanup(&json);
	acme_request_cleanup(&req);
}

/*
 * We currently don't care why an order may have failed, (rate-limited,
 * auth failed, etc).
 *
 * It would be neat if we could obey that a bit better.
 */
static void
acme_order_retry(const char *domain)
{
	u_int32_t	retry_after;

	/* arbitrary number */
	retry_after = 60000;

	acme_keymgr_key_req(domain, &retry_after, sizeof(retry_after),
	    KORE_ACME_ORDER_FAILED);
}

/*
 * Process an order, step by step.
 *
 * This callback is called every second to check on an active order.
 * It will first update the order if required, and updated any of its
 * active awuthoritizations to get the latest data.
 */
static void
acme_order_process(void *udata, u_int64_t now)
{
	struct acme_auth	*auth;
	struct acme_order	*order = udata;

	if ((now - order->start) >= ACME_ORDER_TIMEOUT) {
		acme_order_auth_deactivate(order);
		acme_order_remove(order, "order ran too long");
		return;
	}

	switch (order->state) {
	case ACME_ORDER_STATE_WAITING:
		break;
	case ACME_ORDER_STATE_UPDATE:
		acme_order_update(order);
		order->state = ACME_ORDER_STATE_WAITING;
		break;
	case ACME_ORDER_STATE_UPDATE_AUTH:
		order->auths = 0;
		LIST_FOREACH(auth, &order->auth, list) {
			acme_order_auth_update(order, auth);
			order->auths++;
		}
		order->state = ACME_ORDER_STATE_WAITING;
		break;
	case ACME_ORDER_STATE_CANCELLED:
		acme_order_remove(order, "cancelled");
		order = NULL;
		break;
	case ACME_ORDER_STATE_COMPLETE:
		acme_order_remove(order, "completed");
		order = NULL;
		break;
	case ACME_ORDER_STATE_FETCH_CERT:
		acme_order_fetch_certificate(order);
		order->state = ACME_ORDER_STATE_WAITING;
		break;
	case ACME_ORDER_STATE_RUNNING:
		switch (order->status) {
		case ACME_STATUS_PENDING:
			if (!acme_order_auth_process(order, order->curauth)) {
				acme_order_auth_log_error(order);
				acme_order_remove(order, "cancelled");
				order = NULL;
			}
			break;
		case ACME_STATUS_READY:
			acme_order_request_csr(order);
			break;
		case ACME_STATUS_PROCESSING:
			kore_log(LOG_INFO, "[%s] waiting for certificate",
			    order->domain);
			break;
		case ACME_STATUS_VALID:
			kore_log(LOG_INFO, "[%s] certificate available",
			    order->domain);
			order->state = ACME_ORDER_STATE_FETCH_CERT;
			break;
		case ACME_STATUS_INVALID:
			kore_log(LOG_INFO, "[%s] order authorization failed",
			    order->domain);
			acme_order_auth_log_error(order);
			acme_order_remove(order, "authorization failure");
			order = NULL;
			break;
		default:
			acme_order_auth_deactivate(order);
			acme_order_remove(order, "unknown status");
			order = NULL;
			break;
		}
		break;
	case ACME_ORDER_STATE_ERROR:
		acme_order_auth_deactivate(order);
		acme_order_remove(order, "error");
		order = NULL;
		break;
	default:
		fatal("%s: invalid order state %d", __func__, order->state);
	}

	if (order != NULL) {
		/* Do not go back to update if we are ready for the cert. */
		if (order->state != ACME_ORDER_STATE_FETCH_CERT)
			order->state = ACME_ORDER_STATE_UPDATE;

		kore_timer_add(acme_order_process, ACME_ORDER_TICK,
		    order, KORE_TIMER_ONESHOT);
	}
}

static void
acme_order_remove(struct acme_order *order, const char *reason)
{
	struct acme_auth	*auth;

	LIST_REMOVE(order, list);

	while ((auth = LIST_FIRST(&order->auth)) != NULL) {
		LIST_REMOVE(auth, list);

		if (auth->challenge != NULL) {
			kore_free(auth->challenge->error_detail);
			kore_free(auth->challenge->error_type);
			kore_free(auth->challenge->token);
			kore_free(auth->challenge->type);
			kore_free(auth->challenge->url);
			kore_free(auth->challenge);
		}

		kore_free(auth->url);
		kore_free(auth);
	}

	kore_log(LOG_INFO, "[%s] order removed (%s)", order->domain, reason);

	if (strcmp(reason, "completed"))
		acme_order_retry(order->domain);

	kore_free(order->domain);
	kore_free(order->final);
	kore_free(order->id);
	kore_free(order);
}

static void
acme_order_fetch_certificate(struct acme_order *order)
{
	acme_sign_submit(NULL, order->certloc, order,
	    acme_order_fetch_certificate_submit);
}

static void
acme_order_fetch_certificate_submit(struct acme_sign_op *op,
    struct kore_buf *payload)
{
	struct acme_request	req;
	size_t			len;
	const u_int8_t		*body;
	struct acme_order	*order;

	order = op->udata;
	op->udata = NULL;

	acme_request_prepare(&req, HTTP_METHOD_POST, order->certloc,
	    payload->data, payload->offset);

	if (!acme_request_run(&req)) {
		acme_request_cleanup(&req);
		order->state = ACME_ORDER_STATE_CANCELLED;
		return;
	}

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "[%s] request to '%s' failed: got %ld - expected 200",
		    order->domain, order->certloc, req.curl.http.status);
		acme_request_cleanup(&req);
		order->state = ACME_ORDER_STATE_CANCELLED;
		return;
	}

	kore_curl_response_as_bytes(&req.curl, &body, &len);

	kore_log(LOG_INFO, "got %zu bytes of cert data", len);
	acme_keymgr_key_req(order->domain, body, len, KORE_ACME_INSTALL_CERT);

	acme_request_cleanup(&req);
	order->state = ACME_ORDER_STATE_COMPLETE;
}

static void
acme_order_request_csr(struct acme_order *order)
{
	if (order->flags & ACME_ORDER_CSR_REQUESTED)
		return;

	kore_log(LOG_INFO, "[%s] requesting CSR", order->domain);

	order->flags |= ACME_ORDER_CSR_REQUESTED;
	acme_keymgr_key_req(order->domain, NULL, 0, KORE_ACME_CSR_REQUEST);
}

static void
acme_order_csr_response(struct kore_msg *msg, const void *data)
{
	const struct kore_x509_msg	*req;
	struct kore_json_item		*json;
	struct acme_order		*order;
	char				*b64, *url;

	if (!kore_worker_keymgr_response_verify(msg, data, NULL))
		return;

	req = (const struct kore_x509_msg *)data;

	LIST_FOREACH(order, &orders, list) {
		if (!strcmp(order->domain, req->domain))
			break;
	}

	if (order == NULL) {
		kore_log(LOG_NOTICE, "[%s] csr received but no order active",
		    req->domain);
		return;
	}

	url = kore_strdup(order->final);
	b64 = acme_base64url(req->data, req->data_len);

	json = kore_json_create_object(NULL, NULL);
	kore_json_create_string(json, "csr", b64);
	acme_sign_submit(json, url, url, acme_generic_submit);

	kore_json_item_free(json);
	kore_free(b64);
}

static void
acme_order_auth_deactivate(struct acme_order *order)
{
	struct acme_request	req;
	struct acme_auth	*auth;

	LIST_FOREACH(auth, &order->auth, list) {
		acme_request_prepare(&req, HTTP_METHOD_GET, auth->url, NULL, 0);

		if (!acme_request_run(&req)) {
			kore_log(LOG_NOTICE,
			    "[%s:auth] failed to deactivate %s", order->domain,
			    auth->url);
		} else {
			kore_log(LOG_NOTICE, "[%s:auth] deactivated %s",
			    order->domain, auth->url);
		}

		acme_request_cleanup(&req);
	}
}

static void
acme_order_auth_log_error(struct acme_order *order)
{
	struct acme_auth	*auth;

	LIST_FOREACH(auth, &order->auth, list) {
		if (auth->challenge->status == ACME_STATUS_PENDING ||
		    auth->challenge->status == ACME_STATUS_VALID ||
		    auth->challenge->status == ACME_STATUS_PROCESSING)
			continue;

		kore_log(LOG_INFO, "[%s:auth:challenge] %s = %s (%s)",
		    order->domain, auth->challenge->type,
		    auth->challenge->error_type, auth->challenge->error_detail);
	}
}

static int
acme_order_auth_process(struct acme_order *order, struct acme_auth *auth)
{
	int		ret;

	if (auth == NULL)
		return (KORE_RESULT_OK);

	ret = KORE_RESULT_ERROR;
	kore_log(LOG_INFO, "[%s] processing authentication", order->domain);

	switch (auth->status) {
	case ACME_STATUS_PENDING:
		ret = auth->challenge->process(order, auth->challenge);
		break;
	case ACME_STATUS_VALID:
	case ACME_STATUS_PROCESSING:
		ret = KORE_RESULT_OK;
		break;
	case ACME_STATUS_INVALID:
		kore_log(LOG_NOTICE, "[%s:auth] authorization invalid",
		    order->domain);
		break;
	case ACME_STATUS_EXPIRED:
		kore_log(LOG_NOTICE, "[%s:auth] authorization expired",
		    order->domain);
		break;
	case ACME_STATUS_REVOKED:
		kore_log(LOG_NOTICE, "[%s:auth] authorization revoked",
		    order->domain);
		break;
	default:
		kore_log(LOG_NOTICE, "[%s:auth] invalid auth status %d",
		    order->domain, auth->status);
		break;
	}

	if (ret == KORE_RESULT_OK)
		order->curauth = LIST_NEXT(order->curauth, list);

	return (ret);
}

static void
acme_order_auth_update(struct acme_order *order, struct acme_auth *auth)
{
	acme_sign_submit(NULL, auth->url, auth, acme_order_auth_update_submit);
}

static void
acme_order_auth_update_submit(struct acme_sign_op *op, struct kore_buf *payload)
{
	const char			*p;
	struct acme_request		req;
	size_t				len;
	struct kore_json		json;
	const u_int8_t			*body;
	struct acme_auth		*auth;
	struct acme_order		*order;
	struct acme_challenge		*challenge;
	int				ret, stval;
	struct kore_json_item		*status, *type, *url, *token;
	struct kore_json_item		*array, *object, *err, *detail;

	ret = KORE_RESULT_ERROR;
	memset(&json, 0, sizeof(json));

	auth = op->udata;
	order = auth->order;

	op->udata = NULL;

	acme_request_prepare(&req, HTTP_METHOD_POST, auth->url,
	    payload->data, payload->offset);

	if (!acme_request_run(&req))
		goto cleanup;

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "[%s:auth] request to '%s' failed: got %ld - expected 200",
		    order->domain, auth->url, req.curl.http.status);
		goto cleanup;
	}

	kore_curl_response_as_bytes(&req.curl, &body, &len);

	kore_json_init(&json, body, len);

	if (!kore_json_parse(&json)) {
		kore_log(LOG_NOTICE,
		    "[%s:auth] failed to parse payload from ACME server (%s)",
		    order->domain, kore_json_strerror());
		goto cleanup;
	}

	kore_log(LOG_INFO, "[%s:auth] %s updated", order->domain, auth->url);

	if ((status = kore_json_find_string(json.root, "status")) == NULL) {
		kore_log(LOG_NOTICE, "[%s:auth] payload has no 'status' string",
		    order->domain);
		goto cleanup;
	}

	if ((array = kore_json_find_array(json.root, "challenges")) == NULL) {
		kore_log(LOG_NOTICE,
		    "[%s:auth] payload has no 'challenges' array",
		    order->domain);
		goto cleanup;
	}

	if (TAILQ_EMPTY(&array->data.items)) {
		kore_log(LOG_NOTICE,
		    "[%s:auth] no challenges URLs in challenge array",
		    order->domain);
		goto cleanup;
	}

	if ((stval = acme_status_type(status->data.string)) == -1) {
		kore_log(LOG_NOTICE, "[%s] auth has invalid status",
		    order->domain);
		goto cleanup;
	}

	auth->status = stval;

	TAILQ_FOREACH(object, &array->data.items, list) {
		if (object->type != KORE_JSON_TYPE_OBJECT)
			continue;

		if ((type = kore_json_find_string(object, "type")) == NULL) {
			kore_log(LOG_NOTICE,
			    "[%s:auth:challenge] no type", order->domain);
			continue;
		}

		/*
		 * We only support tls-alpn-01 for now, we ignore the rest.
		 */
		if (strcmp(type->data.string, "tls-alpn-01"))
			continue;

		url = kore_json_find_string(object, "url");
		token = kore_json_find_string(object, "token");
		status = kore_json_find_string(object, "status");

		if (url == NULL || token == NULL || status == NULL) {
			kore_log(LOG_NOTICE,
			    "[%s:auth:challenge] missing members",
			    order->domain);
			continue;
		}

		if (strlen(token->data.string) > ACME_CHALLENGE_TOKEN_MAXLEN) {
			kore_log(LOG_NOTICE,
			    "[%s:auth:challenge] invalid token length",
			    order->domain);
			continue;
		}

		for (p = token->data.string; *p != '\0'; p++) {
			if ((*p >= 'a' && *p <= 'z') ||
			    (*p >= 'A' && *p <= 'Z') ||
			    (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
				continue;
			break;
		}

		if (*p != '\0') {
			kore_log(LOG_NOTICE,
			    "[%s:auth:challenge] invalid token",
			    order->domain);
			continue;
		}

		if ((stval = acme_status_type(status->data.string)) == -1) {
			kore_log(LOG_NOTICE,
			    "[%s:auth:challenge] invalid challenge status",
			    order->domain);
			continue;
		}

		if (auth->challenge == NULL) {
			challenge = kore_calloc(1, sizeof(*challenge));

			challenge->url = kore_strdup(url->data.string);
			challenge->process = acme_challenge_tls_alpn_01;
			challenge->token = kore_strdup(token->data.string);
			challenge->type = kore_strdup(type->data.string);

			auth->challenge = challenge;
		} else {
			challenge = auth->challenge;
		}

		challenge->status = stval;

		if (challenge->status == ACME_STATUS_INVALID &&
		    (err = kore_json_find_object(object, "error")) != NULL) {
			type = kore_json_find_string(err, "type");
			detail = kore_json_find_string(err, "detail");

			if (type == NULL || detail == NULL) {
				kore_log(LOG_NOTICE,
				    "[%s:auth:challenge] error missing fields",
				    order->domain);
			} else {
				kore_free(challenge->error_type);
				kore_free(challenge->error_detail);

				challenge->error_type =
				    kore_strdup(type->data.string);
				challenge->error_detail =
				    kore_strdup(detail->data.string);
			}
		}

		break;
	}

	if (auth->challenge == NULL) {
		kore_log(LOG_NOTICE,
		    "[%s:auth] no supported challenges found", order->domain);
		goto cleanup;
	}

	ret = KORE_RESULT_OK;

cleanup:
	if (ret != KORE_RESULT_OK) {
		order->state = ACME_ORDER_STATE_CANCELLED;
	} else {
		order->auths--;
		if (order->auths == 0) {
			kore_log(LOG_INFO,
			    "[%s:auth] authentications done", order->domain);
			order->state = ACME_ORDER_STATE_RUNNING;
		}
	}

	kore_json_cleanup(&json);
	acme_request_cleanup(&req);
}

static int
acme_challenge_tls_alpn_01(struct acme_order *order,
    struct acme_challenge *challenge)
{
	int			ret;

	ret = KORE_RESULT_RETRY;

	switch (challenge->status) {
	case ACME_STATUS_PENDING:
		acme_challenge_tls_alpn_01_create(order, challenge);
		break;
	case ACME_STATUS_PROCESSING:
		kore_log(LOG_INFO,
		    "[%s:auth:challenge:tls-alpn-01] processing",
		    order->domain);
		break;
	case ACME_STATUS_VALID:
		kore_log(LOG_INFO,
		    "[%s:auth:challenge:tls-alpn-01] valid",
		    order->domain);
		ret = KORE_RESULT_OK;
		break;
	default:
		kore_log(LOG_NOTICE,
		    "[%s:auth:challenge:tls-alpn-01] invalid (%d)",
		    order->domain, challenge->status);
		ret = KORE_RESULT_ERROR;
		break;
	}

	return (ret);
}

static void
acme_challenge_tls_alpn_01_create(struct acme_order *order,
    struct acme_challenge *challenge)
{
	struct kore_buf		auth;
	char			*thumb;
	u_int8_t		digest[SHA256_DIGEST_LENGTH];

	if (challenge->flags & ACME_FLAG_CHALLENGE_CREATED) {
		kore_log(LOG_INFO,
		    "[%s:auth:challenge:tls-alpn-01] pending keymgr",
		    order->domain);
		return;
	}

	challenge->flags |= ACME_FLAG_CHALLENGE_CREATED;

	kore_log(LOG_INFO,
	    "[%s:auth:challenge:tls-alpn-01] requested from keymgr",
	    order->domain);

	thumb = acme_thumbprint_component();

	kore_buf_init(&auth, 128);
	kore_buf_appendf(&auth, "%s.%s", challenge->token, thumb);
	(void)SHA256(auth.data, auth.offset, digest);

	kore_buf_cleanup(&auth);
	kore_free(thumb);

	acme_keymgr_key_req(order->domain, digest, sizeof(digest),
	    KORE_ACME_CHALLENGE_CERT);

	/* XXX - this maybe too fast, keymgr may not have had time. */
	acme_challenge_respond(order, challenge->url, "tls-alpn-01");
}

static void
acme_challenge_respond(struct acme_order *order, const char *url,
    const char *name)
{
	struct kore_json_item	*json;
	char			*copy;

	kore_log(LOG_INFO, "[%s:auth:challenge:%s] submitting challenge",
	    order->domain, name);

	copy = kore_strdup(url);

	json = kore_json_create_object(NULL, NULL);
	acme_sign_submit(json, url, copy, acme_generic_submit);
	kore_json_item_free(json);
}

static void
acme_generic_submit(struct acme_sign_op *op, struct kore_buf *payload)
{
	struct acme_request	req;

	acme_request_prepare(&req, HTTP_METHOD_POST, op->udata,
	    payload->data, payload->offset);

	if (!acme_request_run(&req))
		goto cleanup;

	if (req.curl.http.status != HTTP_STATUS_OK) {
		kore_log(LOG_NOTICE,
		    "request to '%s' failed: status %ld - body '%s'",
		    req.curl.url, req.curl.http.status,
		    kore_curl_response_as_string(&req.curl));
		goto cleanup;
	}

	kore_log(LOG_INFO, "submitted %zu bytes to %s",
	    payload->offset, req.curl.url);

cleanup:
	acme_request_cleanup(&req);
}

static void
acme_request_prepare(struct acme_request *req, int method,
    const char *url, const void *data, size_t len)
{
	memset(req, 0, sizeof(*req));

	if (!kore_curl_init(&req->curl, url, KORE_CURL_SYNC))
		fatal("failed to initialize request to '%s'", url);

	/* Override default timeout. */
	curl_easy_setopt(req->curl.handle,
	    CURLOPT_TIMEOUT, acme_request_timeout);

	kore_curl_http_setup(&req->curl, method, data, len);
	kore_curl_http_set_header(&req->curl, "content-type",
	    "application/jose+json");
}

static void
acme_request_json(struct kore_buf *buf, const char *payload,
    const char *protected, const char *sig)
{
	struct kore_json_item	*json;

	json = kore_json_create_object(NULL, NULL);

	kore_json_create_string(json, "signature", sig);
	kore_json_create_string(json, "payload", payload);
	kore_json_create_string(json, "protected", protected);

	kore_json_item_tobuf(json, buf);
	kore_json_item_free(json);
}

static int
acme_request_run(struct acme_request *req)
{
	size_t				len;
	struct kore_json		json;
	const u_int8_t			*body;
	struct kore_json_item		*detail;

	kore_curl_run(&req->curl);

	if (!kore_curl_success(&req->curl)) {
		kore_log(LOG_NOTICE, "request to '%s' failed: %s",
		    req->curl.url, kore_curl_strerror(&req->curl));
		return (KORE_RESULT_ERROR);
	}

	if (req->curl.http.status == HTTP_STATUS_BAD_REQUEST) {
		kore_curl_response_as_bytes(&req->curl, &body, &len);
		kore_json_init(&json, body, len);

		if (!kore_json_parse(&json)) {
			detail = NULL;
		} else {
			detail = kore_json_find_string(json.root, "detail");
		}

		if (detail != NULL) {
			kore_log(LOG_NOTICE,
			    "request to '%s' failed with 400 - detail: %s",
			    req->curl.url, detail->data.string);
		} else {
			kore_log(LOG_NOTICE,
			    "request to '%s' failed with 400 - body: %.*s",
			    req->curl.url, (int)len, (const char *)body);
		}

		kore_json_cleanup(&json);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static void
acme_request_cleanup(struct acme_request *req)
{
	kore_curl_cleanup(&req->curl);
}

static void
acme_directory_set(struct kore_json *json, const char *name, char **out)
{
	struct kore_json_item	*item;

	if ((item = kore_json_find_string(json->root, name)) == NULL) {
		kore_log(LOG_NOTICE, "directory has missing '%s' URI", name);
		return;
	}

	*out = kore_strdup(item->data.string);
}

static void
acme_sign_submit(struct kore_json_item *json, const char *url, void *udata,
    void (*cb)(struct acme_sign_op *, struct kore_buf *))
{
	struct acme_sign_op	*op;
	struct kore_buf		buf;
	char			*nonce;

	if ((nonce = acme_nonce_fetch()) == NULL) {
		kore_log(LOG_ERR, "failed to fetch nonce from servers");
		return;
	}

	kore_buf_init(&buf, 1024);

	if (json != NULL)
		kore_json_item_tobuf(json, &buf);

	op = kore_calloc(1, sizeof(*op));
	LIST_INSERT_HEAD(&signops, op, list);

	op->cb = cb;
	op->udata = udata;
	op->nonce = nonce;
	op->id = signop_id++;
	op->payload = acme_base64url(buf.data, buf.offset);
	op->protected = acme_protected_component(op->nonce, url);
	op->t = kore_timer_add(acme_sign_expire, 30000, op, KORE_TIMER_ONESHOT);

	kore_buf_reset(&buf);
	kore_buf_append(&buf, &op->id, sizeof(op->id));
	kore_buf_appendf(&buf, "%s.%s", op->protected, op->payload);

	kore_msg_send(KORE_WORKER_KEYMGR, KORE_ACME_SIGN, buf.data, buf.offset);
	kore_buf_cleanup(&buf);
}

static void
acme_sign_expire(void *udata, u_int64_t now)
{
	struct acme_sign_op	*op = udata;

	kore_log(LOG_NOTICE, "signop %u expired (no answer)", op->id);

	LIST_REMOVE(op, list);

	kore_free(op->protected);
	kore_free(op->payload);
	kore_free(op->udata);
	kore_free(op->nonce);
	kore_free(op);
}

static void
acme_sign_result(struct kore_msg *msg, const void *data)
{
	u_int32_t		id;
	struct kore_buf		buf;
	struct acme_sign_op	*op;
	char			*sig;
	const u_int8_t		*ptr;

	if (msg->length < sizeof(id))
		fatal("%s: invalid length (%zu)", __func__, msg->length);

	ptr = data;
	memcpy(&id, ptr, sizeof(id));

	ptr += sizeof(id);
	msg->length -= sizeof(id);

	LIST_FOREACH(op, &signops, list) {
		if (op->id == id)
			break;
	}

	if (op == NULL) {
		kore_log(LOG_NOTICE,
		    "received KORE_ACME_SIGN_RESULT for unknown op: %u", id);
		return;
	}

	kore_timer_remove(op->t);
	LIST_REMOVE(op, list);

	sig = kore_malloc(msg->length + 1);
	memcpy(sig, ptr, msg->length);
	sig[msg->length] = '\0';

	kore_buf_init(&buf, 1024);
	acme_request_json(&buf, op->payload, op->protected, sig);

	op->cb(op, &buf);

	kore_free(op->protected);
	kore_free(op->payload);
	kore_free(op->udata);
	kore_free(op->nonce);
	kore_free(op);

	kore_free(sig);
	kore_buf_cleanup(&buf);
}

static char *
acme_protected_component(const char *nonce, const char *url)
{
	char			*b64;
	struct kore_buf		payload;
	struct kore_json_item	*root, *jwk;

	root = kore_json_create_object(NULL, NULL);

	kore_json_create_string(root, "url", url);
	kore_json_create_string(root, "alg", "RS256");
	kore_json_create_string(root, "nonce", nonce);

	if (account_id == NULL) {
		jwk = kore_json_create_object(root, "jwk");
		kore_json_create_string(jwk, "kty", "RSA");
		kore_json_create_string(jwk, "e", rsakey_e);
		kore_json_create_string(jwk, "n", rsakey_n);
	} else {
		kore_json_create_string(root, "kid", account_id);
	}

	kore_buf_init(&payload, 128);
	kore_json_item_tobuf(root, &payload);

	b64 = acme_base64url(payload.data, payload.offset);

	kore_json_item_free(root);
	kore_buf_cleanup(&payload);

	return (b64);
}

static char *
acme_thumbprint_component(void)
{
	struct kore_json_item	*json;
	struct kore_buf		payload;
	u_int8_t		digest[SHA256_DIGEST_LENGTH];

	json = kore_json_create_object(NULL, NULL);

	/* Order matters here, see RFC7638. */
	kore_json_create_string(json, "e", rsakey_e);
	kore_json_create_string(json, "kty", "RSA");
	kore_json_create_string(json, "n", rsakey_n);

	kore_buf_init(&payload, 128);
	kore_json_item_tobuf(json, &payload);

	(void)SHA256(payload.data, payload.offset, digest);

	kore_json_item_free(json);
	kore_buf_cleanup(&payload);

	return (acme_base64url(digest, sizeof(digest)));
}

static char *
acme_base64url(const void *data, size_t len)
{
	char		*b64;

	if (!kore_base64url_encode(data, len, &b64, KORE_BASE64_RAW)) {
		fatal("%s: failed to encode base64url data of %zu bytes",
		    __func__, len);
	}

	return (b64);
}

static void
acme_keymgr_key_req(const char *domain, const void *data, size_t len, int msg)
{
	struct kore_keyreq	req;
	struct kore_buf		buf;

	memset(&req, 0, sizeof(req));
	req.data_len = len;

	if (kore_strlcpy(req.domain, domain, sizeof(req.domain)) >=
	    sizeof(req.domain))
		fatal("%s: domain truncated", __func__);

	kore_buf_init(&buf, sizeof(req) + len);
	kore_buf_append(&buf, &req, sizeof(req));

	if (data != NULL)
		kore_buf_append(&buf, data, len);

	kore_msg_send(KORE_WORKER_KEYMGR, msg, buf.data, buf.offset);
	kore_buf_cleanup(&buf);
}

static int
acme_status_type(const char *status)
{
	int	type;

	if (!strcmp(status, "pending")) {
		type = ACME_STATUS_PENDING;
	} else if (!strcmp(status, "processing")) {
		type = ACME_STATUS_PROCESSING;
	} else if (!strcmp(status, "valid")) {
		type = ACME_STATUS_VALID;
	} else if (!strcmp(status, "invalid")) {
		type = ACME_STATUS_INVALID;
	} else if (!strcmp(status, "ready")) {
		type = ACME_STATUS_READY;
	} else if (!strcmp(status, "expired")) {
		type = ACME_STATUS_EXPIRED;
	} else if (!strcmp(status, "revoked")) {
		type = ACME_STATUS_REVOKED;
	} else {
		type = -1;
	}

	return (type);
}

static void
acme_rsakey_exp(struct kore_msg *msg, const void *data)
{
	kore_free(rsakey_e);
	rsakey_e = kore_calloc(1, msg->length + 1);
	memcpy(rsakey_e, data, msg->length);
	rsakey_e[msg->length] = '\0';
}

static void
acme_rsakey_mod(struct kore_msg *msg, const void *data)
{
	kore_free(rsakey_n);
	rsakey_n = kore_calloc(1, msg->length + 1);
	memcpy(rsakey_n, data, msg->length);
	rsakey_n[msg->length] = '\0';
}
