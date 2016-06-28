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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <dlfcn.h>

#include "kore.h"

#if defined(KORE_INTEGRITY_SHA256)
#include <openssl/sha.h>
#endif

static TAILQ_HEAD(, kore_module)	modules;

void
kore_module_init(void)
{
	TAILQ_INIT(&modules);
}

void
kore_module_cleanup(void)
{
	struct kore_module	*module, *next;

	for (module = TAILQ_FIRST(&modules); module != NULL; module = next) {
		next = TAILQ_NEXT(module, list);
		TAILQ_REMOVE(&modules, module, list);

		kore_mem_free(module->path);
		(void)dlclose(module->handle);
		kore_mem_free(module);
	}
}

void
kore_module_load(const char *path, const char *onload)
{
	struct stat		st;
	struct kore_module	*module;

	kore_debug("kore_module_load(%s, %s)", path, onload);

	if (stat(path, &st) == -1)
		fatal("stat(%s): %s", path, errno_s);

	module = kore_malloc(sizeof(struct kore_module));
	module->path = kore_strdup(path);
	module->mtime = st.st_mtime;
	module->onload = NULL;
	module->ocb = NULL;

	module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
	if (module->handle == NULL)
		fatal("%s: %s", path, dlerror());

	if (onload != NULL) {
		module->onload = kore_strdup(onload);
		*(void **)&(module->ocb) = dlsym(module->handle, onload);
		if (module->ocb == NULL)
			fatal("%s: onload '%s' not present", path, onload);
	}

	TAILQ_INSERT_TAIL(&modules, module, list);
}

#if defined(KORE_INTEGRITY_SHA256)
void
kore_module_checksum(const char *path, const char *checksum)
{
	struct kore_module	*module;
	struct kore_module	*remmod = NULL;
	struct kore_module	*nxtmod = NULL;

	int fd;
	unsigned int len;
	unsigned int tot=0;
	int c;
	const unsigned int chunk = 1024; // 1K
	unsigned char buf[1024 +1];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	char output[65];
	SHA256_CTX sha256;

	if(!checksum) {
		kore_log(LOG_ERR,"invalid checksum configured: %s", checksum);
		return;
	}

	kore_debug("kore_module_checksum(%s, %s)", path, checksum);

	if(!SHA256_Init(&sha256)) {
		kore_log(LOG_ERR,"SHA256_Init returns error");
		return;
	}

	for(module = TAILQ_FIRST(&modules); module != NULL; module = nxtmod) {
		nxtmod = TAILQ_NEXT(module, list);
		if(remmod) {
			TAILQ_REMOVE(&modules, remmod, list);
			remmod = NULL;
		}
		if(strcmp(module->path, path))
			continue;

		// check sha256
		fd = open(path, O_RDONLY);
		if(fd<0) {
			kore_log(LOG_ERR,"open error for checksum: %s",path);
			kore_log(LOG_ERR,"%s",strerror(errno));
			remmod = module;
			continue;
		}
		do {
			// read chunk of data in binary file
			len = read(fd, buf, chunk);
			if(len<1) {
				kore_log(LOG_ERR,"read error on file: %s",path);
				kore_log(LOG_ERR,"%s",strerror(errno));
				remmod = module;
				break;
			}
			// stop if NULL read
			if(!len)
				break;
			tot+=len;

			// stop if EOF reached
			if(len<chunk) {
				if(!SHA256_Update(&sha256,buf,len)) {
					kore_log(LOG_ERR,"SHA256_Update returns error");
					remmod = module;
					break;
				}
				break;
			}

			// compute sha256 of chunk
			if(!SHA256_Update(&sha256,buf,len)) {
				kore_log(LOG_ERR,"SHA256_Update returns error");
				remmod = module;
				break;
			}

		} while(len>0);
		close(fd);

		if(!SHA256_Final(hash, &sha256)) {
			kore_log(LOG_ERR,"SHA256_Final returns error");
			remmod = module;
			break;
		}

		for(c = 0; c < SHA256_DIGEST_LENGTH; c++) {
			if(snprintf(output + (c * 2), 65, "%02x", hash[c]) >= 65 ) {
				kore_log(LOG_ERR,"hash computation returns a string that is too big");
				remmod = module;
				break;
			}
		}

		output[64] = 0;

		if(strncmp(output,checksum, 65) ) {
			kore_log(LOG_ERR,"checksum match failed: %s",path);
			kore_log(LOG_ERR,"%s:\t%s",path,output);
			kore_log(LOG_ERR,"conf:\t\t%s",checksum);
			remmod = module;
			continue;
		}
	}

	if(remmod) {
		TAILQ_REMOVE(&modules, remmod, list);
		remmod = NULL;
	}
}
#endif

void
kore_module_onload(void)
{
	struct kore_module	*module;

	TAILQ_FOREACH(module, &modules, list) {
		if (module->ocb == NULL)
			continue;

		(void)module->ocb(KORE_MODULE_LOAD);
	}
}

void
kore_module_reload(int cbs)
{
	struct stat			st;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;
	struct kore_module		*module;

	TAILQ_FOREACH(module, &modules, list) {
		if (stat(module->path, &st) == -1) {
			kore_log(LOG_NOTICE, "stat(%s): %s, skipping reload",
			    module->path, errno_s);
			continue;
		}

		if (module->mtime == st.st_mtime)
			continue;

		if (module->ocb != NULL && cbs == 1) {
			if (!module->ocb(KORE_MODULE_UNLOAD)) {
				kore_log(LOG_NOTICE,
				    "not reloading %s", module->path);
				continue;
			}
		}

		module->mtime = st.st_mtime;
		if (dlclose(module->handle))
			fatal("cannot close existing module: %s", dlerror());

		module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
		if (module->handle == NULL)
			fatal("kore_module_reload(): %s", dlerror());

		if (module->onload != NULL) {
			*(void **)&(module->ocb) =
			    dlsym(module->handle, module->onload);
			if (module->ocb == NULL) {
				fatal("%s: onload '%s' not present",
				    module->path, module->onload);
			}

			if (cbs)
				(void)module->ocb(KORE_MODULE_LOAD);
		}

		kore_log(LOG_NOTICE, "reloaded '%s' module", module->path);
	}

	TAILQ_FOREACH(dom, &domains, list) {
		TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
			hdlr->addr = kore_module_getsym(hdlr->func);
			if (hdlr->func == NULL)
				fatal("no function '%s' found", hdlr->func);
			hdlr->errors = 0;
		}
	}

#if !defined(KORE_NO_HTTP)
	kore_validator_reload();
#endif
}

int
kore_module_loaded(void)
{
	if (TAILQ_EMPTY(&modules))
		return (0);

	return (1);
}

#if !defined(KORE_NO_HTTP)
int
kore_module_handler_new(const char *path, const char *domain,
    const char *func, const char *auth, int type)
{
	struct kore_auth		*ap;
	void				*addr;
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	kore_debug("kore_module_handler_new(%s, %s, %s, %s, %d)", path,
	    domain, func, auth, type);

	addr = kore_module_getsym(func);
	if (addr == NULL) {
		kore_debug("function '%s' not found", func);
		return (KORE_RESULT_ERROR);
	}

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (KORE_RESULT_ERROR);

	if (auth != NULL) {
		if ((ap = kore_auth_lookup(auth)) == NULL)
			fatal("no authentication block '%s' found", auth);
	} else {
		ap = NULL;
	}

	hdlr = kore_malloc(sizeof(*hdlr));
	hdlr->auth = ap;
	hdlr->dom = dom;
	hdlr->errors = 0;
	hdlr->addr = addr;
	hdlr->type = type;
	TAILQ_INIT(&(hdlr->params));
	hdlr->path = kore_strdup(path);
	hdlr->func = kore_strdup(func);

	if (hdlr->type == HANDLER_TYPE_DYNAMIC) {
		if (regcomp(&(hdlr->rctx), hdlr->path,
		    REG_EXTENDED | REG_NOSUB)) {
			kore_module_handler_free(hdlr);
			kore_debug("regcomp() on %s failed", path);
			return (KORE_RESULT_ERROR);
		}
	}

	TAILQ_INSERT_TAIL(&(dom->handlers), hdlr, list);
	return (KORE_RESULT_OK);
}

void
kore_module_handler_free(struct kore_module_handle *hdlr)
{
	struct kore_handler_params *param;

	if (hdlr == NULL)
		return;

	if (hdlr->func != NULL)
		kore_mem_free(hdlr->func);
	if (hdlr->path != NULL)
		kore_mem_free(hdlr->path);
	if (hdlr->type == HANDLER_TYPE_DYNAMIC)
		regfree(&(hdlr->rctx));

	/* Drop all validators associated with this handler */
	while ((param = TAILQ_FIRST(&(hdlr->params))) != NULL) {
		TAILQ_REMOVE(&(hdlr->params), param, list);
		if (param->name != NULL)
			kore_mem_free(param->name);
		kore_mem_free(param);
	}

	kore_mem_free(hdlr);
}

struct kore_module_handle *
kore_module_handler_find(const char *domain, const char *path)
{
	struct kore_domain		*dom;
	struct kore_module_handle	*hdlr;

	if ((dom = kore_domain_lookup(domain)) == NULL)
		return (NULL);

	TAILQ_FOREACH(hdlr, &(dom->handlers), list) {
		if (hdlr->type == HANDLER_TYPE_STATIC) {
			if (!strcmp(hdlr->path, path))
				return (hdlr);
		} else {
			if (!regexec(&(hdlr->rctx), path, 0, NULL, 0))
				return (hdlr);
		}
	}

	return (NULL);
}

#endif /* !KORE_NO_HTTP */

void *
kore_module_getsym(const char *symbol)
{
	void			*ptr;
	struct kore_module	*module;

	TAILQ_FOREACH(module, &modules, list) {
		ptr = dlsym(module->handle, symbol);
		if (ptr != NULL)
			return (ptr);
	}

	return (NULL);
}
