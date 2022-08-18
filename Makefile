# Kore Makefile

CC?=cc
DESTDIR?=
PREFIX?=/usr/local
OBJDIR?=obj
KORE=kore
KODEV=kodev/kodev
KOREPATH?=$(shell pwd)
KORE_CRYPTO?=crypto
INSTALL_DIR=$(PREFIX)/bin
MAN_DIR?=$(PREFIX)/share/man
SHARE_DIR=$(PREFIX)/share/kore
INCLUDE_DIR=$(PREFIX)/include/kore
TLS_BACKEND?=openssl
KORE_TMPDIR?=/tmp

TOOLS=	kore-serve

GENERATED=
PLATFORM=platform.h
VERSION=$(OBJDIR)/version.c
PYTHON_CURLOPT=misc/curl/python_curlopt.h

S_SRC=	src/kore.c src/buf.c src/config.c src/connection.c \
	src/domain.c src/filemap.c src/fileref.c src/json.c src/log.c \
	src/mem.c src/msg.c src/module.c src/net.c src/pool.c src/runtime.c \
	src/sha1.c src/sha2.c src/timer.c src/utils.c src/worker.c
S_SRC+= src/tls_$(TLS_BACKEND).c

FEATURES=
FEATURES_INC=

CFLAGS+=-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iinclude/kore -I$(OBJDIR) -std=c99 -pedantic
CFLAGS+=-Wtype-limits -fno-common
CFLAGS+=-DPREFIX='"$(PREFIX)"' -fstack-protector-all

LDFLAGS+=-rdynamic

ifeq ("$(TLS_BACKEND)", "openssl")
	S_SRC+=src/keymgr_openssl.c
	CFLAGS+=-DTLS_BACKEND_OPENSSL
	FEATURES+=-DTLS_BACKEND_OPENSSL

	ifneq ("$(OPENSSL_PATH)", "")
		CFLAGS+=-I$(OPENSSL_PATH)/include
		LDFLAGS+=-L$(OPENSSL_PATH)/lib -lssl -l$(KORE_CRYPTO)
	else
		LDFLAGS+=-lssl -l$(KORE_CRYPTO)
	endif
else
ifneq ("$(ACME)", "")
$(error ACME not supported under TLS backend $(TLS_BACKEND))
endif
endif

ifneq ("$(KORE_SINGLE_BINARY)", "")
	CFLAGS+=-DKORE_SINGLE_BINARY -DKORE_TMPDIR='"$(KORE_TMPDIR)"'
	FEATURES+=-DKORE_SINGLE_BINARY
endif

ifneq ("$(DEBUG)", "")
	CFLAGS+=-g
	FEATURES+=-DKORE_DEBUG
endif

ifneq ("$(NOOPT)", "")
	CFLAGS+=-O0
else
	CFLAGS+=-O2
endif

ifneq ("$(NOSENDFILE)", "")
	CFLAGS+=-DKORE_NO_SENDFILE
endif

ifneq ("$(NOHTTP)", "")
	CFLAGS+=-DKORE_NO_HTTP
	FEATURES+=-DKORE_NO_HTTP
else
	S_SRC+= src/auth.c src/accesslog.c src/http.c \
		src/route.c src/validator.c src/websocket.c
endif

ifneq ("$(PGSQL)", "")
	S_SRC+=src/pgsql.c
	LDFLAGS+=-L$(shell pg_config --libdir) -lpq
	CFLAGS+=-I$(shell pg_config --includedir) -DKORE_USE_PGSQL \
	    -DPGSQL_INCLUDE_PATH="\"$(shell pg_config --includedir)\""
	FEATURES+=-DKORE_USE_PGSQL
	FEATURES_INC+=-I$(shell pg_config --includedir)
endif

ifneq ("$(TASKS)", "")
	S_SRC+=src/tasks.c
	LDFLAGS+=-lpthread
	CFLAGS+=-DKORE_USE_TASKS
	FEATURES+=-DKORE_USE_TASKS
endif

ifneq ("$(JSONRPC)", "")
	S_SRC+=src/jsonrpc.c
	LDFLAGS+=-lyajl
	CFLAGS+=-DKORE_USE_JSONRPC
	FEATURES+=-DKORE_USE_JSONRPC
endif

ifneq ("$(PYTHON)", "")
	S_SRC+=src/python.c
	GENERATED+=$(PYTHON_CURLOPT)
	KORE_PYTHON_LIB?=$(shell ./misc/python3-config.sh --ldflags)
	KORE_PYTHON_INC?=$(shell ./misc/python3-config.sh --includes)
	LDFLAGS+=$(KORE_PYTHON_LIB)
	CFLAGS+=$(KORE_PYTHON_INC) -DKORE_USE_PYTHON
	FEATURES+=-DKORE_USE_PYTHON
	FEATURES_INC+=$(KORE_PYTHON_INC)
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "freebsd")
	KORE_CURL_LIB=-L/usr/local/lib -lcurl
	KORE_CURL_INC=-I/usr/local/include
endif

ifneq ("$(ACME)", "")
	S_SRC+=src/acme.c
	CURL=1
	CFLAGS+=-DKORE_USE_ACME
	FEATURES+=-DKORE_USE_ACME
endif

ifneq ("$(CURL)", "")
	S_SRC+=src/curl.c
	KORE_CURL_LIB?=$(shell curl-config --libs)
	KORE_CURL_INC?=$(shell curl-config --cflags)
	LDFLAGS+=$(KORE_CURL_LIB)
	CFLAGS+=$(KORE_CURL_INC) -DKORE_USE_CURL
	FEATURES+=-DKORE_USE_CURL
	FEATURES_INC+=$(KORE_CURL_INC)
endif

ifneq ("$(SANITIZE)", "")
	CFLAGS+=-fsanitize=$(SANITIZE)
	LDFLAGS+=-fsanitize=$(SANITIZE)
endif

ifeq ("$(OSNAME)", "darwin")
	ifeq ("$(TLS_BACKEND)", "openssl")
		OSSL_INCL=$(shell pkg-config openssl --cflags)
		CFLAGS+=$(OSSL_INCL)
		LDFLAGS+=$(shell pkg-config openssl --libs)
		FEATURES_INC+=$(OSSL_INCL)
	endif
	S_SRC+=src/bsd.c
else ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	LDFLAGS+=-ldl
	S_SRC+=src/linux.c src/seccomp.c
else
	S_SRC+=src/bsd.c
	ifneq ("$(JSONRPC)", "")
		CFLAGS+=-I/usr/local/include
		LDFLAGS+=-L/usr/local/lib
	endif
endif

S_OBJS=	$(S_SRC:src/%.c=$(OBJDIR)/%.o)
S_OBJS+=$(OBJDIR)/version.o

all: $(PLATFORM) $(GENERATED) $(VERSION) $(KORE) $(KODEV)

$(PLATFORM): $(OBJDIR) force
	@if [ -f misc/$(OSNAME)-platform.sh ]; then \
		misc/$(OSNAME)-platform.sh > $(OBJDIR)/$(PLATFORM) ; \
	fi

$(PYTHON_CURLOPT): $(OBJDIR) force
	@cp $(PYTHON_CURLOPT) $(OBJDIR)

$(VERSION): $(OBJDIR) force
	@if [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		printf "const char *kore_version = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION); \
	elif [ -f RELEASE ]; then \
		printf "const char *kore_version = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *kore_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION);

$(KODEV): src/cli.c
	$(MAKE) -C kodev

$(KORE): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KORE)
	@echo $(LDFLAGS) > kore.linker
	@echo $(FEATURES) $(FEATURES_INC) > kore.features

objects: $(OBJDIR) $(PLATFORM) $(GENERATED) $(S_OBJS)
	@echo $(LDFLAGS) > $(OBJDIR)/ldflags
	@echo "$(FEATURES) $(FEATURES_INC)" > $(OBJDIR)/features

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install:
	mkdir -p $(DESTDIR)$(SHARE_DIR)
	mkdir -p $(DESTDIR)$(INCLUDE_DIR)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	mkdir -p $(DESTDIR)$(MAN_DIR)/man1
	install -m 644 share/man/kodev.1 $(DESTDIR)$(MAN_DIR)/man1/kodev.1
	install -m 555 $(KORE) $(DESTDIR)$(INSTALL_DIR)/$(KORE)
	install -m 644 kore.features $(DESTDIR)$(SHARE_DIR)/features
	install -m 644 kore.linker $(DESTDIR)$(SHARE_DIR)/linker
	install -m 644 include/kore/*.h $(DESTDIR)$(INCLUDE_DIR)
	install -m 644 misc/ffdhe4096.pem $(DESTDIR)$(SHARE_DIR)/ffdhe4096.pem
	$(MAKE) -C kodev install
	$(MAKE) install-sources

install-sources:
	@mkdir -p $(DESTDIR)$(SHARE_DIR)
	@cp Makefile $(DESTDIR)$(SHARE_DIR)
	@cp -R src $(DESTDIR)$(SHARE_DIR)
	@cp -R include $(DESTDIR)$(SHARE_DIR)
	@cp -R misc $(DESTDIR)$(SHARE_DIR)
	@if [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		echo "$$GIT_BRANCH-$$GIT_REVISION" > \
		    $(DESTDIR)$(SHARE_DIR)/RELEASE; \
	elif [ -f RELEASE ]; then \
		cp RELEASE $(DESTDIR)$(SHARE_DIR); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi

uninstall:
	rm -f $(DESTDIR)$(INSTALL_DIR)/$(KORE)
	rm -rf $(DESTDIR)$(INCLUDE_DIR)
	rm -rf $(DESTDIR)$(SHARE_DIR)
	$(MAKE) -C kodev uninstall

tools-build: $(KODEV)
	for t in $(TOOLS); do \
		cd tools/$$t; \
		env \
		    KODEV_OUTPUT=$(KOREPATH) \
		    KORE_SOURCE=$(KOREPATH) \
		    KORE_BUILD_FLAVOR=$(OSNAME) \
		    $(KOREPATH)/$(KODEV) build; \
		cd $(KOREPATH); \
	done

tools-clean: $(KODEV)
	for t in $(TOOLS); do \
		cd tools/$$t; \
		$(KOREPATH)/$(KODEV) clean; \
		cd $(KOREPATH); \
	done

tools-install:
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	for t in $(TOOLS); do \
		install -m 555 $$t $(DESTDIR)$(INSTALL_DIR)/$$t; \
	done

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kore.c: $(VERSION)

src/python.c: $(PYTHON_CURLOPT)

src/seccomp.c: $(PLATFORM)

clean:
	rm -f $(VERSION)
	find . -type f -name \*.o -exec rm {} \;
	rm -rf $(KORE) $(OBJDIR) kore.features kore.linker
	$(MAKE) -C kodev clean

releng-build-examples:
	rm -rf /tmp/kore_releng
	$(MAKE) clean
	$(MAKE) PYTHON=1 PGSQL=1 TASKS=1 PREFIX=/tmp/kore_releng
	$(MAKE) install PREFIX=/tmp/kore_releng
	$(MAKE) -C examples

.PHONY: all clean force
