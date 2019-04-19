# Kore Makefile

CC?=cc
PREFIX?=/usr/local
OBJDIR?=obj
KORE=kore
KODEV=kodev/kodev
KORE_CRYPTO?=crypto
INSTALL_DIR=$(PREFIX)/bin
MAN_DIR=$(PREFIX)/share/man
SHARE_DIR=$(PREFIX)/share/kore
INCLUDE_DIR=$(PREFIX)/include/kore

VERSION=src/version.c

S_SRC=	src/kore.c src/buf.c src/config.c src/connection.c \
	src/domain.c src/filemap.c src/fileref.c src/mem.c src/msg.c \
	src/module.c src/net.c src/pool.c src/runtime.c src/timer.c \
	src/utils.c src/worker.c src/keymgr.c $(VERSION)

FEATURES=
FEATURES_INC=

CFLAGS+=-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iinclude/kore -std=c99 -pedantic
CFLAGS+=-DPREFIX='"$(PREFIX)"' -fstack-protector-all

ifneq ("$(OPENSSL_PATH)", "")
CFLAGS+=-I$(OPENSSL_PATH)/include
LDFLAGS=-rdynamic -L$(OPENSSL_PATH) -lssl -l$(KORE_CRYPTO)
else
LDFLAGS=-rdynamic -lssl -l$(KORE_CRYPTO)
endif

ifneq ("$(KORE_SINGLE_BINARY)", "")
	CFLAGS+=-DKORE_SINGLE_BINARY
	FEATURES+=-DKORE_SINGLE_BINARY
endif

ifneq ("$(DEBUG)", "")
	CFLAGS+=-DKORE_DEBUG -g
	FEATURES+=-DKORE_DEBUG
	NOOPT=1
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
		src/validator.c src/websocket.c
endif

ifneq ("$(NOTLS)", "")
	CFLAGS+=-DKORE_NO_TLS
	FEATURES+=-DKORE_NO_TLS
	ifneq ("$(NOHTTP)", "")
		LDFLAGS=-rdynamic
	else
		LDFLAGS=-rdynamic -l$(KORE_CRYPTO)
	endif
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
	KORE_PYTHON_LIB?=$(shell python3-config --ldflags)
	KORE_PYTHON_INC?=$(shell python3-config --includes)
	LDFLAGS+=$(KORE_PYTHON_LIB)
	CFLAGS+=$(KORE_PYTHON_INC) -DKORE_USE_PYTHON
	FEATURES+=-DKORE_USE_PYTHON
	FEATURES_INC+=$(KORE_PYTHON_INC)
endif

ifneq ("$(SANITIZE)", "")
	CFLAGS+=-fsanitize=$(SANITIZE)
	LDFLAGS+=-fsanitize=$(SANITIZE)
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-I/opt/local/include/ -I/usr/local/opt/openssl/include
	LDFLAGS+=-L/opt/local/lib -L/usr/local/opt/openssl/lib
	S_SRC+=src/bsd.c
else ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	LDFLAGS+=-ldl
	S_SRC+=src/linux.c
else
	S_SRC+=src/bsd.c
	ifneq ("$(JSONRPC)", "")
		CFLAGS+=-I/usr/local/include
		LDFLAGS+=-L/usr/local/lib
	endif
endif

S_OBJS=	$(S_SRC:src/%.c=$(OBJDIR)/%.o)

all: $(VERSION) $(KORE) $(KODEV)

$(VERSION): force
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

$(KODEV):
	$(MAKE) -C kodev

$(KORE): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KORE)
	@echo $(FEATURES) $(FEATURES_INC) > kore.features

objects: $(OBJDIR) $(S_OBJS)
	@echo $(LDFLAGS) > $(OBJDIR)/ldflags
	@echo "$(FEATURES) $(FEATURES_INC)" > $(OBJDIR)/features

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install:
	mkdir -p $(SHARE_DIR)
	mkdir -p $(INCLUDE_DIR)
	mkdir -p $(INSTALL_DIR)
	mkdir -p $(MAN_DIR)/man1
	install -m 644 share/man/kodev.1 $(MAN_DIR)/man1/kodev.1
	install -m 555 $(KORE) $(INSTALL_DIR)/$(KORE)
	install -m 644 kore.features $(SHARE_DIR)/features
	install -m 644 include/kore/*.h $(INCLUDE_DIR)
	$(MAKE) -C kodev install

uninstall:
	rm -f $(INSTALL_DIR)/$(KORE)
	rm -rf $(INCLUDE_DIR)
	rm -rf $(SHARE_DIR)
	$(MAKE) -C kodev uninstall

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(VERSION)
	find . -type f -name \*.o -exec rm {} \;
	rm -rf $(KORE) $(OBJDIR) kore.features
	$(MAKE) -C kodev clean

releng-build-examples:
	rm -rf /tmp/kore_releng
	$(MAKE) clean
	$(MAKE) PYTHON=1 PGSQL=1 TASKS=1 PREFIX=/tmp/kore_releng
	$(MAKE) install PREFIX=/tmp/kore_releng
	$(MAKE) -C examples

.PHONY: all clean force
