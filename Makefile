# Kore Makefile

CC?=gcc
PREFIX?=/usr/local
OBJDIR?=obj
KORE=kore
INSTALL_DIR=$(PREFIX)/bin
INCLUDE_DIR=$(PREFIX)/include/kore

S_SRC=	src/kore.c src/buf.c src/config.c src/connection.c \
	src/domain.c src/mem.c src/msg.c src/module.c src/net.c \
	src/pool.c src/runtime.c src/timer.c src/utils.c src/worker.c \
	src/keymgr.c

FEATURES=

CFLAGS+=-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -std=c99 -pedantic
CFLAGS+=-DPREFIX='"$(PREFIX)"'
LDFLAGS=-rdynamic -lssl -lcrypto

ifeq ("$(KORE_SINGLE_BINARY)", "")
	S_SRC+=src/cli.c
else
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
		LDFLAGS=-rdynamic -lcrypto
	endif
endif

ifneq ("$(PGSQL)", "")
	S_SRC+=src/pgsql.c
	LDFLAGS+=-L$(shell pg_config --libdir) -lpq
	CFLAGS+=-I$(shell pg_config --includedir) -DKORE_USE_PGSQL \
	    -DPGSQL_INCLUDE_PATH="\"$(shell pg_config --includedir)\""
	FEATURES+=-I$(shell pg_config --includedir) -DKORE_USE_PGSQL
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
	LDFLAGS+=$(shell python3-config --ldflags)
	CFLAGS+=$(shell python3-config --includes) -DKORE_USE_PYTHON
	FEATURES+=$(shell python3-config --includes) -DKORE_USE_PYTHON
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-I/opt/local/include/ -I/usr/local/opt/openssl/include
	LDFLAGS+=-L/opt/local/lib -L/usr/local/opt/openssl/lib
	S_SRC+=src/bsd.c
else ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1
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

$(KORE): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KORE)

objects: $(OBJDIR) $(S_OBJS)
	@echo $(LDFLAGS) > $(OBJDIR)/ldflags
	@echo $(FEATURES) > $(OBJDIR)/features

all: $(KORE)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install:
	mkdir -p $(INCLUDE_DIR)
	mkdir -p $(INSTALL_DIR)
	install -m 555 $(KORE) $(INSTALL_DIR)/$(KORE)
	install -m 644 includes/*.h $(INCLUDE_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(KORE)
	rm -rf $(INCLUDE_DIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	find . -type f -name \*.o -exec rm {} \;
	rm -rf $(KORE) $(OBJDIR)

.PHONY: all clean
