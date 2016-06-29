# Kore Makefile

CC?=gcc
PREFIX?=/usr/local
KORE=kore
INSTALL_DIR=$(PREFIX)/bin
INCLUDE_DIR=$(PREFIX)/include/kore

S_SRC=	src/kore.c src/buf.c src/cli.c src/config.c src/connection.c \
	src/domain.c src/mem.c src/msg.c src/module.c src/net.c \
	src/pool.c src/timer.c src/utils.c src/worker.c src/keymgr.c
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -std=c99 -pedantic
CFLAGS+=-DPREFIX='"$(PREFIX)"'
LDFLAGS=-rdynamic -lssl -lcrypto

ifneq ("$(DEBUG)", "")
	CFLAGS+=-DKORE_DEBUG -g
	NOOPT=1
endif

ifneq ("$(NOOPT)", "")
	CFLAGS+=-O0
else
	CFLAGS+=-O2
endif

ifneq ("$(NOHTTP)", "")
	CFLAGS+=-DKORE_NO_HTTP
else
	S_SRC+= src/auth.c src/accesslog.c src/http.c \
		src/validator.c src/websocket.c
endif

ifneq ("$(NOTLS)", "")
	CFLAGS+=-DKORE_NO_TLS
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
endif

ifneq ("$(TASKS)", "")
	S_SRC+=src/tasks.c
	LDFLAGS+=-lpthread
	CFLAGS+=-DKORE_USE_TASKS
endif

ifneq ("$(INTEGRITY)", "")
LDFLAGS+=-lcrypto
CFLAGS+=-DKORE_INTEGRITY_SHA256
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
endif

$(KORE): $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KORE)

all: $(KORE)

install:
	mkdir -p $(INCLUDE_DIR)
	mkdir -p $(INSTALL_DIR)
	install -m 555 $(KORE) $(INSTALL_DIR)/$(KORE)
	install -m 644 includes/*.h $(INCLUDE_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(KORE)
	rm -rf $(INCLUDE_DIR)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	find . -type f -name \*.o -exec rm {} \;
	rm -f $(KORE)

.PHONY: all clean
