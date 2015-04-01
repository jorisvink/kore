# Kore Makefile

CC?=gcc
PREFIX?=/usr/local
KORE=kore
INSTALL_DIR=$(PREFIX)/bin
INCLUDE_DIR=$(PREFIX)/include/kore

S_SRC=	src/kore.c src/accesslog.c src/auth.c src/buf.c src/cli.c src/config.c \
	src/connection.c src/domain.c src/http.c src/mem.c src/module.c \
	src/net.c src/pool.c src/spdy.c src/validator.c src/utils.c \
	src/websocket.c src/worker.c src/zlib_dict.c
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
CFLAGS+=-DPREFIX='"$(PREFIX)"'
LDFLAGS+=-rdynamic -lssl -lcrypto -lz

ifneq ("$(DEBUG)", "")
	CFLAGS+=-DKORE_DEBUG
endif

ifneq ("$(KORE_CPP_SUPPORT)", "")
	CFLAGS+=-DKORE_CPP_SUPPORT
	LDFLAGS+=-lstdc++
endif

ifneq ("$(KORE_PEDANTIC_MALLOC)", "")
	CFLAGS+=-DKORE_PEDANTIC_MALLOC
endif

ifneq ("$(BENCHMARK)", "")
	CFLAGS+=-DKORE_BENCHMARK
	LDFLAGS=-rdynamic -lz -lcrypto
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

all: $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KORE)

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

.PHONY: clean
