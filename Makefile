# Kore Makefile

CC=gcc
BIN=kore

S_SRC+=	src/kore.c src/accesslog.c src/auth.c src/buf.c src/config.c \
	src/connection.c src/domain.c src/http.c src/mem.c src/module.c \
	src/net.c src/pool.c src/spdy.c src/validator.c src/utils.c \
	src/worker.c src/zlib_dict.c
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS+=-rdynamic -lssl -lcrypto -lz

ifneq ("$(DEBUG)", "")
	CFLAGS+=-DKORE_DEBUG
endif

ifneq ("$(PGSQL)", "")
	S_SRC+=contrib/postgres/kore_pgsql.c
	LDFLAGS+=-lpq
	CFLAGS+=-DKORE_USE_PGSQL
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-I/opt/local/include/
	LDFLAGS+=-L/opt/local/lib
	S_SRC+=src/bsd.c
else ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1
	LDFLAGS+=-ldl
	S_SRC+=src/linux.c
else
	S_SRC+=src/bsd.c
endif

all: $(S_OBJS)
	$(CC) $(CFLAGS) $(S_OBJS) $(LDFLAGS) -o $(BIN)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	find . -type f -name \*.o -exec rm {} \;
	rm -f $(BIN)

.PHONY: clean
