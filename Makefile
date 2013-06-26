# Kore Makefile

CC=gcc
BIN=kore

S_SRC+=	src/kore.c src/buf.c src/config.c src/net.c src/spdy.c src/http.c \
	src/accesslog.c src/domain.c src/module.c src/utils.c \
	src/worker.c src/connection.c src/zlib_dict.c
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-I/usr/local/ssl/include
CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS+=-rdynamic -Llibs -lssl -lcrypto -lz

default:
	@echo "Please specify a build target [linux | bsd]"

linux:
	@LDFLAGS="-ldl" CFLAGS="-D_GNU_SOURCE=1" S_SRC=src/linux.c make kore

bsd:
	@S_SRC=src/bsd.c make kore

kore: $(S_OBJS)
	$(CC) $(CFLAGS) $(S_OBJS) $(LDFLAGS) -o $(BIN)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(BIN)
