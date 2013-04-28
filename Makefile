# Kore Makefile

CC=gcc
BIN=kore

S_SRC=	src/kore.c src/utils.c
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-I/usr/local/ssl/include
CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS=-static -Llibs -lssl -lcrypto

light: $(S_OBJS)
	$(CC) $(CFLAGS) $(S_OBJS) $(LDFLAGS) -o $(BIN)

.c.o: $<
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(BIN)
