#
# You probably want to change the include and library
# paths before compiling.
#

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
CFLAGS+=-I../../openssl-1.0.1i/include

all:
	gcc $(CFLAGS) -c client.c -o client.o
	gcc -L../../openssl-1.0.1i/ client.o -o client -lcrypto -lssl

clean:
	rm -f client *.o
