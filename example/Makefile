# Example Kore module

.SUFFIXES:	.html .css

CC=gcc
BIN=example.module

HTML=	html/index.html html/profile.html
H_SRCS=	$(HTML:.html=.c)

CSS=	css/style.css
C_SRCS=	$(CSS:.css=.c)

S_SRC=	src/example.c $(H_SRCS) $(C_SRCS)
S_OBJS=	$(S_SRC:.c=.o)

CFLAGS+=-I. -I../includes
CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -g
LDFLAGS+=-shared

all:
	make clean
	make example.module

example.module: html_inject $(H_SRCS) $(C_SRCS) $(S_OBJS)
	$(CC) $(LDFLAGS) $(S_OBJS) -o $(BIN)
	make clean_o

html_inject: tools/html_inject.c
	$(CC) $(CFLAGS) tools/html_inject.c -o tools/html_inject

.html.c:
	tools/html_inject $< `basename $<` > $@

.css.c:
	tools/html_inject $< `basename $<` > $@

.c.o: $<
	$(CC) -fPIC $(CFLAGS) -c $< -o $@

clean:
	make clean_o
	rm -f css/*.c html/*.c tools/html_inject $(BIN)
	rm -f static.h

clean_o:
	rm -f css/*.o html/*.o src/*.o
