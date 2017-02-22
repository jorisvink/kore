# kodev Makefile

CC?=gcc
PREFIX?=/usr/local
OBJDIR?=obj
KODEV=kodev
INSTALL_DIR=$(PREFIX)/bin

S_SRC=	../src/cli.c

CFLAGS+=-Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -std=c99 -pedantic
CFLAGS+=-DPREFIX='"$(PREFIX)"'
LDFLAGS=-lcrypto

ifneq ("$(NOOPT)", "")
	CFLAGS+=-O0
else
	CFLAGS+=-O2
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-I/opt/local/include/ -I/usr/local/opt/openssl/include
	LDFLAGS+=-L/opt/local/lib -L/usr/local/opt/openssl/lib
else ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1
endif

S_OBJS=	$(S_SRC:../src/%.c=$(OBJDIR)/%.o)

$(KODEV): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(KODEV)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install: $(KODEV)
	mkdir -p $(INSTALL_DIR)
	install -m 555 $(KODEV) $(INSTALL_DIR)/$(KODEV)

uninstall:
	rm -f $(INSTALL_DIR)/$(KODEV)

$(OBJDIR)/%.o: ../src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	find . -type f -name \*.o -exec rm {} \;
	rm -rf $(KODEV) $(OBJDIR)

.PHONY: all clean
