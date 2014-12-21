# Kore Makefile

CC?=gcc
PREFIX?=/usr/local
KORE=kore
KORE_TEST=kore-test
TESTS=kore-test
LIBNAME=libkore
INSTALL_DIR=$(PREFIX)/bin
INCLUDE_DIR=$(PREFIX)/include/kore

S_SRC=	src/kore.c src/buf.c src/cli.c src/config.c src/connection.c \
	src/domain.c src/mem.c src/msg.c src/module.c src/net.c \
	src/pool.c src/timer.c src/utils.c src/worker.c
S_OBJS=	$(S_SRC:.c=.o)
LIB_OBJS=	$(S_SRC:.c=.o)

TEST_SRC=	tests/test.c tests/test-buf.c tests/test-utils.c tests/unit.c
TEST_OBJS=	$(TEST_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
CFLAGS+=-DPREFIX='"$(PREFIX)"'
LDFLAGS=-rdynamic -lssl -lcrypto

ifneq ("$(DEBUG)", "")
	CFLAGS+=-DKORE_DEBUG
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

STLIBSUFFIX=a
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)
STLIB_MAKE_CMD=ar rcs $(STLIBNAME)

$(STLIBNAME): $(LIB_OBJS)
	$(STLIB_MAKE_CMD) $(LIB_OBJS)

TEST_LIBNAME=$(LIBNAME)-test.$(STLIBSUFFIX)
TEST_LIB_MAKE_CMD=ar rcs $(TEST_LIBNAME)

$(TEST_LIBNAME): $(TEST_OBJS) $(STLIBNAME)
	$(TEST_LIB_MAKE_CMD) $(TEST_OBJS)
	mv $(TEST_LIBNAME) tests/

$(KORE): $(S_OBJS)
	$(CC) $(S_OBJS) -o $(KORE) $(LDFLAGS)

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
	rm -f $(STLIBNAME)
	find tests/ -type f -name \*.o -exec rm {} \;
	rm -f tests/$(TEST_LIBNAME)
	rm -f tests/$(TESTS)
	rm -f $(KORE_TEST)

$(KORE_TEST): CFLAGS += -DKORE_TEST -DKORE_PEDANTIC_MALLOC
$(KORE_TEST): $(TEST_LIBNAME)
	$(CC) $(CFLAGS) -o $@ tests/$< $(STLIBNAME) $(LDFLAGS)
	./$(KORE_TEST)

check: $(KORE_TEST)

valgrind:
	valgrind --leak-check=full ./$(KORE_TEST)

.PHONY: all clean
