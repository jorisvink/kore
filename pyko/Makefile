# pyko Makefile

BIN=pyko
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

KODEV?=../kodev/kodev

build:
	$(KODEV) build

clean:
	$(KODEV) clean

install:
	install -m 555 $(BIN) $(INSTALL_DIR)/$(BIN)

uninstall:
	rm -f $(INSTALL_DIR)/$(BIN)
