#
# Build all relevant examples.
# This only exists to quickly test building all examples.
#
# Kore must be built with PGSQL=1 TASKS=1 PYTHON=1 to get all
# of the below examples to build correctly.
#
# Don't run this directly, run it from the top level as
# $ make releng-build-examples
#

CURDIR=		$(shell pwd)
KODEV=		/tmp/kore_releng/bin/kodev

EXAMPLES=	async-curl \
		cookies \
		cpp \
		generic \
		headers \
		integers \
		memtag \
		messaging \
		nohttp \
		parameters \
		pgsql \
		pgsql-sync \
		pipe_task \
		sse \
		tasks \
		tls-proxy \
		upload \
		video_stream \
		websocket \

all:
	@for example in $(EXAMPLES); do \
		cd $$example; \
		$(KODEV) clean && $(KODEV) build || exit 1; \
		cd $(CURDIR); \
	done

clean:
	@for example in $(EXAMPLES); do \
		cd $$example; \
		$(KODEV) clean; \
		cd $(CURDIR); \
	done
