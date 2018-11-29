#
# Build all relevant examples.
# This only exists to quickly test building all examples.
#

CURDIR=		$(shell pwd)
KODEV=		../kodev/kodev

EXAMPLES=	cookies \
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
		python \
		python-async \
		python-echo \
		python-pgsql \
		sse \
		tasks \
		tls-proxy \
		upload \
		video_stream \
		websocket \

all: $(KODEV)
	@for example in $(EXAMPLES); do \
		cd $$example; \
		../$(KODEV) clean && ../$(KODEV) build || exit 1; \
		cd $(CURDIR); \
	done

$(KODEV):
	$(MAKE) -C $(KORE_ROOT)/kodev
