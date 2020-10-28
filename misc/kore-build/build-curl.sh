#!/bin/sh

set -e

. ./env.sh

if [ $# -ne 3 ]; then
	echo "Usage: build-curl.sh [release] [openssl] [nghttp2]"
	exit 1
fi

export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$FAKEROOT/openssl-$2/lib/pkgconfig:$FAKEROOT/nghttp2-$3/lib/pkgconfig"

NAME=curl-$1

fetch "https://curl.haxx.se/download/$NAME.tar.gz" $NAME

default_build $NAME --enable-shared=no
