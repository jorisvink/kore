#!/bin/sh

set -e

. ./env.sh

if [ $# -ne 1 ]; then
	echo "Usage: build-nghttp2.sh [release]"
	exit 1
fi

NAME=nghttp2-$1

fetch "https://github.com/nghttp2/nghttp2/releases/download/v$1/$NAME.tar.gz" $NAME

default_build $NAME --enable-lib-only --prefix=$FAKEROOT/$NAME --enable-shared=no
