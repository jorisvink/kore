#!/bin/sh

set -e

. ./env.sh

if [ $# -ne 1 ]; then
	echo "Usage: build-openssl.sh [release]"
	exit 1
fi

NAME=openssl-$1

fetch "https://www.openssl.org/source/$NAME.tar.gz" $NAME

build $NAME ./config no-shared --prefix=$FAKEROOT/$NAME
