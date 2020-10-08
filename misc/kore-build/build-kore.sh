#!/bin/sh

set -e

if [ $# -ne 4 ]; then
	echo "Usage: build-kore.sh [openssl] [python] [curl] [nghttp2]"
	exit 1
fi

# Set ROOT based on the versions given.
VERSION=kore_ossl-$1_python-$2_curl-$3_nghttp2-$4
ROOT=`pwd`/$VERSION

# Pull in the rest of the functions.
. ./helpers.sh

OPENSSL=openssl-$1
PYTHON=Python-$2
CURL=curl-$3
NGHTTP2=nghttp2-$4

# Build OpenSSL
echo "Building $OPENSSL"
fetch "https://www.openssl.org/source/$OPENSSL.tar.gz" $OPENSSL
build $OPENSSL ./config no-shared --prefix=$FAKEROOT/$OPENSSL

# Build Python
echo "Building $PYTHON"
fetch "https://www.python.org/ftp/python/$2/$PYTHON.tgz" $PYTHON
default_build $PYTHON

# Build nghttp2
echo "Building $NGHTTP2"
fetch \
    "https://github.com/nghttp2/nghttp2/releases/download/v$4/$NGHTTP2.tar.gz" \
    $NGHTTP2

default_build $NGHTTP2 --enable-lib-only --prefix=$FAKEROOT/$NGHTTP2 \
    --enable-shared=no

# Build curl
echo "Building $CURL"
export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$FAKEROOT/$OPENSSL/lib/pkgconfig:$FAKEROOT/$NGHTTP2/lib/pkgconfig"

fetch "https://curl.haxx.se/download/$CURL.tar.gz" $CURL
default_build $CURL --enable-shared=no

# Now we can build kore.
unset PKG_CONFIG
unset PKG_CONFIG_PATH

export PATH=$FAKEROOT/bin:$PATH
export OPENSSL_PATH=$FAKEROOT/$OPENSSL

cd $ROOT

if [ ! -d kore ]; then
	git clone https://git.kore.io/kore.git
fi

pushd kore
make clean
LDFLAGS=-L$FAKEROOT/$NGHTTP2/lib make PYTHON=1 CURL=1 ACME=1

mv kore $ROOT/kore.bin
popd
