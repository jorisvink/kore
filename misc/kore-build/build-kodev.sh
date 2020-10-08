#!/bin/sh

set -e

. /home/build/env.sh

if [ $# -ne 4 ]; then
	echo "Usage: build-kore.sh [openssl] [python] [curl] [nghttp2]"
	exit 1
fi

export PATH=$FAKEROOT/Python-$2/bin:$FAKEROOT/curl-$3/bin:$PATH
export OPENSSL_PATH=$FAKEROOT/openssl-$1

kodev clean
kodev build
