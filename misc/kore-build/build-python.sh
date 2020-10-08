#!/bin/sh

set -e
set -x

. ./env.sh

if [ $# -ne 1 ]; then
	echo "Usage: build-python.sh [release]"
	exit 1
fi

NAME=Python-$1

fetch "https://www.python.org/ftp/python/$1/$NAME.tgz" $NAME

default_build $NAME
