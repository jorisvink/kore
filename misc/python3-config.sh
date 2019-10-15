#!/bin/sh

if [ $# -ne 1 ]; then
	echo "python3-flags.sh [--ldflags|--includes]"
	exit 1
fi

python3-config $1 --embed > /dev/null 2>&1

if [ $? -eq 0 ]; then
	python3-config $1 --embed
else
	python3-config $1
fi
