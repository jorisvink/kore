#!/bin/sh

if [ $# -ne 1 ]; then
	echo "python3-flags.sh [--ldflags|--includes]"
	exit 1
fi

if [ ! -z "$PYTHON_CONFIG" ]; then
	BIN=$PYTHON_CONFIG
else
	BIN=python3-config
fi

$BIN $1 --embed > /dev/null 2>&1

if [ $? -eq 0 ]; then
	$BIN $1 --embed
else
	$BIN $1
fi
