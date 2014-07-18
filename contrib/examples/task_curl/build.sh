#!/bin/sh
#
# Copyright (c) 2013 Joris Vink <joris@coders.se>
#
# Kore module build script, use this as a base for building
# your own modules for kore.

# The name of the module you will be building
MODULE=task_curl.so

# The directory containing your module source.
SOURCE_DIR=.

# Compiler settings.
CC=gcc
CFLAGS="-I. -I/usr/local/include -Wall -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wshadow \
	-Wpointer-arith -Wcast-qual -Wsign-compare -g"

LDFLAGS="-L/usr/local/lib -shared -lcurl"

MODULE_BUILD_DATE=$(date +"%Y-%m-%d %H:%M:%S")

### Begin building ####
echo "Building module ${MODULE}..."
rm -f ${MODULE}

if [ ! -d .objs ]; then
	mkdir .objs;
fi
rm -f .objs/*

for src in `find ${SOURCE_DIR} -type f -name \*.c`; do
	base=`basename $src`;
	${CC} ${CFLAGS} -fPIC -c $src -o .objs/${base}.o
	if [ $? -ne 0 ]; then
		echo "Build error, check above messages for clues.";
		exit 1;
	fi
done

${CC} ${LDFLAGS} `find .objs -name \*.o -type f` -o ${MODULE}
echo "Building completed!"

rm -rf .objs
