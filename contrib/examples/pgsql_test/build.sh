#!/bin/sh
#
# Kore pgsql test module build directives.
#

MODULE=pgsql_test.module
SOURCE_DIR=.
PGDIR=$(pg_config --includedir)
CC=gcc
CFLAGS="-I. -I/usr/local/includes -I${PGDIR} \
	-Wall -Wstrict-prototypes -Wmissing-prototypes \
	-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual \
	-Wsign-compare -g"

OSNAME=$(uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
if [ "${OSNAME}" = "darwin" ]; then
	LDFLAGS="-dynamiclib -undefined suppress -flat_namespace"
else
	LDFLAGS="-shared"
fi

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
