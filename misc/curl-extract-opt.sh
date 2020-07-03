#!/bin/sh

if [ $# -ne 1 ]; then
	echo "Usage: curl-extract-opt.sh /path/to/include/curl"
	exit 1
fi

if [ ! -d $1 ]; then
	echo "given argument is not a directory"
	exit 1
fi

if [ ! -f "$1/curl.h" ]; then
	echo "$1 does not contain curl.h"
	exit 1
fi

if [ ! -f "$1/curlver.h" ]; then
	echo "$1 does not contain curlver.h"
fi

version=`egrep "#define LIBCURL_VERSION " "$1/curlver.h" | awk '{ print $3 }' | sed s/\"//g`

echo "/* Auto generated on `date` from $version */"

cat << __EOF

struct {
	const char	*name;
	int		value;
	PyObject	*(*cb)(struct pycurl_handle *, int, PyObject *);
} py_curlopt[] = {
__EOF

egrep "^.*CURLOPT\(.*\),$" "$1/curl.h" | \
    cut -d'(' -f 2 | cut -d ')' -f 1 | sed 's/,/ /g' | \
    sed 's/CURLOPTTYPE_OBJECTPOINT/NULL/g' | \
    sed 's/CURLOPTTYPE_STRINGPOINT/pycurl_handle_setopt_string/g' | \
    sed 's/CURLOPTTYPE_LONG/pycurl_handle_setopt_long/g' | \
    sed 's/CURLOPTTYPE_SLISTPOINT/pycurl_handle_setopt_slist/g' | \
    sed 's/CURLOPTTYPE_FUNCTIONPOINT/NULL/g' | \
    sed 's/CURLOPTTYPE_OFF_T/NULL/g' | \
    sed 's/CURLOPTTYPE_BLOB/NULL/g' | \
    awk '{ printf "\t{ \"%s\", %s, %s },\n", $1, $3, $2 } '

echo "\t{ NULL, 0, 0 }"
echo "};"
