#!/bin/sh


CERTDIR=cert

rm -rf ${CERTDIR}
mkdir -p ${CERTDIR}

openssl genrsa -des3 -passout pass:pass 2048 > ${CERTDIR}/server.key
openssl req -passin pass:pass -new -key ${CERTDIR}/server.key -x509 -days 356 -out ${CERTDIR}/server.crt << EOF
IO
Kore
Kore
Kore
Kore
Kore
Kore
EOF
openssl rsa -in ${CERTDIR}/server.key -passin pass:pass -out ${CERTDIR}/server.key
