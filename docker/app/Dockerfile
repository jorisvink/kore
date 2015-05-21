FROM kore/build
MAINTAINER Thordur I. Bjornsson <thorduri@secnorth.net>

ENV KORE_VERSION 1.2.3

WORKDIR /kore

ADD https://github.com/jorisvink/kore/archive/$KORE_VERSION-release.tar.gz /kore/
RUN tar -zxf $KORE_VERSION-release.tar.gz && cd kore-$KORE_VERSION-release/ && \
    make clean && make && make install && \
    rm -rf /kore/$KORE_VERSION-release.tar.gz /kore/kore-$KORE_VERSION-release

EXPOSE 443 8888
ENTRYPOINT ["kore", "run"]
