FROM alpine:3

RUN apk update && apk upgrade && apk add tini coreutils make gcc g++ bearssl-dev mbedtls-dev gnutls-dev openssl-dev
RUN apk add openssl-libs-static

ENTRYPOINT [ "/sbin/tini", "--" ]
CMD [ "/bin/sleep", "infinity" ]
