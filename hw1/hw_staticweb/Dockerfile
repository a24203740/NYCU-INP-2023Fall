FROM alpine:3

RUN apk update && apk upgrade && apk add tini coreutils lighttpd wget curl wrk py3-requests 

ENTRYPOINT [ "/sbin/tini", "--" ]
CMD [ "/bin/sleep", "infinity" ]
