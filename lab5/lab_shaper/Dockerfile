FROM alpine:3

RUN apk update && apk upgrade && apk add tini coreutils bash \
		iptables iproute2 iperf3 python3

ENTRYPOINT [ "/sbin/tini", "--" ]
CMD [ "/bin/sleep", "infinity" ]
