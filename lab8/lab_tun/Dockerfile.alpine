FROM alpine:3

RUN apk update && apk upgrade && apk add tini iproute2 iptables procps iperf3 tcpdump bash gcc g++ linux-headers make

ENTRYPOINT [ "/sbin/tini", "--" ]
CMD [ "/bin/sleep", "infinity" ]
