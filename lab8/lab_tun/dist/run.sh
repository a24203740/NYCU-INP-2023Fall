#!/bin/sh

PORT=8888

if [ -z "$1" ]; then
	echo "usage: $0 {client|server}"
	exit 1
fi

## create tun device
mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then mknod -m 0666 /dev/net/tun c 10 200; fi

## drop gre packets
iptables -F
iptables -I INPUT   1 -p gre -j DROP
iptables -I OUTPUT  1 -p gre -j DROP
iptables -I FORWARD 1 -p gre -j DROP

TUNVPN=
if [ -x ./tunvpn ]; then
   TUNVPN=./tunvpn
elif [ -x /dist/tunvpn ]; then	
   TUNVPN=/dist/tunvpn
else
	echo "## tunvpn executable not found"
fi

## invoke the iperf3 server
iperf3 -s &

case $1 in
server)
	$TUNVPN server $PORT &
	;;
client)
	$TUNVPN client server $PORT &
	;;
*)
	echo "## unknown profile"
	;;
esac

exit 0
