#!/bin/sh

if [ `id -u` != "0" ]; then
	echo you have to run this script with root permission
fi

if [ "$1" = "0" ]; then
	tc qdisc del dev lo root netem 2>/dev/null
	echo cleared
	exit 0
fi

if [ -z "$2" ]; then
	echo usage: $0 [delay] [rate]
	exit 1
fi

tc qdisc del dev lo root netem 2>/dev/null
tc qdisc add dev lo root netem delay "$1" rate "$2" #loss $3

