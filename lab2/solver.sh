#!/bin/bash

wget https://inp.zoolab.org/binflag/challenge?id=110550075 -O ./input/input.bin

./binPacketParser > output/log

FLAG=$(cat "./output/flag");
wget "https://inp.zoolab.org/binflag/verify?v=${FLAG}" -O ./output/result

cat "./output/result"

