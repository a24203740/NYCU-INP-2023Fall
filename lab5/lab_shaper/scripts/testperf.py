#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
from testutil import *

idx   = [ i         for i in range(10) ]
delay = [ (i+1)*2   for i in range(10) ]
bw    = [ (i+1)*100 for i in range(10) ]
random.shuffle(idx)

for _ in range(3): tc_clear()
for i in idx:
    (d, b) = (delay[i], bw[i])
    print('{}: delay = {:<16s}; bw = {}'.format(
        yellow('#'*16 + ' CONFIG'), green(f'{d}ms'), green(f'{b}Mbit')))
    tc_clear()
    tc_config(d, b)
    tc_run('qdisc show')
    print(cyan('#' * 16))
    shell('iperf3 -c localhost -p 9997')
    shell('sleep 2')
print(cyan('## Done.'))

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
