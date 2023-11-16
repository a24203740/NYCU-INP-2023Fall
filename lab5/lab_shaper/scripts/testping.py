#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
from testutil import *

delay = [ (i+1)*5  for i in range(10) ]
bw    = [ (i+1)*100 for i in range(10) ]
random.shuffle(delay)
random.shuffle(bw)

for _ in range(3): tc_clear()
for (d, b) in zip(delay, bw):
    print('{}: delay = {:<16s}; bw = {}'.format(
        yellow('#'*16 + ' CONFIG'), green(f'{d}ms'), green(f'{b}Mbit')))
    tc_clear()
    tc_config(d, b)
    tc_run('qdisc show')
    print(cyan('#' * 16))
    shell('ping -c 3 localhost 2>/dev/null | grep ttl')
print(cyan('## Done.'))

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
