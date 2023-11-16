#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import random
import subprocess
from testutil import *

delay = [ (i+1)*10 + random.randint(-5, 5)   for i in range(10) ]
bw    = [ (i+1)*50 + random.randint(-30, 30) for i in range(10) ]
random.shuffle(delay)
random.shuffle(bw)

shell('killall server', stderr=subprocess.DEVNULL)
shell('sleep 1')
shell('chroot --userspec=1000:1000 /dist /server &')

delta_d = 0
delta_b = 0
pat = re.compile(r'^# RESULTS: delay = ([0-9\.]+) ms, bandwidth = ([0-9\.]+) Mbps')

for _ in range(3): tc_clear()
for (d, b) in zip(delay, bw):
    print('{}: delay = {:<16s}; bw = {}'.format(
        yellow('## CONFIG'), green(f'{d}ms'), green(f'{b}Mbit')))
    tc_clear()
    tc_config(d, b)
    tc_run('qdisc show')
    print(cyan('#' * 16))
    r = shell('timeout -k 1 20 chroot --userspec=1000:1000 /dist /client', stdout=subprocess.PIPE)
    msg = r.stdout.decode().strip()
    print(red('>>>'), msg)
    m = pat.search(msg)
    if m == None:
        delta_d += 1000
        delta_b += 1000
        continue
    dd = float(m.group(1)) - d
    db = float(m.group(2)) - b
    delta_d += abs(dd)
    delta_b += abs(db)
    print(red('>>>'), 'Delta D = {:.3f} ms, Delta BW = {:.3f} Mbps'.format(dd, db))
print(cyan('## Done.'))

print('## Summary: delta delay = {:.3f} ms, delta bw = {:.3f} Mbps'.format(
        delta_d, delta_b))

# run a shell for further inspection
shell('/bin/bash')

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
