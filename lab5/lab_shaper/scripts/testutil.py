#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess

tc = '/sbin/tc'

def shell(cmd = None, **kwargs):
    if cmd == None:
        return subprocess.run('/bin/sh', shell=False, **kwargs)
    if type(cmd) == str:
        return subprocess.run(cmd, shell=True, **kwargs)
    return subprocess.run(cmd, shell=False, **kwargs)

def tc_run(args, **kwargs):
    global tc
    if type(args) == list:
        return shell([tc] + args, **kwargs)
    return shell(f'{tc} {args}'.split(), **kwargs)

def tc_show():
    return tc_run('qdisc show')

def tc_clear():
    return tc_run('qdisc del dev lo root netem', stderr=subprocess.DEVNULL)

def tc_config(d, b):    # delay, bandwidth
    return tc_run(f'qdisc add dev lo root netem delay {d}ms rate {b}Mbit')

def red(m):    return f'\x1b[1;31m{m}\x1b[m'
def green(m):  return f'\x1b[1;32m{m}\x1b[m'
def yellow(m): return f'\x1b[1;33m{m}\x1b[m'
def cyan(m):   return f'\x1b[1;36m{m}\x1b[m'

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
