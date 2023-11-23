#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

green = '\x1b[1;32m'
red =  '\x1b[1;31m'
normal = '\x1b[m'

def getargs(module, argv, opt):
    nopt = len(opt)
    optstr = ' '.join(opt)
    scheme = "https" if "https" in sys.argv[(nopt+1):] else "http"
    if len(argv) < len(opt)+1:
        print(f'usage: {module} {optstr} [scheme]')
        sys.exit(-1)
    popt = {}
    for i in range(len(opt)): popt[opt[i]] = argv[i+1]
    return scheme, popt

def output(module, passed, reason, remark = ''):
    global green, red, normal
    remark = remark.ljust(40, '.')
    dot = '.' if passed else '' 
    color = green if passed else red
    passed = f'{color}{passed}{normal}'
    print(f'# {module} {remark}{dot} [{passed}] {reason}')

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
