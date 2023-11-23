#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
from utils import *

passed = True
reason = 'OK'
scheme, opt = getargs(__file__, sys.argv, ['host', 'path', 'realpath'])

if opt['path'][0] != '/': opt['path'][0] = '/' + opt['path'][0]

try:
    r = requests.get(f"{scheme}://{opt['host']}{opt['path']}", verify=False, allow_redirects=False)
except Exception as e:
    passed = False
    reason = str(e)
    output(__file__, passed, reason)
    sys.exit(-2)

payload = b''
with open(opt['realpath'], 'rb') as f: payload = f.read()

if r.status_code != 200:
    passed, reason = False, "Status code != 200"
elif 'Content-Type' not in r.headers:
    passed, reason = False, "Header check failed"
elif r.content != payload:
    passed, reason = False, "Content does not match"

output(__file__, passed, reason, f"({opt['path']}) ")

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
