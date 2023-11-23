#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
from utils import *

passed = True
reason = 'OK'
scheme, opt = getargs(__file__, sys.argv, ['host', 'path', 'code'])

if opt['path'][0] != '/': opt['path'][0] = '/' + opt['path'][0]

try:
    r = requests.get(f"{scheme}://{opt['host']}{opt['path']}", verify=False, allow_redirects=False)
except Exception as e:
    passed = False
    reason = str(e)
    output(__file__, passed, reason)
    sys.exit(-2)

if r.status_code != int(opt['code']):
    passed, reason = False, "Status code != " + opt['code']

output(__file__, passed, reason, f"({opt['path']} = {opt['code']}) ")

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
