#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
from utils import *

passed = True
reason = 'OK'
scheme, opt = getargs(__file__, sys.argv, ['host', 'path', 'method'])

if opt['path'][0] != '/': opt['path'][0] = '/' + opt['path'][0]

try:
    r = requests.request(opt['method'], f"{scheme}://{opt['host']}{opt['path']}", verify=False, allow_redirects=False)
except Exception as e:
    passed = False
    reason = str(e)
    output(__file__, passed, reason)
    sys.exit(-2)

if r.status_code != 501:
    passed, reason = False, "Status code != 501"

output(__file__, passed, reason, f"({opt['method']} {opt['path']} = 501) ")

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
