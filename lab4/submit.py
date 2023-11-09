#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import zlib
import base64 as b64
from pwn import *

if len(sys.argv) < 2:
    print(f'usage: {sys.argv[0]} /path/to/static/executable')
    sys.exit(-1)

payload = b''
with open(sys.argv[1], 'rb') as f: payload = f.read()
print(f'# {len(payload)} bytes read')

payload = b64.b64encode(zlib.compress(payload))
print(f'# {len(payload)} bytes to sent')

r = remote('inp.zoolab.org', 10315)
r.sendlineafter(b'executable: ', payload)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
