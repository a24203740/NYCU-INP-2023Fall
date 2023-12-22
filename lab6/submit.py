#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import zlib
import base64 as b64
import solpow
from pwn import *

if len(sys.argv) < 3:
    print(f'usage: [TOKEN=teamtoken] {sys.argv[0]} /path/to/static/server.exe /path/to/static/client.exe [server-ip]')
    sys.exit(-1)

def load_payload(path):
    payload = b''
    with open(path, 'rb') as f: payload = f.read()
    payload = b64.b64encode(zlib.compress(payload))
    print(f'## {path}: {len(payload)} bytes to send')
    return payload

server = load_payload(sys.argv[1])
client = load_payload(sys.argv[2])

r = remote('inp.zoolab.org' if len(sys.argv) < 4 else sys.argv[3], 10560)

solpow.solve_pow(r)

tt = os.environ.get('TOKEN')
r.sendlineafter(b'skip): ', b'' if tt == None else tt.encode())
r.sendlineafter(b'base64: ', server)
r.sendlineafter(b'base64: ', client)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
