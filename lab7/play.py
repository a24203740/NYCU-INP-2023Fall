#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import zlib
import base64 as b64
from solpow import *
from pwn import *

def load_payload(path):
    payload = b''
    with open(path, 'rb') as f: payload = f.read()
    payload = b64.b64encode(zlib.compress(payload))
    print(f'## {path}: {len(payload)} bytes to send')
    return payload

if __name__ == "__main__":
    payload = b''
    if len(sys.argv) > 1:
        payload = load_payload(sys.argv[1])

    host = os.getenv('HOST')
    if host == None or host.strip() == '':
        r = remote('inp.zoolab.org', 10850);
    else:
        r = remote(host, 10850);

    solve_pow(r);
    r.sendlineafter(b'executable: ', payload)
    r.interactive();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
