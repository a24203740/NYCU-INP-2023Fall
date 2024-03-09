#!/usr/bin/env python3

from pwn import *
import json
import sys

IP = "localhost"
PORT = 8888

conns = []

SERVER = ""
PORT = ""
CASE = ""

def build_new_connection():
    conn = remote(IP, PORT)
    conn.recvuntil(b"Welcome to the Chat server.")
    conn.recvuntil(b"*********************************\n")
    return conn

def close_all_connections():
    for conn in conns:
        conn.close() 

def save_result(file, output):
    if len(output)==0:
        return
    path = file + '.txt'
    f = open("./" + CASE + "/" + path, 'w')
    for i in range(len(output)):
        f.write(output[i].decode())
    f.close()

def run_test():
    conns = []
    result = []
    for i in range(1001):
        print(i)
        conns.append(build_new_connection())
        conns[i].sendline("register " + str(i) + " " + str(i))
        # print(conns[i].recvline())
        conns[i].sendline("login " + str(i) + " " + str(i))
        conns[i].recvline()
        result.append(conns[i].recvline())

    save_result("client1000", result)


if __name__ == "__main__":
    if len(sys.argv) < 4 or len(sys.argv) > 4:
        print("#Usage: python3 checker.py [your server executable] [port] [case] ")
    else:
        SERVER = sys.argv[1]
        PORT = sys.argv[2]
        CASE = sys.argv[3]
        
        #print(SERVER)
        server = process([SERVER, str(PORT)])
        
        run_test()

        close_all_connections()

        server.interactive()
        #server.close()
        

