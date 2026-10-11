import gdb
gdb.execute("set pagination off")
gdb.execute("break *main+0x11")   # after setup, at menu loop
gdb.execute("run")
# now in main loop after setup
gdb.execute("printf \"heap base region:\\n\"")
gdb.execute("info proc mappings")
gdb.execute("x/40gx $reinterpret_cast<long*>(0)")
