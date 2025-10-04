from pwn import *

e = ELF("dead_drop_1")

libc = ELF("./libc.so.6")

