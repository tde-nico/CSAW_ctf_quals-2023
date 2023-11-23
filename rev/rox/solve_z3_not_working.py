from z3 import *
from data import data


LEN = 74

blob = "?B8_zWqtfDG2=\x16c\x1F\x12\x1A\x12\\*\x03d\x1C\x15@\x01?L\x02:0\x1D|iM\x19_H^ \x03\x17\tRkLeoH\x06[+(@.N\v\x1610V!n-0K\x1C\x10\x04?\x18A4"
final_flag = "flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}"

blob = list(blob)
final_flag = list(final_flag)

flag = [BitVec(f"char_{i}", 8) for i in range(LEN)]

data_size = len(data)
D = Array('D', BitVecSort(8), BitVecSort(8))
for i, el in enumerate(data):
	D = Store(D, i, el)


s = Solver()



for i in range(LEN):
	s.add(And(flag[i] >= 0x21, flag[i] <= 0x7e))



for i in range(LEN):
	blob[i] = BitVecVal(ord(blob[i]), 8) ^ flag[i]



for j in range(LEN):
	data_select = Select(D, (10 * j + 12) % data_size)
	data_xor = data_select + flag[j % LEN]
	data_xor = blob[j] ^ Select(D, data_xor % data_size)
	blob[j] = data_xor




for k in range(5, LEN):
	for l in range(300): 
		xor_1 = blob[k] ^ (l * 0x20)
		xor_2 = xor_1 ^ If(blob[k - 5] == 110, BitVecVal(1, 8), BitVecVal(0, 8)) # 'n'
		blob[k] = xor_2



for m in range(LEN):
	s.add(blob[m] == BitVecVal(ord(final_flag[m]), 8))



print('Evaluating...')
while s.check() == sat:
	m = s.model()

	try:
		string = "".join([chr(m[char].as_long()) for char in flag])
		print(string)
	except Exception as e:
		print(e)

	s.add(Or([char != s.model()[char] for char in flag]))


print('UNSAT')
exit()

