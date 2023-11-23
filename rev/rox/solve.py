from data import data

LEN = 74


blob = "?B8_zWqtfDG2=\x16c\x1F\x12\x1A\x12\\*\x03d\x1C\x15@\x01?L\x02:0\x1D|iM\x19_H^ \x03\x17\tRkLeoH\x06[+(@.N\v\x1610V!n-0K\x1C\x10\x04?\x18A4"
final_flag = (
	"flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}"
)

flag = "aN0ther_HeRRing_or_iS_tHis_iT"

for idx in range(5, 74):

	b1_s = ord(blob[idx])
	f1 = ord(final_flag[idx])
	print(f"IDX {idx}")
	for c in range(0x20, 0x7F + 1):
		b1 = b1_s ^ c
		addr = 10 * idx + 12
		data_loc = data[addr]
		data_shifted = data_loc + c
		data_shifted = b1 ^ data[data_shifted]

		blobidx = data_shifted

		for l in range(300):
			char_k = blobidx
			xor_1 = char_k ^ (l * 0x20)
			xor_2 = (
				xor_1  # ^ If(blob[k - 5] == 110, BitVecVal(1, 16), BitVecVal(0, 16))
			)
			blobidx = xor_2

		if blobidx == f1:
			print(chr(c), end=" ")
	print("\n")