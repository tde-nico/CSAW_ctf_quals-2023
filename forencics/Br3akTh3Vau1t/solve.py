import base64


decimal_number = 5346815611816381158830026000575759913046890410767282609674124748425112753245783703275530777684185849448083


'''
decimal_number = 15295865526991442899

int -> hex
15295865526991442899 -> d445d4a7e477d3d3

d4 45 d4 a7 e4 77 d3 d3

3d 3d 77 4e 7a 4d 54 4d
=  =  w  N  z  M  T  M

M  T  M  z  N  w  =  =
4d 5d 4d 7a 4e 77 3d 3d


base64 -> str
'MTMzNw==' -> '1337'
'''


# bitshift 4 bit for byte
hexadecimal_string = hex(decimal_number)[2:]
reversed_hexadecimal = hexadecimal_string[::-1]
hex_bytes = bytes.fromhex(reversed_hexadecimal)
reversed_hex_bytes = hex_bytes[::-1]

# base 64 decode
flag = base64.b64decode(reversed_hex_bytes)


print(flag.decode())
# csawctf{w@11_ST_1s_n0t_n3ce$$@ry}
