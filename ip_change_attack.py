import requests
import binascii

original_cookie = eval("b'118c28b01a67c44390555c3bfbb24280acb1c774922aa8f2efdd76c623526c3a3e1e9a8ac9032bdbccae7d4abc4dd0fd'")
b_cookie = bytearray(binascii.a2b_hex(original_cookie))
b_cookie[0] = b_cookie[0] ^ b_cookie[16] ^ ord(b'\x84')
b_cookie[1] = b_cookie[1] ^ b_cookie[17] ^ ord(b'\x47')
b_cookie[2] = b_cookie[2] ^ b_cookie[18] ^ ord(b'\x7a')
b_cookie[3] = b_cookie[3] ^ b_cookie[19] ^ ord(b'\x06')

new_cookie = binascii.b2a_hex(b_cookie)
print(new_cookie)
#original_cookie = eval("b'ae6b54331f7a4015d0ad8dab98bc0772f3420d0bf319982f7f20e7e674e70d85d37e9fcfae288b18afb1f8b0d87e0b3d'")

url = "http://52.4.146.190:8080/"
cookies = {
    'topsecret': str(new_cookie),
    }
response = requests.get(url, cookies=cookies).text
print(response)
