from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

data = b'secret data'
print(data)

key = get_random_bytes(32)
print(key)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(ciphertext)
nonce = cipher.nonce

cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)