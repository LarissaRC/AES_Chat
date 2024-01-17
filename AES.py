
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import base64

def encrypt_message(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce

    # Converte a mensagem cifrada e o nonce para Base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode()
    nonce_base64 = base64.b64encode(nonce).decode()
    tag_base64 = base64.b64encode(tag).decode()

    return ciphertext_base64, nonce_base64, tag_base64

def decrypt_message(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    return data.decode('utf-8')