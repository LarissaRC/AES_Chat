
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
import base64

# Função para cifrar uma mensagem

def encrypt_message(data, key):

    # Cria um objeto de cifra AES no modo EAX
    cipher = AES.new(key, AES.MODE_EAX)

    # Obtém o nonce e o tag
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce

    # Converte a mensagem cifrada, o nonce e o tag para Base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode()
    nonce_base64 = base64.b64encode(nonce).decode()
    tag_base64 = base64.b64encode(tag).decode()

    return ciphertext_base64, nonce_base64, tag_base64, ciphertext

# Função para decifrar uma mensagem

def decrypt_message(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    return data.decode('utf-8')