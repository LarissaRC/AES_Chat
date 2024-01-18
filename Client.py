import socket
import threading
import json
import sqlite3
import base64
from colorama import Fore, init
from DiffieHellman import DiffieHellman
from AES import encrypt_message, decrypt_message
import hashlib

# Inicializa o colorama
init(autoreset=True)

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def derive_key_from_int(value):
    # Converte o valor inteiro para bytes
    value_bytes = int_to_bytes(value)

    # Usa SHA-256 para derivar uma chave de 256 bits (32 bytes)
    key = hashlib.sha256(value_bytes).digest()

    return key

def genetare_AES_key(df_secret_value):
    AES_key = derive_key_from_int(df_secret_value)
    return AES_key

def sender_diffie_hellman(client_socket, sender_name, receiver_name):
    dh = DiffieHellman.DH()

    #print("Início do processo Diffie-Hellman (Sender)")

    publicSecret = dh.calcPublicSecret()

    clients_shared_keys[receiver_name] = {
        "base": dh.base,
        "prime": dh.sharedPrime,
        "publicSecretReceived": '',
        "publicSecret": publicSecret,
        "secretValue": '',
        "AES_key": ''
    }

    message = {
        "base": dh.base,
        "prime": dh.sharedPrime,
        "publicSecret": publicSecret,
        "senderName": sender_name
    }

    message_info = {
        "sender_name": sender_name,
        "recipient_name": receiver_name,
        "message": message
    }
    
    client_socket.send(json.dumps(message_info, ensure_ascii=False).encode())

    # Recebe o valor público gerado pelo cliente
    data = client_socket.recv(1024)
    message_info = json.loads(data.decode())
    clients_shared_keys[receiver_name]["publicSecretReceived"] = message_info.get("message")["publicSecret"]

    # Calculça o valor secreto
    dh.calcSharedSecret(clients_shared_keys[receiver_name]["publicSecretReceived"])
    clients_shared_keys[receiver_name]["secretValue"] = dh.key

    # Gerar chave AES
    AES_key = genetare_AES_key(dh.key)
    clients_shared_keys[receiver_name]["AES_key"] = AES_key

def receiver_diffie_hellman(client_socket, message_info):
    dh = DiffieHellman.DH()

    #print("Início do processo Diffie-Hellman (Receiver)")

    message = message_info.get("message", "")

    dh.base = message["base"]
    dh.sharedPrime = message["prime"]
    publicSecret = message["publicSecret"]

    clients_shared_keys[message["senderName"]] = {
        "base": dh.base,
        "prime": dh.sharedPrime,
        "publicSecretReceived": publicSecret,
        "publicSecret": "",
        "secretValue": '',
        "AES_key": ''
    }

    # Calcular o valor público gerado
    calcedPubSecret = dh.calcPublicSecret()
    clients_shared_keys[message_info["sender_name"]]["publicSecret"] = calcedPubSecret

    # Enviar o valor calculado para o cliente que iniciou o processo diffie-hellman
    message = { "publicSecret": calcedPubSecret }

    new_message_info = {
        "sender_name": message_info.get("recipient_name", "Unknown"),
        "recipient_name": message_info.get("sender_name", ""),
        "message": message
    }
    
    client_socket.send(json.dumps(new_message_info, ensure_ascii=False).encode())

    # Calcular valor secreto
    dh.calcSharedSecret(publicSecret)
    clients_shared_keys[message_info["sender_name"]]["secretValue"] = dh.key

    # Gerar chave AES
    AES_key = genetare_AES_key(dh.key)
    clients_shared_keys[message_info["sender_name"]]["AES_key"] = AES_key

def show_DF():
    print("Valores DF gerados:")
    for client_data in clients_shared_keys:
        print(f"{Fore.GREEN}- {client_data}{Fore.RESET} {clients_shared_keys[client_data]['secretValue']}")

def show_AES_key():
    print("Chaves AES geradas:")
    for client_data in clients_shared_keys:
        print(f"{Fore.GREEN}- {client_data}{Fore.RESET} {clients_shared_keys[client_data]['AES_key']}")

def receive_messages(client_socket):
    while True:
        try:
            # Recebe mensagens do servidor e imprime na tela
            data = client_socket.recv(1024)
            if not data:
                print("[+] Desconectado do servidor.")
                break

            message_info = json.loads(data.decode())

            # Processa a mensagem recebida
            sender_name = message_info.get("sender_name", "Unknown")
            recipient_name = message_info.get("recipient_name", "")
            message = message_info.get("message", "")

            # Verifica se é de fato uma mensagem ou se é uma solicitação de Diffie-Hellman
            if 'nonce' not in message_info:
                receiver_diffie_hellman(client, message_info)
            else:
                encrypted_message_base64 = message_info.get("message", "")
                nonce_base64 = message_info.get("nonce", "")
                tag_base64 = message_info.get("tag", "")

                # Converte a mensagem Base64 de volta para bytes
                encrypted_message = base64.b64decode(encrypted_message_base64)
                nonce = base64.b64decode(nonce_base64)
                tag = base64.b64decode(tag_base64)
                
                # Descriptografa a mensagem
                message = decrypt_message(encrypted_message, clients_shared_keys[sender_name]["AES_key"], nonce, tag)

                # Imprime a mensagem recebida
                print(f"{Fore.YELLOW}[{sender_name}]:{Fore.RESET} {message}")
        except Exception as e:
            print(f"Erro ao receber mensagens: {Fore.RED}{str(e)}{Fore.RESET}")
            break

def authenticate_and_start_client():
    # Autenticação do cliente
    name = input("[+] Informe seu username: ")

    auth_info = {
        "name": name,
    }

    client.send(json.dumps(auth_info).encode())
    print("[+] Aguardando autenticação...")

    authentication_response = client.recv(1024).decode()

    if authentication_response != "authenticated":
        print(f"{Fore.RED}[+] Falha na autenticação. Encerrando o cliente.{Fore.RESET}")
        client.close()
        exit()

    print(f"[+] {Fore.GREEN}Autenticação bem-sucedida.{Fore.RESET} Conectado ao servidor.")

    data = client.recv(1024).decode()
    clients_online = json.loads(data)

    for client_online in clients_online:
        if clients_online[client_online] != name:
            #print("- " + clients_online[client_online])
            sender_diffie_hellman(client, name, clients_online[client_online])

    while True:
        # Inicia uma thread para receber mensagens do servidor
        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.start()

        # Informa o nome do destinatário desejado
        recipient_name = input("[+] Informe o nome do destinatário: ")

        if recipient_name.lower() == 'exit':
            print("[+] Cliente encerrado.")
            client.close()
            exit()
        elif recipient_name.lower() == 'new':
            # Reinicia a iteração para iniciar uma nova conversa
            continue
        elif recipient_name.lower() == 'df':
            # Mostrar os valores gerados na troca diffie-hellman
            show_DF()
            continue
        elif recipient_name.lower() == 'keys':
            # Mostrar as chaves AES geradas
            show_AES_key()
            continue

        # Envia mensagens para o servidor
        while True:
            try:
                message = input()
                if message.lower() == 'exit':
                    print("[+] Saindo da conversa.")
                    break
                elif message.lower() == 'new':
                    # Encerra a conversa atual e reinicia a iteração para iniciar uma nova conversa
                    break

                encrypted_message, nonce, tag = encrypt_message(message.encode('utf-8'), clients_shared_keys[recipient_name]["AES_key"])
                message_info = {"sender_name": name, "recipient_name": recipient_name,
                                "message": encrypted_message, "nonce": nonce, "tag": tag}
                print(message_info)
                client.send(json.dumps(message_info, ensure_ascii=False).encode())
            except KeyboardInterrupt:
                print("[+] Cliente encerrado.")
                client.close()
                exit()

if __name__ == "__main__":
    host = '127.0.0.1'
    port = 5555

    clients_shared_keys = {}

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    authenticate_and_start_client()