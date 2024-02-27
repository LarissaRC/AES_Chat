import socket
import threading
import json
from DiffieHellman import DiffieHellman
from Cryptodome.Protocol.KDF import PBKDF2
from colorama import Fore, init
from BD_creation import fazer_login, cadastrar_cliente, obter_apelidos
from AES import encrypt_message, decrypt_message
import base64

# Inicializa o colorama
init(autoreset=True)

# Dicionário para armazenar as conexões dos clientes e seus nomes
clientes = {}
group_clients = []

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def derive_key_from_int(value):
    # Converte o valor inteiro para bytes
    value_bytes = int_to_bytes(value)

    # Usa SHA-256 para derivar uma chave de 256 bits (32 bytes)
    key = PBKDF2(value_bytes, b'', dkLen=32, count=1000000, prf=None)

    return key

# Geração da chave AES
def genetare_AES_key(df_secret_value):
    AES_key = derive_key_from_int(df_secret_value)
    return AES_key

def send_DF_message(sender_name, recipient_name, message):
    for address, connection_info in clientes.items():
        if connection_info["name"] == recipient_name:

            # Prepara os dados para envio
            message_info = {
                "sender_name": sender_name,
                "recipient_name": recipient_name,
                "message": message
            }

            # Envia a mensagem criptografada
            connection_info["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())

def send_message(sender_name, recipient_name, message, nonce, tag):
    for address, connection_info in clientes.items():
        if connection_info["name"] == recipient_name:

            # Prepara os dados para envio
            message_info = {
                "sender_name": sender_name,
                "recipient_name": recipient_name,
                "message": message,
                "nonce": nonce,
                "tag": tag
            }

            # Envia a mensagem criptografada
            connection_info["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())

def send_group_message(sender_name, recipient_name, message, nonce, tag):
    for address, connection_info in clientes.items():
        if connection_info["name"] == recipient_name:

            # Prepara os dados para envio
            message_info = {
                "sender_name": sender_name,
                "recipient_name": recipient_name,
                "message": message,
                "nonce": nonce,
                "tag": tag,
                "is_group_message": True
            }

            # Envia a mensagem criptografada
            connection_info["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())

def send_group_key(sender_name, recipient_name, message, nonce, tag, group_key):
    for address, connection_info in clientes.items():
        if connection_info["name"] == recipient_name:

            # Prepara os dados para envio
            message_info = {
                "sender_name": sender_name,
                "recipient_name": recipient_name,
                "message": message,
                "nonce": nonce,
                "tag": tag,
                "is_group_key": True
            }

            # Envia a mensagem criptografada
            connection_info["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())

def send_group_list(sender_name, recipient_name):
    for address, connection_info in clientes.items():
        if connection_info["name"] == recipient_name:

            # Prepara os dados para envio
            message_info = {
                "sender_name": sender_name,
                "recipient_name": recipient_name,
                "group_list": group_clients
            }

            # Envia a mensagem criptografada
            connection_info["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())

def remove_client(client_address):
    if client_address in clientes:
        # Informar aos outros clientes que este saiu
        for client in clientes:
            if client == client_address:
                continue
            message_info = {
                "sender_name": "server",
                "recipient_name": clientes[client]["name"],
                "client_that_left": clientes[client_address]["name"]
            }
            clientes[client]["socket"].send(json.dumps(message_info, ensure_ascii=False).encode())
        del clientes[client_address]

def handle_client(client_socket, client_address):
    try:
        client_key = ""
        # Troca de chaves entre servidor e cliente
        dh = DiffieHellman.DH()

        data = client_socket.recv(1024).decode()
        message = json.loads(data)

        dh.base = message["base"]
        dh.sharedPrime = message["prime"]
        publicSecret = message["publicSecret"]

        # Calcular o valor público gerado
        calcedPubSecret = dh.calcPublicSecret()

        # Enviar o valor calculado para o cliente que iniciou o processo diffie-hellman
        message = { "publicSecret": calcedPubSecret }
        
        client_socket.send(json.dumps(message, ensure_ascii=False).encode())

        # Calcular valor secreto
        dh.calcSharedSecret(publicSecret)

        # Gerar chave AES
        AES_key = genetare_AES_key(dh.key)
        client_key = AES_key
        print(f"Chave gerada para este cliente: {Fore.YELLOW}{AES_key}{Fore.RESET}")


        while True:
            # Autenticação do cliente
            authentication_data = client_socket.recv(1024).decode()
            auth_info = json.loads(authentication_data)

            email = auth_info.get("email")
            email = base64.b64decode(email)
            password = auth_info.get("password")
            password = base64.b64decode(password)

            logged = False
            name = ""

            if "apelido" in auth_info:
                apelido = auth_info.get("apelido")
                apelido = base64.b64decode(apelido)

                email_nonce = auth_info.get("email_nonce")
                email_nonce = base64.b64decode(email_nonce)
                email_tag = auth_info.get("email_tag")
                email_tag = base64.b64decode(email_tag)
                email = decrypt_message(email, client_key, email_nonce, email_tag)

                apelido_nonce = auth_info.get("apelido_nonce")
                apelido_nonce = base64.b64decode(apelido_nonce)
                apelido_tag = auth_info.get("apelido_tag")
                apelido_tag = base64.b64decode(apelido_tag)
                apelido = decrypt_message(apelido, client_key, apelido_nonce, apelido_tag)

                password_nonce = auth_info.get("password_nonce")
                password_nonce = base64.b64decode(password_nonce)
                password_tag = auth_info.get("password_tag")
                password_tag = base64.b64decode(password_tag)
                password = decrypt_message(password, client_key, password_nonce, password_tag)

                print(f"{email} {apelido} {password}")

                logged = cadastrar_cliente(email, apelido, password)
            else:
                email_nonce = auth_info.get("email_nonce")
                email_nonce = base64.b64decode(email_nonce)
                email_tag = auth_info.get("email_tag")
                email_tag = base64.b64decode(email_tag)
                email = decrypt_message(email, client_key, email_nonce, email_tag)

                password_nonce = auth_info.get("password_nonce")
                password_nonce = base64.b64decode(password_nonce)
                password_tag = auth_info.get("password_tag")
                password_tag = base64.b64decode(password_tag)
                password = decrypt_message(password, client_key, password_nonce, password_tag)

                name = fazer_login(email, password)

            if name == "" and not logged:
                # Envia sinal de autenticação mal-sucedida para o cliente
                message_info = {
                    "logged": False,
                    "username": "",
                }
                client_socket.send(json.dumps(message_info).encode())
            elif name != "" or logged:
                # Envia sinal de autenticação bem-sucedida para o cliente
                message_info = {
                    "logged": True,
                    "username": name,
                }

                if logged:
                    name = apelido
                    
                client_socket.send(json.dumps(message_info).encode())
                break

        print(f"[{client_address}] Autenticado como {Fore.YELLOW}{name}{Fore.RESET}")
        
        clientes[client_address] = {"socket": client_socket, "name": name}

        # Enviar lista de usuários logados atualmente para o cliente
        clients_names = {}
        for client in clientes:
            clients_names[clientes[client]["name"]] = clientes[client]["name"]
        client_socket.send(json.dumps(clients_names, ensure_ascii=False).encode())

        while True:
            try:
                # Recebe a mensagem do cliente
                data = client_socket.recv(1024)
                if not data:
                    print(f"{Fore.YELLOW}[{client_address}]{Fore.RESET} Cliente desconectado.")
                    del clientes[client_address]
                    break

                message_info = json.loads(data.decode())

                # Processa a mensagem e encaminha para o destinatário
                sender_name = name
                recipient_name = message_info.get("recipient_name", "")
                message = message_info.get("message", "")

                # Verifica se é uma mensagem criptografada
                if "is_in_group" in message_info:
                    if message_info.get("is_in_group") == True:
                        group_clients.append(sender_name)
                        print(f"{sender_name} {Fore.GREEN}entrou{Fore.RESET} no grupo")
                    else:
                        group_clients.remove(sender_name)
                        print(f"{sender_name} {Fore.RED}saiu{Fore.RESET} no grupo")
                    
                    # Avisar os outros usuários que um usuário saiu
                    for online_client in clientes:
                        send_group_list("server", clientes[online_client]["name"])
                elif 'nonce' in message_info:
                    nonce = message_info.get("nonce", "")
                    tag = message_info.get("tag", "")
                    # Encaminha a mensagem para o destinatário
                    if 'is_group_key' in message_info:
                        send_group_key(sender_name, recipient_name, message, nonce, tag, True)
                    elif recipient_name == "group":
                        for online_client in clientes:
                            if clientes[online_client]["name"] == sender_name or clientes[online_client]["name"] not in group_clients:
                                continue
                            send_group_message(sender_name, clientes[online_client]["name"], message, nonce, tag)
                    else:
                        send_message(sender_name, recipient_name, message, nonce, tag)
                else:
                    # Encaminha a mensagem para o destinatário, no caso, uma mensagem diffi-hellman
                    send_DF_message(sender_name, recipient_name, message)

            except Exception as e:
                print(f"Erro ao lidar com o cliente {Fore.YELLOW}{client_address}: {Fore.RED}{str(e)}{Fore.RESET}")
                remove_client(client_address)  # Remove cliente em caso de erro
                break
    except Exception as e:
        print(f"Erro durante autenticação do cliente {Fore.YELLOW}{client_address}: {Fore.RED}{str(e)}{Fore.RESET}")
        remove_client(client_address)  # Remove cliente em caso de erro

def start_server():
    host = '0.0.0.0'
    port = 5555

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"{Fore.GREEN}[+] Servidor escutando em {host}:{port}")

    while True:
        client_socket, client_address = server.accept()
        print(f"[+] Nova conexão de {Fore.YELLOW}{client_address}{Fore.RESET}")

        # Inicia uma thread para lidar com o cliente
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()