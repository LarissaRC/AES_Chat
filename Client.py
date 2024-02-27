import socket
import threading
import json
import sqlite3
import base64
from colorama import Fore, init
from DiffieHellman import DiffieHellman
from AES import encrypt_message, decrypt_message
import hashlib
from Cryptodome.Protocol.KDF import PBKDF2
from random import randrange
import pyfiglet

# Inicializa o colorama
init(autoreset=True)

global group_key
global group_list
global is_in_group
group_key = None
group_list = []
is_in_group = False

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

# Geração da chave em grupo
def genetare_group_key():
    key = randrange(30000, 60000)
    return key

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
        "senderName": sender_name,
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

    ######################## Prints essenciais #########################
    print(f"\n{Fore.GREEN}{'#' * 30}{Fore.RESET} Diffie-Hellman com o cliente {Fore.YELLOW}{receiver_name} {Fore.GREEN}{'#' * 30}{Fore.RESET}")
    print(f"{Fore.YELLOW}Base: {Fore.RESET}{dh.base}")
    print(f"{Fore.YELLOW}Primo: {Fore.RESET}{dh.sharedPrime}")
    print(f"{Fore.YELLOW}Valor público gerado: {Fore.RESET}{publicSecret}")
    print(f"{Fore.YELLOW}Valor público recebido: {Fore.RESET}{clients_shared_keys[receiver_name]['publicSecretReceived']}")
    print(f"{Fore.YELLOW}Valor secreto gerado: {Fore.RESET}{dh.key}")
    print(f"{Fore.YELLOW}Chave AES gerada: {Fore.RESET}{AES_key}")
    print(f"{Fore.GREEN}{'#' * 92}{Fore.RESET}\n")


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

    ######################## Prints essenciais #########################
    print(f"\n\n{Fore.GREEN}{'#' * 30}{Fore.RESET} Diffie-Hellman com o cliente {Fore.YELLOW}{message_info['sender_name']} {Fore.GREEN}{'#' * 30}{Fore.RESET}")
    print(f"{Fore.YELLOW}Base: {Fore.RESET}{dh.base}")
    print(f"{Fore.YELLOW}Primo: {Fore.RESET}{dh.sharedPrime}")
    print(f"{Fore.YELLOW}Valor público gerado: {Fore.RESET}{calcedPubSecret}")
    print(f"{Fore.YELLOW}Valor público recebido: {Fore.RESET}{publicSecret}")
    print(f"{Fore.YELLOW}Valor secreto gerado: {Fore.RESET}{dh.key}")
    print(f"{Fore.YELLOW}Chave AES gerada: {Fore.RESET}{AES_key}")
    print(f"{Fore.GREEN}{'#' * 92}{Fore.RESET}\n")

def show_DF():
    print("Valores DF gerados:")
    for client_data in clients_shared_keys:
        print(f"{Fore.GREEN}- {client_data}{Fore.RESET} {clients_shared_keys[client_data]['secretValue']}")

def show_AES_key():
    print("\nChaves AES geradas:")
    for client_data in clients_shared_keys:
        print(f"{Fore.GREEN}- {client_data}{Fore.RESET} {clients_shared_keys[client_data]['AES_key']}")
    print("\n")

def receive_messages(client_socket):
    global group_list
    global group_key
    global is_in_group

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
            message = message_info.get("message", "")

            # Verifica se é de fato uma mensagem ou se é uma solicitação de Diffie-Hellman
            if sender_name == 'server':
                if message_info.get("client_that_left"):
                    print(f"\n{Fore.RED}{message_info.get('client_that_left')}{Fore.RESET} saiu da aplicação.")
                    del clients_shared_keys[message_info.get("client_that_left")]
                elif "group_list" in message_info:
                    group_list = message_info.get("group_list")
                    if len(group_list) == 1:
                        print(f"\n{Fore.YELLOW}Você é o único no grupo atualmente\n")
                    else:
                        print(f"\nClientes presentes no grupo atualmente:")
                        for member in group_list:
                            print(f'{Fore.GREEN}{member}')
                        print("")
            elif 'nonce' not in message_info:
                receiver_diffie_hellman(client, message_info)
            else:
                encrypted_message_base64 = message_info.get("message", "")
                nonce_base64 = message_info.get("nonce", "")
                tag_base64 = message_info.get("tag", "")

                # Converte a mensagem Base64 de volta para bytes
                encrypted_message = base64.b64decode(encrypted_message_base64)
                nonce = base64.b64decode(nonce_base64)
                tag = base64.b64decode(tag_base64)

                # verifica se é de fato uma mensagem ou se é a chave nova de grupo
                if "is_group_key" in message_info:
                    # Descriptografa a mensagem
                    message = decrypt_message(encrypted_message, clients_shared_keys[sender_name]["AES_key"], nonce, tag)
                    group_key = int(message)
                    group_key = genetare_AES_key(group_key)
                    print(f"{Fore.YELLOW}Valor recebido para gerar mensagem em grupo:{Fore.RESET} {group_key}")
                else:
                    # Imprime a mensagem recebida
                    if 'is_group_message' in message_info:
                        # Descriptografa a mensagem
                        message = decrypt_message(encrypted_message, group_key, nonce, tag)
                        print(f"{Fore.GREEN}[{sender_name}]:{Fore.RESET} {message}")
                    else:
                        # Descriptografa a mensagem
                        message = decrypt_message(encrypted_message, clients_shared_keys[sender_name]["AES_key"], nonce, tag)
                        print(f"{Fore.YELLOW}[{sender_name}]:{Fore.RESET} {message}")
        except Exception as e:
            print(f"Erro ao receber mensagens: {Fore.RED}{str(e)}{Fore.RESET}")
            break

def authenticate_and_start_client():
    global group_key
    global group_list
    global is_in_group

    while True:
        # Autenticação do cliente
        print(pyfiglet.figlet_format("Bem vindo!"))
        email = input("[+] Informe seu email: ")
        password = input("[+] Informe sua senha: ")

        auth_info = {
            "email": email,
            "password": password,
        }

        client.send(json.dumps(auth_info).encode())
        print("[+] Aguardando autenticação...")

        authentication_response = client.recv(1024).decode()

        message_info = json.loads(authentication_response)
        logged = message_info.get("logged")
        name = message_info.get("username")

        if not logged:
            print(f"{Fore.RED}[+] Email ou senha inválidos. Tente novamente{Fore.RESET}")
            continue
        else:
            print(f"[+] {Fore.GREEN}Autenticação bem-sucedida.{Fore.RESET} Conectado ao servidor.")
            print(f"[+] Seja bem-vindo(a), {Fore.GREEN}{name}.")
            break

    data = client.recv(1024).decode()
    clients_online = json.loads(data)

    for client_online in clients_online:
        if clients_online[client_online] != name:
            sender_diffie_hellman(client, name, clients_online[client_online])

    while True:
        # Inicia uma thread para receber mensagens do servidor
        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.start()

        # Gerar e enviar a chave secreta caso esta ainda não tenha sido gerada
        if group_key is None:
            group_key = genetare_group_key()
            for online_client in clients_shared_keys:
                encrypted_message, nonce, tag, texto_cifrado = encrypt_message(str(group_key).encode('utf-8'), clients_shared_keys[online_client]["AES_key"])
                message_info = {"sender_name": name, "recipient_name": online_client,
                                "message": encrypted_message, "nonce": nonce, "tag": tag, "is_group_key": True}
                print(message_info)
                print(f"{Fore.GREEN}Mensagem criptografada: {Fore.RESET}{texto_cifrado}")
                client.send(json.dumps(message_info, ensure_ascii=False).encode())

            group_key = genetare_AES_key(group_key)
            print(f'\n{Fore.YELLOW}Valor compartilhado para gerar chave em grupo: {Fore.RESET}{group_key}\n')

        # Informa o nome do destinatário desejado
        recipient_name = input("[+] Escolha uma opção: \nexit - sair do programa\nkeys - ver as chaves AES\nusers - ver usuários online\nnome do usuário - iniciar uma conversa\ngroup - entrar no chat em grupo\n\nOpção:")

        if recipient_name.lower() == 'exit':
            print("[+] Cliente encerrado.")
            client.close()
            exit()
        elif recipient_name.lower() == 'df':
            # Mostrar os valores gerados na troca diffie-hellman
            show_DF()
            continue
        elif recipient_name.lower() == 'keys':
            # Mostrar as chaves AES geradas
            show_AES_key()
            continue
        elif recipient_name.lower() == 'users':
            if len(clients_shared_keys) == 0:
                print(f"{Fore.RED}\nNão há outros usuários online!!\n{Fore.RESET}")
                continue
            print("\nUsuários online:")
            for user in clients_shared_keys:
                print(f"{Fore.GREEN}- {user}{Fore.RESET}")
            print("\n")
            continue
        elif recipient_name.lower() == 'group':
            print(pyfiglet.figlet_format("Chat Grupo"))
            print(f"{Fore.YELLOW}\nEntrou no grupo\n{Fore.RESET}")
            is_in_group = True
            message_info = {"sender_name": name, "recipient_name": "server", "is_in_group": is_in_group}
            client.send(json.dumps(message_info, ensure_ascii=False).encode())
        elif recipient_name not in clients_shared_keys:
            print(f"{Fore.RED}{recipient_name}{Fore.RESET} não está mais na aplicação. Escolha outro usuário.")
            recipient_name = ""
            continue

        # Envia mensagens para o servidor
        while True:
            try:
                message = input()

                # Verifica se o usuário escolhido não saiu da aplicação
                if recipient_name not in clients_shared_keys and is_in_group == False:
                    print(f"{Fore.RED}Usuário não está mais online! Escolha outro!{Fore.RESET}")
                    recipient_name = ""
                    break

                if message.lower() == 'exit':
                    print("[+] Saindo da conversa.")

                    if is_in_group:
                        print(f"{Fore.YELLOW}\nSaiu no grupo\n{Fore.RESET}")
                        is_in_group = False
                        message_info = {"sender_name": name, "recipient_name": "server", "is_in_group": is_in_group}
                        client.send(json.dumps(message_info, ensure_ascii=False).encode())
                    break

                if is_in_group:
                    encrypted_message, nonce, tag, texto_cifrado = encrypt_message(message.encode('utf-8'), group_key)
                    message_info = {"sender_name": name, "recipient_name": "group",
                                    "message": encrypted_message, "nonce": nonce, "tag": tag}
                    print(message_info)
                    print(f"{Fore.GREEN}Mensagem criptografada: {Fore.RESET}{texto_cifrado}")
                    client.send(json.dumps(message_info, ensure_ascii=False).encode())
                else:
                    encrypted_message, nonce, tag, texto_cifrado = encrypt_message(message.encode('utf-8'), clients_shared_keys[recipient_name]["AES_key"])
                    message_info = {"sender_name": name, "recipient_name": recipient_name,
                                    "message": encrypted_message, "nonce": nonce, "tag": tag}
                    print(message_info)
                    print(f"{Fore.GREEN}Mensagem criptografada: {Fore.RESET}{texto_cifrado}")
                    client.send(json.dumps(message_info, ensure_ascii=False).encode())
            except KeyboardInterrupt:
                print("[+] Cliente encerrado.")
                client.close()
                exit()

if __name__ == "__main__":
    host = '127.0.0.1'
    port = 5555

    clients_shared_keys = {}
    recipient_name = ""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    authenticate_and_start_client()