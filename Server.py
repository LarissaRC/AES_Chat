import socket
import threading
import json
import base64
from colorama import Fore, init

# Inicializa o colorama
init(autoreset=True)

# Dicionário para armazenar as conexões dos clientes e seus nomes
clientes = {}
group_clients = []

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
        # Autenticação do cliente
        authentication_data = client_socket.recv(1024).decode()
        auth_info = json.loads(authentication_data)

        name = auth_info.get("name")

        print(f"[{client_address}] Autenticado como {Fore.YELLOW}{name}{Fore.RESET}")

        # Envia sinal de autenticação bem-sucedida para o cliente
        client_socket.send("authenticated".encode())
        
        clientes[client_address] = {"socket": client_socket, "name": name}

        # Enviar lista de usuários logados atualmente para o cliente
        clients_names = {}
        for client in clientes:
            clients_names[clientes[client]["name"]] = clientes[client]["name"]
        client_socket.send(json.dumps(clients_names, ensure_ascii=False).encode())

        '''
        print("Clientes atualmente logados:")
        for client in clientes:
            print("- " + clientes[client]["name"])
        '''

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
                if 'nonce' in message_info:
                    nonce = message_info.get("nonce", "")
                    tag = message_info.get("tag", "")
                    # Encaminha a mensagem para o destinatário
                    if 'is_group_key' in message_info:
                        send_group_key(sender_name, recipient_name, message, nonce, tag, True)
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

    print(f"[+] Servidor escutando em {host}:{port}")

    while True:
        client_socket, client_address = server.accept()
        print(f"[+] Nova conexão de {Fore.YELLOW}{client_address}{Fore.RESET}")

        # Inicia uma thread para lidar com o cliente
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()