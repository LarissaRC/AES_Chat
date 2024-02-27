import sqlite3
import hashlib

# Função para criar a tabela de clientes
def create_table():
    conn = sqlite3.connect('clientes.db')
    cursor = conn.cursor()

    # Criação da tabela de clientes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            apelido TEXT,
            senha TEXT
        )
    ''')

    conn.commit()
    conn.close()

# Função para cadastrar um novo cliente
def cadastrar_cliente(email, apelido, senha):
    conn = sqlite3.connect('clientes.db')
    cursor = conn.cursor()

    # Verifica se o email já está cadastrado
    cursor.execute('SELECT * FROM clientes WHERE email=?', (email,))
    if cursor.fetchone() is not None:
        conn.commit()
        conn.close()
        return False
    # Verifica se o apelido já está cadastrado
    cursor.execute('SELECT * FROM clientes WHERE apelido=?', (apelido,))
    if cursor.fetchone() is not None:
        conn.commit()
        conn.close()
        return False
    else:
        # Insere o novo cliente no banco de dados
        hashed_password = hashlib.sha256(senha.encode()).hexdigest()
        cursor.execute('INSERT INTO clientes (email, apelido, senha) VALUES (?, ?, ?)', (email, apelido, hashed_password))

    conn.commit()
    conn.close()

    return True

# Função para realizar o login
def fazer_login(email, senha):
    conn = sqlite3.connect('clientes.db')
    cursor = conn.cursor()

    # Verifica se o email e a senha correspondem a algum cliente
    hashed_password = hashlib.sha256(senha.encode()).hexdigest()
    cursor.execute('SELECT apelido FROM clientes WHERE email=? AND senha=?', (email, hashed_password))
    cliente = cursor.fetchone()

    conn.close()

    if cliente is not None:
        return cliente[0]
    else:
        return ""

# Função para obter apelidos de todos os clientes
def obter_apelidos():
    conn = sqlite3.connect('clientes.db')
    cursor = conn.cursor()

    # Seleciona todos os apelidos
    cursor.execute('SELECT apelido FROM clientes')
    apelidos = cursor.fetchall()

    conn.close()

    return [apelido[0] for apelido in apelidos]

# Função para limpar o banco de dados (excluir a tabela de clientes)
def limpar_banco():
    conn = sqlite3.connect('clientes.db')
    cursor = conn.cursor()

    # Exclui a tabela de clientes se ela existir
    cursor.execute('DROP TABLE IF EXISTS clientes')

    conn.commit()
    conn.close()

    create_table()

# Função principal para o menu
def menu():
    create_table()

    while True:
        print("\nMenu:")
        print("1. Criar uma conta")
        print("2. Logar na conta")
        print("3. Obter apelidos de todos os cadastrados")
        print("4. Limpar o banco de dados")
        print("5. Sair")

        escolha = input("Escolha a opção (1/2/3/4/5): ")

        if escolha == '1':
            email = input("Digite o email: ")
            apelido = input("Digite o apelido: ")
            senha = input("Digite a senha: ")
            cadastrar_cliente(email, apelido, senha)

        elif escolha == '2':
            email = input("Digite o email: ")
            senha = input("Digite a senha: ")
            if fazer_login(email, senha):
                continue  # Volta ao menu após o login bem-sucedido

        elif escolha == '3':
            apelidos = obter_apelidos()
            print("Apelidos cadastrados:")
            for apelido in apelidos:
                print(f"- {apelido}")

        elif escolha == '4':
            limpar_banco()
            print("Banco de dados limpo!")

        elif escolha == '5':
            print("Saindo do programa. Até logo!")
            break

        else:
            print("Escolha inválida. Por favor, digite 1, 2, 3 ou 4.")

if __name__ == "__main__":
    menu()
