from random import randrange


def is_prime(number):
    if 0 <= number <= 2:
        return False

    # https://pt.wikipedia.org/wiki/Crivo_de_Erat%C3%B3stenes

    primes = []

    # Inicialização do array
    for i in range(number + 1):
        primes.append(True)

    # Excluindo 0 e 1 desde o início
    primes[0] = False
    primes[1] = False

    # Todos os múltiplos de um número primo são excluídos
    for i in range(number + 1):
        if primes[i] is True:
            j = 2 * i
            while j <= number:
                primes[j] = False
                j += i

    # Ao remover os múltiplos de um número primo, o próximo número que não foi removido é também primo.
    return primes[number] is True

# Geração de um primo aleatório
def rand_prime(size):
    prime = 1

    while not is_prime(prime):
        prime = randrange(size, 200000)

    return prime
