from KryptoMath import Prime


class DH:

	# Cores do Diffie-Hellman
	def __init__(self):
		self.privatePrime = Prime.rand_prime(2000)
		self.sharedPrime = Prime.rand_prime(2000)
		self.base = Prime.rand_prime(2000)
		self.key = int()


    # Calcula o primeiro passo para o segredo compartilhado	
	def calcPublicSecret(self):
		return (self.base ** self.privatePrime) % self.sharedPrime

    # Calcula o segredo compartilhado
	def calcSharedSecret(self, privSecret):
		self.key = (privSecret ** self.privatePrime) % self.sharedPrime
