from DiffieHellman import DiffieHellman

users = ["A", "B", "C"]

for i in range(len(users)):
    print(f"User {i+1}:")
    for j in range(len(users)):
        print(f"- {users[(i + j) % len(users)]}")


dha = DiffieHellman.DH()

dhb = DiffieHellman.DH()
dhb.sharedPrime = dha.sharedPrime
dhb.base = dha.base

dhc = DiffieHellman.DH()
dhc.sharedPrime = dha.sharedPrime
dhc.base = dha.base

dhd = DiffieHellman.DH()
dhd.sharedPrime = dha.sharedPrime
dhd.base = dha.base

print("A")

publicSecret = dha.calcPublicSecret()
print("B")
misturakkk = dhb.calcMultiPublicSecret(publicSecret)
print(misturakkk)
misturakkkk = dhc.calcMultiPublicSecret(misturakkk)
print(misturakkkk)
dhd.calcSharedSecret(misturakkkk)
print("E")

publicSecret = dhb.calcPublicSecret()
misturakkk = dhc.calcMultiPublicSecret(publicSecret)
misturakkkk = dhd.calcMultiPublicSecret(misturakkk)
dha.calcSharedSecret(misturakkkk)

publicSecret = dhc.calcPublicSecret()
misturakkk = dhd.calcMultiPublicSecret(publicSecret)
misturakkkk = dha.calcMultiPublicSecret(misturakkk)
dhb.calcSharedSecret(misturakkkk)

publicSecret = dhd.calcPublicSecret()
misturakkk = dha.calcMultiPublicSecret(publicSecret)
misturakkkk = dhb.calcMultiPublicSecret(misturakkk)
dhc.calcSharedSecret(misturakkkk)

print(f"A: {dha.key}")
print(f"B: {dhb.key}")
print(f"C: {dhc.key}")
print(f"D: {dhd.key}")