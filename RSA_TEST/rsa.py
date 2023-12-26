from Crypto.PublicKey import RSA 

key = RSA.generate(4096, e=65537)

# public_key = key.publickey().export_key()
e = list(key.e.to_bytes(3, byteorder='big'))
print(e)
print()

n = list(key.n.to_bytes(512, byteorder='big'))
for h in n:
    print('0x' + format(h, '02x'), end=', ')
print('\n')

p = list(key.p.to_bytes(512, byteorder='big'))
print('p : ')
for h in p:
    print('0x' + format(h, '02x'), end=', ')
print('\n')

q = list(key.q.to_bytes(512, byteorder='big'))
print('q : ')
for h in q:
    print('0x' + format(h, '02x'), end=', ')
print('\n')

d = list(key.d.to_bytes(1024, byteorder='big'))
print('d : ')
for h in d:
    print('0x' + format(h, '02x'), end=', ')
print('\n')

# format(255, '02x')
