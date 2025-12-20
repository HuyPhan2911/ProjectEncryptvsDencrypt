from crypto.des import encrypt, decrypt

data = b"HELLO DES TEST"
key = "abc"   # ngắn vẫn OK

enc = encrypt(data, key)
dec = decrypt(enc, key)

print(enc)
print(dec)
