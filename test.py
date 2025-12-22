from crypto.tripledes import TripleDES

# Khóa 24 bytes (3-key)
key = b"0123456789abcdef01234567"
tdes = TripleDES(key)

data = b"Hello TripleDES!"
enc = tdes.encrypt(data)
print("Encrypted:", enc.hex())

dec = tdes.decrypt(enc)
print("Decrypted:", dec)
