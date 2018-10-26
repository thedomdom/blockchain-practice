from Crypto.Hash import SHA256

print('Trying to hash a binary value')
h = SHA256.new()
h.update(b'This is a test of the setup')
print(h.hexdigest())
print("It seems to work")
