from Crypto.Cipher import AES
import binascii, os

key = b"3153153153153153"
#iv =  os.urandom(16)
iv = bytes(16)



plaintext = open('message.txt', 'rb').read().strip()
ciphertext = open('message.enc', 'rb').read().strip()

cipher = AES.new(key, AES.MODE_CBC, iv)
known_ciphertext = cipher.encrypt(plaintext)


encrypted_flag = binascii.unhexlify(open('message.enc', 'rb').read().strip())

iv = bytes(a ^ b for a, b in zip(encrypted_flag[:16],known_ciphertext[:16]))
orig_cipher = AES.new(key, AES.MODE_CBC, iv)

print(orig_cipher.decrypt(encrypted_flag))

#encrypted_flag.write(binascii.hexlify(cipher.encrypt(plaintext)))
#encrypted_flag.close()
