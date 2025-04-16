import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b'YELLOW SUBMARINE'

def aes_ecb_decrypt(ciphertext, key):
	cipher = Cipher(algorithms.AES(key), modes.ECB())
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def aes_ecb_encrypt(ciphertext, key):
	cipher = Cipher(algorithms.AES(key), modes.ECB())
	encryptor = cipher.encryptor()
	return encryptor.update(ciphertext) + encryptor.finalize()


def main():
	ciphertext_file = open("challenges/files/7.txt")

	ciphertext = ciphertext_file.read()

	raw_ciphertext = base64.b64decode(ciphertext)

	plaintext = aes_ecb_decrypt(raw_ciphertext, KEY)

	print(plaintext.decode("ascii"))

if __name__ == '__main__':
	main()