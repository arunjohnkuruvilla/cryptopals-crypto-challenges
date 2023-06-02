import base64
from Crypto.Cipher import AES

KEY = b'YELLOW SUBMARINE'

def aes_ecb_decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(ciphertext)

def main():
	ciphertext_file = open("challenges/files/7.txt")

	ciphertext = ciphertext_file.read()

	raw_ciphertext = base64.b64decode(ciphertext)

	plaintext = aes_ecb_decrypt(raw_ciphertext, KEY)

	print(plaintext.decode("ascii"))

if __name__ == '__main__':
	main()