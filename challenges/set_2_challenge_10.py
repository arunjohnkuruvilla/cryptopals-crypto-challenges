import base64
import sys
import binascii
import set_1_challenge_02 as challenge_02
import set_1_challenge_07 as challenge_07
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_cbc_decrypt(ciphertext, key, iv, block_size = 16):
	if len(key) != len(iv):
		raise Exception("Key and IV lengths do not match.")

	ciphertext_blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

	current_iv = iv

	plaintext_hex = b''

	for counter, ciphertext_block in enumerate(ciphertext_blocks):
		current_intermediate = challenge_07.aes_ecb_decrypt(ciphertext_block, key)

		plaintext_hex += challenge_02.xor(current_intermediate, current_iv)

		current_iv = ciphertext_block

	# Add implementation for PKCS#07 unpadding

	return plaintext_hex

def aes_cbc_encrypt(plaintext, key, iv, block_size = 16):
	if len(key) != len(iv):
		raise Exception("Key and IV lengths do not match.")

	plaintext_blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]

	current_iv = iv

	ciphertext = b''

	for counter, plaintext_block in enumerate(plaintext_blocks):

		current_intermediate = challenge_02.xor(plaintext_block, current_iv)

		current_ciphertext = challenge_07.aes_ecb_decrypt(current_intermediate, key)

		ciphertext += current_ciphertext

		current_iv = current_ciphertext

	return ciphertext


def main(): 
	ciphertext_file = open("challenges/files/10.txt")
	ciphertext_file_contents = ciphertext_file.readlines()

	ciphertext = ""
	for line in ciphertext_file_contents:
		ciphertext += line.rstrip()

	raw_ciphertext = base64.b64decode(ciphertext)

	plaintext = aes_cbc_decrypt(raw_ciphertext, b'YELLOW SUBMARINE', b'\x00'*16, 16)

	print(plaintext.decode("ascii"))

if __name__ == '__main__':
	main()