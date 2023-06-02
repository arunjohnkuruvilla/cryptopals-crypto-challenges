import base64
import sys
import binascii
import set_1_challenge_7 as challenge_7
import set_1_challenge_5 as challenge_5

def aes_cbc_decrypt(ciphertext, key, iv, block_size = 16):
	if len(key) != len(iv):
		raise Exception("Key and IV lengths do not match.")

	ciphertext_blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

	current_iv = iv

	plaintext_hex = b''

	for counter, ciphertext_block in enumerate(ciphertext_blocks):
		current_intermediate = challenge_7.aes_ecb_decrypt(ciphertext_block, key)

		plaintext_hex += challenge_5.repeated_xor_encrypt(current_intermediate, current_iv)

		current_iv = ciphertext_block

	return binascii.unhexlify(plaintext_hex)


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