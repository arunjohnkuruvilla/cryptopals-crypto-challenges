import sys
import base64
import binascii

INPUT_STRING = b'''Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal'''

OUTPUT_STRING = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

def repeated_xor_encrypt(plaintext, key):
	key_length = len(key)
	plaintext_length = len(plaintext)

	ciphertext = b''

	for counter, char in enumerate(plaintext):
		current_key_char = key[counter%key_length]

		current_ciphertext_char = chr(char ^ current_key_char)

		ciphertext = ciphertext + binascii.hexlify(current_ciphertext_char.encode())

	return ciphertext

if __name__ == '__main__':
	ciphertext = repeated_xor_encrypt(INPUT_STRING, b'ICE')

	print(ciphertext)

	print(ciphertext == OUTPUT_STRING)