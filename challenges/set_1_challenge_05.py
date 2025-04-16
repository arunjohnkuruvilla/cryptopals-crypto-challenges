import sys
import base64
import binascii
import set_1_challenge_02 as challenge_2

def repeated_xor_encrypt(plaintext, key):

	key_length = len(key)

	ciphertext = b''

	for counter, char in enumerate(plaintext):
		current_key_char = key[counter%key_length]

		print(type(char))
		print(type(current_key_char))
		current_ciphertext_char = challenge_2.xor(char, current_key_char)

		ciphertext = ciphertext + current_ciphertext_char

	return ciphertext

if __name__ == '__main__':

	INPUT_STRING = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	KEY = "ICE"

	OUTPUT_STRING = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	ciphertext_string = repeated_xor_encrypt(INPUT_STRING, KEY)
	hex_ciphertext = binascii.hexlify(ciphertext_string).decode('ascii')
	
	assert hex_ciphertext == OUTPUT_STRING