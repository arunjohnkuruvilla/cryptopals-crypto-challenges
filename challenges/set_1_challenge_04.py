import binascii
import set_1_challenge_03 as challenge_3

def identify_single_char_xor():
	source_file = open("./challenges/files/4.txt", "r")
	lines = source_file.readlines()

	max_line = 0
	max_score = 0.0
	max_key = ''
	max_plaintext = ''

	for counter, line in enumerate(lines):
		ciphertext_line = line.rstrip()
		raw_ciphertext_line = binascii.unhexlify(ciphertext_line)

		current_key, current_plaintext, current_score = challenge_3.detect_xor_key(raw_ciphertext_line)

		if current_score > max_score:
			max_score = current_score
			max_plaintext = current_plaintext
			max_key = current_key
			max_line = counter

	print("Line #" + str(max_line) + " : Key '" + max_key + "' : " + max_plaintext)

if __name__ == '__main__':
	identify_single_char_xor()
