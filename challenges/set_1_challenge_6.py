import sys
import base64
import binascii

def hamming_distance(str1, str2):
	assert len(str1) == len(str2)
		# raise Exception("Length of " + str1 + " is not equal to " + str2)

	hamming_distance = 0

	for counter, str1_char in enumerate(str1):
		str1_char_bits = format(ord(str1_char), '08b')
		str2_char_bits = format(ord(str2[counter]), '08b')

		for bit_counter, str1_char_bit in enumerate(str1_char_bits):

			if str1_char_bit != str2_char_bits[bit_counter]:
				hamming_distance = hamming_distance + 1

	return hamming_distance

def break_repeating_key_xor(ciphertext):
	raw_ciphertext = base64.b64decode(ciphertext).decode('utf-8')

	plaintext = ""

	keysize_dict = {}

	for x in range(2, 40):
		first_part = raw_ciphertext[0:x]
		second_part = raw_ciphertext[x:2*x]
		third_part = raw_ciphertext[2*x:3*x]
		fourth_part = raw_ciphertext[3*x:4*x]

		current_hamming_distance1 = hamming_distance(first_part, second_part)
		current_hamming_distance2 = hamming_distance(third_part, fourth_part)

		normalized_current_hamming_distance = (current_hamming_distance1)/(x) 

		keysize_dict[x] = normalized_current_hamming_distance

	print(sorted(keysize_dict.items(), key=lambda x:x[1])[0][0])
	print(sorted(keysize_dict.items(), key=lambda x:x[1])[1][0])
	print(sorted(keysize_dict.items(), key=lambda x:x[1])[2][0])
	print(sorted(keysize_dict.items(), key=lambda x:x[1])[3][0])
	print(sorted(keysize_dict.items(), key=lambda x:x[1])[4][0])

	return plaintext

if __name__ == '__main__':

	assert hamming_distance("this is a test", "wokka wokka!!!") == 37

	ciphertext_file = open("challenges/files/6.txt")

	ciphertext_file_contents = ciphertext_file.readlines()

	ciphertext = ""

	for line in ciphertext_file_contents:
		ciphertext = ciphertext + line.strip()

	plaintext = break_repeating_key_xor(ciphertext)

	print(plaintext)
