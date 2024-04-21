import base64
import itertools
import set_1_challenge_03 as challenge_03
import set_1_challenge_05 as challenge_05

def hamming_distance(str1, str2):
	assert len(str1) == len(str2)

	hamming_distance = 0

	for counter, str1_char in enumerate(str1):
		str1_char_bits = format(str1_char, '08b')
		str2_char_bits = format(str2[counter], '08b')

		for bit_counter, str1_char_bit in enumerate(str1_char_bits):
			if str1_char_bit != str2_char_bits[bit_counter]:
				hamming_distance = hamming_distance + 1

	return hamming_distance

def get_smallest_normalized_edit_distance(string):
	keysize_dict = {}
	
	for x in range(2, 40):
		blocks = [string[i:i+x] for i in range(0, len(string), x)][0:5]
		pairs = list(itertools.combinations(blocks, 2))
		scores = [hamming_distance(p[0], p[1])/float(x) for p in pairs]

		keysize_dict[x] = sum(scores) / len(scores)

	return sorted(keysize_dict.items(), key=lambda x:x[1])[0][0]

def get_transposed_blocks(ciphertext, current_potential_keysize):
	transposed_blocks = [b'']*current_potential_keysize

	counter = 0
	while counter < len(ciphertext):
		transposed_blocks[counter%current_potential_keysize] = transposed_blocks[counter%current_potential_keysize] + bytes([ciphertext[counter]])
		counter = counter + 1

	return transposed_blocks

def break_repeating_key_xor(ciphertext):
	raw_ciphertext = base64.b64decode(ciphertext)

	potential_keysize = get_smallest_normalized_edit_distance(raw_ciphertext)

	transposed_blocks = get_transposed_blocks(raw_ciphertext, potential_keysize)

	key = ''
	score = 0.0

	for block in transposed_blocks:
		block_key, block_plaintext, block_score = challenge_03.detect_xor_key(block)
		key = key + block_key
		score = score + block_score

	return key

if __name__ == '__main__':

	HAMMING_DISTANCE_STRING_1 = 'this is a test'
	
	HAMMING_DISTANCE_STRING_2 = 'wokka wokka!!!'

	assert hamming_distance(HAMMING_DISTANCE_STRING_1.encode('utf-8'), HAMMING_DISTANCE_STRING_2.encode('utf-8')) == 37

	ciphertext_file = open("challenges/files/6.txt")

	ciphertext_file_contents = ciphertext_file.readlines()

	ciphertext = ""

	for line in ciphertext_file_contents:
		ciphertext = ciphertext + line.strip()

	raw_ciphertext = base64.b64decode(ciphertext)

	key = break_repeating_key_xor(ciphertext)

	plaintext_bytes = challenge_05.repeated_xor_encrypt(raw_ciphertext.decode('utf-8'), key)

	print("Key: " + key)
	print("Plaintext: \n" + plaintext_bytes.decode('utf-8'))
