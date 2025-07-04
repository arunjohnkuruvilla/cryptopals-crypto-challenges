import binascii
import re
import string

FREQUENCIES = { 
	'a': 0.0651738,
	'b': 0.0124248,
	'c': 0.0217339,
	'd': 0.0349835,
	'e': 0.1041442,
	'f': 0.0197881,
	'g': 0.0158610,
	'h': 0.0492888,
	'i': 0.0558094,
	'j': 0.0009033,
	'k': 0.0050529,
	'l': 0.0331490,
	'm': 0.0202124,
	'n': 0.0564513,
	'o': 0.0596302,
	'p': 0.0137645,
	'q': 0.0008606,
	'r': 0.0497563,
	's': 0.0515760,
	't': 0.0729357,
	'u': 0.0225134,
	'v': 0.0082903,
	'w': 0.0171272,
	'x': 0.0013692,
	'y': 0.0145984,
	'z': 0.0007836,
	' ': 0.1918182 
}

charspace = string.ascii_letters + string.digits + ",.' :\n"

def single_byte_raw_xor(input_string, key):
	return ''.join(map(lambda x: chr(x ^ key), input_string))

def single_byte_xor(input_string, key):
	return ''.join(map(lambda x: chr(x ^ ord(key)), input_string))

def english_score(plaintext):
	score = 0
	score_content = []

	for x in plaintext:
		if x.lower() in FREQUENCIES:
				score_content.append(x.lower())
				score += FREQUENCIES.get(x.lower())

	return score, score_content

def detect_xor_key(ciphertext):
	scores = {}
	results = {}

	for char_int in range(0,256):
		char = chr(char_int)

		output_string = single_byte_xor(ciphertext, char)

		score = 0.0

		printable = True

		for x in output_string:
			if x not in string.printable:
				printable = False
				break
		
		if not printable:
			continue

		for x in output_string:
			if x.lower() in FREQUENCIES:
				score += FREQUENCIES.get(x.lower())

		scores[char] = score
		results[char] = output_string


	if (len(scores) > 0):
		sorted_scores = dict(sorted(scores.items(), key=lambda item: item[1], reverse=True)[:1])

		for key in sorted_scores.keys():
			return key, results[key], sorted_scores[key]
	else:
		return "NONE", "", 99999

def main():
	INPUT_STRING = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	RAW_INPUT_STRING = binascii.unhexlify(INPUT_STRING)
	
	key, plaintext, score = detect_xor_key(RAW_INPUT_STRING)

	print(key + ": " + plaintext)

if __name__ == '__main__':
	main()

