import binascii
import re
import string

INPUT_STRING = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

FREQUENCIES = { 
	'a': 0.082,
	'b': 0.015,	
	'c': 0.028,
	'd': 0.043,
	'e': 0.13,
	'f': 0.022,
	'g': 0.02,
	'h': 0.061,
	'i': 0.07,
	'j': 0.0015,
	'k': 0.0077,
	'l': 0.04,
	'm': 0.024,
	'n': 0.067,
	'o': 0.075,
	'p': 0.019,
	'q': 0.00095,
	'r': 0.06,
	's': 0.063,
	't': 0.091,
	'u': 0.028,
	'v': 0.0098,
	'w': 0.024,
	'x': 0.0015,
	'y': 0.02,
	'z': 0.00074
}

charspace = string.ascii_letters + string.digits + ",.' :\n"

def string_xor(input_string, int_key):
	return ''.join(map(lambda x: chr(x ^ int_key), input_string))

def getChi2(input_string):
	count = []
	ignored = 0

	for i in range(0,26):
		count.append(0)

	for char in input_string:
		char_int = ord(char)
		if (char in string.ascii_uppercase):
			count[char_int - 65] += 1
		elif (char in string.ascii_lowercase):
			count[char_int - 97] += 1
		elif (char in string.punctuation or char in string.whitespace):
			ignored += 0
		else:
			return 99999

	chi2 = 0.0
	length = len(input_string) - ignored

	for i in range(0, 26):
		observed = float(count[i])
		expected = float(length * FREQUENCIES[chr(i + 97)])
		difference = observed - expected
		chi2 += (difference*difference)/expected

	return chi2

def letter_to_symbol_score(input_string):
	letters = 0
	symbols = 0
	for char in input_string:
		if char in string.ascii_uppercase or char in string.ascii_lowercase or char == " ":
			letters += 1
	return (letters*100)/len(input_string)

def is_string_printable(input_string):
    for char in input_string:
        if char not in charspace:
            return False;
    return True


def detect_xor_key(input_string):
	scores = {}
	results = {}

	for char_int in range(0,255):
		char = chr(char_int)
		raw_string = binascii.unhexlify(input_string)

		output_string = string_xor(raw_string, ord(char))

		# for punc_char in string.punctuation:
			
		# 	pretty_result = pretty_result.replace(punc_char, '')

		pretty_result = re.sub(r'[\x00-\x1F]+', '', output_string)

		if not is_string_printable(pretty_result):

			continue

		scores[char] = getChi2(pretty_result)
		results[char] = pretty_result

	if (len(scores) > 0):
		sorted_scores = dict(sorted(scores.items(), key=lambda item: item[1])[:1])


		for key in sorted_scores.keys():
			return key, results[key], sorted_scores[key]
	else:
		return "NONE", "", 99999

def main():
	key, plaintext, score = detect_xor_key(INPUT_STRING)

	print(key + ": " + plaintext)

if __name__ == '__main__':
	main()

