import binascii

def xor(sequence_1, sequence_2):
	
	if len(sequence_1) != len(sequence_2):
		raise Exception("Inputs are of unequal length")
	
	return bytes(a ^ b for a, b in zip(sequence_1, sequence_2))

if __name__ == "__main__":
	INPUT_STRING_1 = "1c0111001f010100061a024b53535009181c"
	RAW_INPUT_STRING_1 = binascii.unhexlify(INPUT_STRING_1)

	INPUT_STRING_2 = "686974207468652062756c6c277320657965"
	RAW_INPUT_STRING_2 = binascii.unhexlify(INPUT_STRING_2)

	OUTPUT_STRING = "746865206b696420646f6e277420706c6179"
	RAW_OUTPUT_STRING = binascii.unhexlify(OUTPUT_STRING)

	assert RAW_OUTPUT_STRING == xor(RAW_INPUT_STRING_1, RAW_INPUT_STRING_2)
