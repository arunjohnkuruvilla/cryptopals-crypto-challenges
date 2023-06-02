import binascii

INPUT_STRING_1 = "1c0111001f010100061a024b53535009181c"

INPUT_STRING_2 = "686974207468652062756c6c277320657965"

OUTPUT_STRING = "746865206b696420646f6e277420706c6179"

def xor(hex_encoded_input_1, hex_encoded_input_2):
	

	hex_decoded_input_1 = binascii.unhexlify(hex_encoded_input_1)
	hex_decoded_input_2 = binascii.unhexlify(hex_encoded_input_2)

	if len(hex_decoded_input_1) != len(hex_decoded_input_2):
		raise Exception("Inputs are of unequal length")
	output = ""

	for counter, char in enumerate(hex_decoded_input_1):
		output += chr(hex_decoded_input_1[counter] ^ hex_decoded_input_2[counter])

	return binascii.hexlify(output.encode('ascii'))

print(OUTPUT_STRING.encode('ASCII') == xor(INPUT_STRING_1, INPUT_STRING_2))
