import base64
import binascii

INPUT_STRING = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

OUTPUT_STRING = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

def get_base64_string_from_hex_encoded_string(hex_encoded_input):
	return base64.b64encode(binascii.unhexlify(hex_encoded_input))

print(get_base64_string_from_hex_encoded_string(INPUT_STRING))

print(OUTPUT_STRING.encode('ASCII') == get_base64_string_from_hex_encoded_string(INPUT_STRING))