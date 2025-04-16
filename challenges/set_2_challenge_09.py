def pkcs07_pad(input_string, block_size = 16):
	padding_size = block_size - len(input_string)%block_size
	
	if padding_size == 0:
		return input_string
	else:
		return input_string + (bytes([padding_size]) * padding_size)

def pkcs07_unpad(input_string, block_size = 16):
	padding_size = input_string[-1]

	padding = input_string[(len(input_string) - padding_size):]

	padding_found = True

	for char in padding:
		if char != padding_size:
			padding_found = False

	if padding_found:
		return input_string[:-padding_size]
	return input_string
	
	# if padding_size == 0:
	# 	return input_string
	# else:
	# 	return input_string + (bytes([padding_size]) * padding_size)

def main():
	test_string = b'YELLOW_SUBMARINE'

	assert pkcs07_pad(test_string, 20) == b'YELLOW_SUBMARINE\x04\x04\x04\x04'

if __name__ == '__main__':
	main()