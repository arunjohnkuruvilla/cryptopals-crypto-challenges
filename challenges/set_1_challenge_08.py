import binascii

def detect_ecb_encryption(string, block_size = 16):
	blocks = [string[i:i+block_size] for i in range(0, len(string), block_size)]

	blocks_without_duplicates = [*set(blocks)]

	if len(blocks_without_duplicates) < len(blocks):
		return True
	else:
		return False

def main():	
	ciphertext_file = open("challenges/files/8.txt")

	ciphertext_file_contents = ciphertext_file.readlines()

	lineNumber = 1

	for line in ciphertext_file_contents:
		raw_ciphertext_line = binascii.unhexlify(line.rstrip())

		if detect_ecb_encryption(raw_ciphertext_line):
			break

		lineNumber += 1
	
	print("Line #" + str(lineNumber))

if __name__ == '__main__':
	main()