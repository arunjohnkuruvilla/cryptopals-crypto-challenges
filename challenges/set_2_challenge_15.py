def pkcs07_unpad(input_string, block_size = 16):
	padding_size = input_string[-1]

	padding = input_string[(len(input_string) - padding_size):]

	padding_found = True

	for char in padding:
		if char != padding_size:
			raise Exception("Invalid Padding")

	if padding_found:
		return input_string[:-padding_size]
	return input_string

def main():
    assert pkcs07_unpad(b'ICE ICE BABY\x04\x04\x04\x04') == b'ICE ICE BABY'

    try:
        pkcs07_unpad(b'ICE ICE BABY\x05\x05\x05\x05')
    except Exception as e:
        assert str(e) == "Invalid Padding"

    try:
        pkcs07_unpad(b'ICE ICE BABY\x01\x02\x03\x04')
    except Exception as e:
        assert str(e) == "Invalid Padding"


if __name__ == '__main__':
    main()