import random
import binascii
import base64
import string
import set_1_challenge_07 as challenge_07
import set_1_challenge_08 as challenge_08
import set_2_challenge_09 as challenge_09
import set_2_challenge_10 as challenge_10

BLOCK_SIZE = 16

ENCRYPTION_KEY = random.randbytes(BLOCK_SIZE)

def oracle(plaintext):

    append_text = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    append_text += b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    append_text += b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    append_text += b"YnkK"

    manipulated_plaintext = challenge_09.pkcs07_pad(plaintext + base64.b64decode(append_text))
    
    return challenge_07.aes_ecb_decrypt(manipulated_plaintext, ENCRYPTION_KEY)

def detect_block_size():

    plaintext = b'A'

    while len(plaintext) < 40:
        ciphertext = oracle(plaintext)

        if challenge_08.detect_ecb_encryption(ciphertext):
            break

        plaintext += b'A'

    return int(len(plaintext)/2)

def byte_at_a_time_ecb_simple(hidden_text_length):

    extracted_hidden_text = b''

    for i in range(1, hidden_text_length):

        base = b'A'*(hidden_text_length - i)

        base_ciphertext = oracle(base)

        for char in string.printable:
            
            char_ciphertext = oracle(base + extracted_hidden_text + char.encode("utf-8"))

            if base_ciphertext[0:hidden_text_length] == char_ciphertext[0:hidden_text_length]:
                extracted_hidden_text += char.encode("utf-8")
                break

    return extracted_hidden_text

def main():

    detected_block_size = detect_block_size()

    # To identify if the encryption mode is ECB, ecrypt a string that is several multiples of the detected block size.
    assert challenge_08.detect_ecb_encryption(b'A' * detected_block_size * 4) == True

    # The length of the hidden text will be equal to the length of the ciphertext when encrypting an empty string.
    hidden_text_length = len(oracle(b''))

    hidden_text = byte_at_a_time_ecb_simple(hidden_text_length)

    print(hidden_text.decode())

if __name__ == '__main__':
	main()