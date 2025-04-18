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

RANDOM_PREFIX_LENGTH = random.randint(1, 255)
RANDOM_PREFIX = random.randbytes(RANDOM_PREFIX_LENGTH)

def oracle(plaintext):

    append_text = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    append_text += b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    append_text += b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    append_text += b"YnkK"

    manipulated_plaintext = RANDOM_PREFIX
    manipulated_plaintext += plaintext
    manipulated_plaintext += base64.b64decode(append_text)
    manipulated_plaintext = challenge_09.pkcs07_pad(manipulated_plaintext)
    
    return challenge_07.aes_ecb_decrypt(manipulated_plaintext, ENCRYPTION_KEY)

def byte_at_a_time_ecb_hard(hidden_text_length, prefix_length, detected_block_size):

    extracted_hidden_text = b''

    filler_length = detected_block_size - (prefix_length % detected_block_size)

    for i in range(1, hidden_text_length):

        base = b'A'*(filler_length) + b'A' * ((hidden_text_length) * detected_block_size - i)

        check_length = prefix_length + (hidden_text_length) * detected_block_size + 1

        base_ciphertext = oracle(base)

        for char in string.printable:
            
            char_ciphertext = oracle(base + extracted_hidden_text + char.encode("ascii"))

            if base_ciphertext[0:check_length] == char_ciphertext[0:check_length]:
                extracted_hidden_text += char.encode("ascii")
                break

    return extracted_hidden_text

def detect_block_size():

    plaintext = b''
    ciphertext = oracle(plaintext)
    initial_length = len(ciphertext)
    new_length = initial_length

    while new_length == initial_length:
        plaintext += b'A'
        ciphertext = oracle(plaintext)
        new_length = len(ciphertext)

    return new_length - initial_length

def detect_equal_blocks(payload, detected_block_size):
    blocks = [payload[i:i+detected_block_size] for i in range(0, len(payload), detected_block_size)]

    for i in range(0, len(blocks) - 1):
        if blocks[i] == blocks[i+1]:
            return True
    return False

def detect_prefix_length(detected_block_size):

    ciphertext_empty = oracle(b'')
    blocks_empty = [ciphertext_empty[i:i+detected_block_size] for i in range(0, len(ciphertext_empty), detected_block_size)]

    ciphertext_one_char = oracle(b'A')
    blocks_one_char = [ciphertext_one_char[i:i+detected_block_size] for i in range(0, len(ciphertext_one_char), detected_block_size)]

    block_index = 0
    while block_index < len(blocks_one_char):
        if blocks_empty[block_index] != blocks_one_char[block_index]:
            break
        block_index += 1

    for i in range(0, detected_block_size):
        filler_plaintext = b'A' * (2 * detected_block_size + i)
        ciphertext = oracle(filler_plaintext)

        if detect_equal_blocks(ciphertext, detected_block_size):
            # return i
            if i == 0:
                return (block_index * detected_block_size)
            return (block_index * detected_block_size) + (detected_block_size - i)

    return -1


def main():
    detected_block_size = detect_block_size()

    prefix_length = detect_prefix_length(detected_block_size)

    hidden_text_length = len(oracle(b'')) - prefix_length

    hidden_text = byte_at_a_time_ecb_hard(hidden_text_length, prefix_length, detected_block_size)

    print(hidden_text.decode())


if __name__ == '__main__':
    main()
