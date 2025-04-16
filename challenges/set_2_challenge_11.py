import random
import binascii
import set_1_challenge_07 as challenge_07
import set_1_challenge_08 as challenge_08
import set_2_challenge_09 as challenge_09
import set_2_challenge_10 as challenge_10

def oracle(plaintext):
    random_key = random.randbytes(16)

    choice = random.randint(0, 1)

    prepend_text_length = random.randint(5, 10)
    prepend_text = random.randbytes(prepend_text_length)

    append_text_length = random.randint(5, 10)
    append_text = random.randbytes(append_text_length)

    manipulated_input = challenge_09.pkcs07_pad(prepend_text + plaintext + append_text)

    if choice == 0:
        random_iv = random.randbytes(16)
        return challenge_10.aes_cbc_encrypt(manipulated_input, random_key, random_iv)
    else:
        return challenge_07.aes_ecb_decrypt(manipulated_input, random_key)


def main():

    ciphertext = oracle(b'A'*60)
    print(ciphertext)
    print(challenge_08.detect_ecb_encryption(ciphertext))


if __name__ == '__main__':
	main()