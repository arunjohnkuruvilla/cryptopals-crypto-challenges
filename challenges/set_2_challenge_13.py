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

def aes_encrypt_profile(email):
    plaintext = profile_for(email)
    return challenge_07.aes_ecb_encrypt(challenge_09.pkcs07_pad(plaintext.encode('ascii')), ENCRYPTION_KEY)

def aes_decrypt_profile(ciphertext):
    plaintext = challenge_07.aes_ecb_decrypt(ciphertext, ENCRYPTION_KEY)
    return key_value_parser(challenge_09.pkcs07_unpad(plaintext).decode("ascii"))

def key_value_parser(input):
    print(input)
    pairs = input.split('&')

    output = {}

    for pair in pairs:
        key = pair.split('=')[0]
        value = pair.split('=')[1]

        output[key] = value

    return output

def profile_for(email):

    email = email.replace('=', '')
    email = email.replace('&', '')

    return 'email=' + email + '&uid=10&role=user'

def detect_block_size():

    plaintext = ''
    ciphertext = aes_encrypt_profile(plaintext)
    initial_length = len(ciphertext)
    new_length = initial_length

    while new_length == initial_length:
        plaintext += 'A'
        ciphertext = aes_encrypt_profile(plaintext)
        new_length = len(ciphertext)

    return new_length - initial_length

def main():

    test_input = 'foo=bar&baz=qux&zap=zazzle'
    test_output = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }

    assert key_value_parser(test_input) == test_output

    assert profile_for("foo@bar.com") == 'email=foo@bar.com&uid=10&role=user'

    assert profile_for("foo@bar.com&role=admin") == 'email=foo@bar.comroleadmin&uid=10&role=user'

    ciphertext = aes_encrypt_profile("foo@bar.com")

    print(aes_decrypt_profile(ciphertext))

    detected_block_size = detect_block_size()

    # Assuming a block size of 16
    # Block 1               Block 2                                                 Block 3
    # email=xxxxxxxxxx      admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b       &uid=10&role=user
    # Block 1 - 'x's are added till the end of the block is reached.
    # Block 2 - the required keyword 'admin' is added, and the remaining block is PK7 padded. In the final 
    #       cut-and-pasted block, this block would be pasted at the end.
    # Block 3 - this block is not modified for the attack. The content are added by the oracle.
    first_plaintext = 'x' * (detected_block_size - len('email='))
    first_plaintext += 'admin' + (chr(detected_block_size - len('admin')) * (detected_block_size - len('admin')))
    
    first_ciphertext =  aes_encrypt_profile(first_plaintext)

    second_plaintext = 'x' * (detected_block_size - len('email='))
    second_plaintext += 'x' * (detected_block_size - len('&uid=10&role='))

    second_ciphertext =  aes_encrypt_profile(second_plaintext)

    modified_ciphertext = second_ciphertext[:detected_block_size*2] 
    modified_ciphertext += first_ciphertext[detected_block_size:detected_block_size*2]

    modified_plaintext = aes_decrypt_profile(modified_ciphertext)
    print(modified_plaintext)

if __name__ == '__main__':
    main()