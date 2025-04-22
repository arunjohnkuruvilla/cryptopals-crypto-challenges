import random
import binascii
import base64
import string
import set_1_challenge_07 as challenge_07
import set_1_challenge_08 as challenge_08
import set_2_challenge_09 as challenge_09
import set_2_challenge_10 as challenge_10
import set_2_challenge_15 as challenge_15


class CBCOrable:
    def __init__(self):
        self._block_size = 16
        self._iv = random.randbytes(self._block_size)
        self._key = random.randbytes(self._block_size)
        self._prefix = b'comment1=cooking%20MCs;userdata='
        self._suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def function_1(self, plaintext):
        filtered_plaintext = plaintext.replace(b';', b'')
        filtered_plaintext = plaintext.replace(b'=', b'')

        manipulated_plaintext = self._prefix + plaintext + self._suffix
        padded_plaintext = challenge_09.pkcs07_pad(manipulated_plaintext, self._block_size)

        ciphertext = challenge_10.aes_cbc_encrypt(padded_plaintext, 
            self._key, 
            self._iv, 
            self._block_size
        )

        return ciphertext

    def function_2(self, ciphertext):
        padded_plaintext = challenge_10.aes_cbc_decrypt(ciphertext, 
            self._key, 
            self._iv, 
            self._block_size)

        unpadded_plaintext = challenge_15.pkcs07_unpad(padded_plaintext, self._block_size)

        return b';admin=true;' in unpadded_plaintext


def main():
    cbc_oracle = CBCOrable()

    # TODO - Compute this dynamically
    block_size = cbc_oracle._block_size
    # TODO - Compute this dynamically as in an ideal case the prefix string may not be known
    prefix_length = len(cbc_oracle._prefix)

    # Compute the length of additional bytes required to pad the prefix to the block size.
    prefix_pad_length = (block_size - (prefix_length % block_size)) % block_size

    # An additional block is added to enable replacement.
    total_prefix_length = prefix_length + prefix_pad_length + block_size

    # An intermediate plaintext is first to be encrypted. The '?' character is used as we know that this is character 
    # will not be encoded. This character will in the future be converted to '=' and ';' through CBC bit flipping.
    intermediate_plaintext = b'?admin?true'
    intermediate_plaintext_prefix_length = (block_size - (len(intermediate_plaintext) % block_size)) % block_size

    # The final plaintext block will be -
    # |01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|     
    #   ?  ?  ?  ?  ?  ?  a  d  m  i  n  ?  t  r  u  e
    # The plaintext is prepended with '?' to align the intermediate plaintext to the end of the block. 
    final_plaintext = intermediate_plaintext_prefix_length * b'?' + intermediate_plaintext

    # The pad for the prefix is also added to keep the intermediate plaintext aligned to the end of the block. An 
    # additional block of all '?' is also added to ensure that the byte can be XORed correctly to the required value
    prefix_aligned_plaintext = prefix_pad_length * b'?' + block_size * b'?' +  final_plaintext

    ciphertext = cbc_oracle.function_1(prefix_aligned_plaintext)

    # The 11th byte from the end of the previous block of the plaintext needs to be changed, so that the 11th byte of 
    # the plaintext is changed from a '?' to a ';'.
    # XORing a byte with itself is 0. This can then be changed to any byte value needed during decryption.
    semicolon = ciphertext[total_prefix_length - 11] ^ ord('?') ^ ord(';')

    # The 5th byte from the end of the previous block of the plaintext needs to be changed, so that the 5th byte of 
    # the plaintext is changed from a '?' to a '='.
    # XORing a byte with itself is 0. This can then be changed to any byte value needed during decryption.
    equals = ciphertext[total_prefix_length - 5] ^ ord('?') ^ ord('=')

    manipulated_ciphertext = ciphertext[:total_prefix_length - 11]
    manipulated_ciphertext += bytes([semicolon])
    manipulated_ciphertext += ciphertext[total_prefix_length - 10: total_prefix_length - 5]
    manipulated_ciphertext += bytes([equals])
    manipulated_ciphertext += ciphertext[total_prefix_length - 4:]

    assert cbc_oracle.function_2(manipulated_ciphertext) == True

if __name__ == '__main__':
    main()