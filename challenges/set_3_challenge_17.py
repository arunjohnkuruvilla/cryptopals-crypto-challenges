import random
import binascii
import base64
import string
import sys
import set_1_challenge_07 as challenge_07
import set_1_challenge_08 as challenge_08
import set_2_challenge_09 as challenge_09
import set_2_challenge_10 as challenge_10
import set_2_challenge_15 as challenge_15


class CBCPaddingOracle:
    def __init__(self):
        self._block_size = 16
        self._key = random.randbytes(self._block_size)
        self._plaintexts = [
            b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
            b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
            b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
            b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
            b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
            b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
            b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
            b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
            b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
            b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
        ]

    def encrypt(self):
        # Generate a random IV everytime an encryption operation is performed.
        iv = random.randbytes(self._block_size)

        choice = random.randint(0, len(self._plaintexts) - 1)
        plaintext_selected = self._plaintexts[choice]

        raw_plaintext_selected = base64.b64decode(plaintext_selected)

        padded_plaintext_selected = challenge_09.pkcs07_pad(raw_plaintext_selected, self._block_size)

        ciphertext = challenge_10.aes_cbc_encrypt(padded_plaintext_selected, 
            self._key, 
            iv,
            self._block_size
        )

        return ciphertext, iv

    def decrypt_and_validate_padding(self, ciphertext, iv):

        plaintext = challenge_10.aes_cbc_decrypt(ciphertext, 
            self._key, 
            iv,
            self._block_size
        )

        return challenge_15.is_pkcs07_padded(plaintext, self._block_size)

def create_manipulated_iv(current_iv, char_to_guess, padding_length, plaintext_block, block_size):

    # Index of the first character of the padding.
    index_of_manipulated_char = len(current_iv) - padding_length

    # Need to understand why padding_length needs to be added to the XOR to get the right IV character.
    manipulated_char = current_iv[index_of_manipulated_char] ^ char_to_guess ^ padding_length

    # Replace the exsiting character
    output = current_iv[:index_of_manipulated_char] + bytes([manipulated_char]) 

    i = 0

    # Replace every character after the manipulated character. Each character is XORed with the positional charaters 
    # identified till now.
    # Need to understand why padding_length needs to be added to the XOR to get the right IV character.
    for k in range(index_of_manipulated_char + 1, block_size):

        manipulated_char = current_iv[k] ^ plaintext_block[i] ^ padding_length

        output += bytes([manipulated_char])

        i += 1

    return output


def main():

    cbc_padding_oracle = CBCPaddingOracle()

    block_size = cbc_padding_oracle._block_size

    ciphertext, iv = cbc_padding_oracle.encrypt()

    plaintext = b''

    ciphertext_blocks = [iv] + [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # The indexing starts from 1 as the IV is added to the ciphertext block.
    for ciphertext_block_index in range (1, len(ciphertext_blocks)):

        plaintext_block = b''

        # Decryption starts from the end of the block.
        for i in range(block_size - 1, -1, -1):

            padding_length = len(plaintext_block) + 1

            possible_last_bytes = []

            # Loop through the character space.
            for j in range(256):

                manipulated_iv = create_manipulated_iv(ciphertext_blocks[ciphertext_block_index - 1],
                    j,
                    padding_length,
                    plaintext_block,
                    block_size
                )

                # Call the oracle to check if the padding is valid. 
                # The oracle will only approve a padding if it is of the following - 
                # | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |     
                #    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?  \x01
                # OR 
                # | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |     
                #    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?  \x02 \x02
                # OR
                # | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |     
                #    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?    ?  \x03 \x03 \x03
                # etc.
                # The decryption function can be used to identify which character when XORed with the character of the 
                # IV will result in valid padding.
                if cbc_padding_oracle.decrypt_and_validate_padding(ciphertext_blocks[ciphertext_block_index], manipulated_iv) is True:

                    # Add the character to the list of possible last bytes if the charater produces a valid PKCS07 
                    # padding in the plaintext.
                    possible_last_bytes += bytes([j])
            
            if len(possible_last_bytes) > 1:
                for byte in possible_last_bytes:
                    for j in range(256):
                        manipulated_iv = create_manipulated_iv(ciphertext_blocks[ciphertext_block_index - 1], 
                            j, 
                            padding_length + 1,
                            bytes([byte]) + plaintext_block,
                            block_size
                        )
                        if cbc_padding_oracle.decrypt_and_validate_padding(ciphertext_blocks[ciphertext_block_index], manipulated_iv) is True:

                            possible_last_bytes = [byte]
                            break

            if len(possible_last_bytes) > 0:
                plaintext_block = bytes([possible_last_bytes[0]]) + plaintext_block

        plaintext += plaintext_block
       
    print(challenge_09.pkcs07_unpad(plaintext))


if __name__ == '__main__':
    main()

