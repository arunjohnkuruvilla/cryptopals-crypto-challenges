import base64
import struct
import set_1_challenge_02 as challenge_02
import set_1_challenge_07 as challenge_07


def aes_ctr(data_stream, key, nonce, block_size):
    output_stream = b''

    counter = 0

    while data_stream:

        # '<' - Little endian
        # 'Q' - Unsigned long long
        # 64 bit unsigned number is 8 bytes. This translates to an unsigned long long number which is 8 bytes.
        nonce_and_counter_block = struct.pack('<QQ', nonce, counter)

        # Encrypt the nonce and counter block.
        encrypted_counter = challenge_07.aes_ecb_encrypt(nonce_and_counter_block, key)

        # XOR the data stream upto the a block size or less.
        output_stream += challenge_02.xor(encrypted_counter, data_stream[:block_size])

        # Shrink the data stream by a block size.
        data_stream = data_stream[block_size:]

        # Increment the counter after each encryption/decryption.
        counter += 1

    return output_stream


def main():

    encrypted_stream = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

    raw_encrypted_stream = base64.b64decode(encrypted_stream)

    print(aes_ctr(raw_encrypted_stream, b'YELLOW SUBMARINE', 0, 16))


if __name__ == '__main__':
    main()