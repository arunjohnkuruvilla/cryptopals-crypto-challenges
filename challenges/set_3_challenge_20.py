import base64
import struct
import random
import base64
import string
import set_1_challenge_02 as challenge_02
import set_1_challenge_03 as challenge_03
import set_1_challenge_07 as challenge_07
import set_3_challenge_18 as challenge_18

PLAINTEXTS = [
    'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
]

def get_key_for_column(column_stream):
    print("column_stream", column_stream)
    possible_key_chars = []

    key_candidate = 0
    key_score = 0.0
    key_plaintext = b''
    key_score_content = []

    for key in range(256):
        curr_plaintext = challenge_03.single_byte_raw_xor(column_stream, key)

        printable = True
        for char in curr_plaintext:
            if char not in string.printable or char == '^':
                printable = False

        if not printable:
            continue

        curr_score, curr_score_content = challenge_03.english_score(curr_plaintext)

        if curr_score > key_score:
            key_score = curr_score
            key_candidate = key
            key_plaintext = curr_plaintext
            key_score_content = curr_score_content

    print("key_plaintext", key_plaintext)
    print("key_score", key_score)
    print("key_score_content", key_score_content)
    return bytes([key_candidate])

def crack_aes_ctr_same_nonce_v1(ciphertexts):
    keystream = bytearray(b'')

    plaintexts = []

    for i in range(max(map(len, ciphertexts))):

        column = b''
        for c in ciphertexts:
            column += bytes([c[i]]) if i < len(c) else b''

        key_for_column = get_key_for_column(column)

        keystream += key_for_column

    for ciphertext in ciphertexts:
        plaintexts.append(challenge_02.xor(ciphertext, keystream))
        

    return plaintexts

def main():
    # Set a smallest block size. The decryption works parially for block sizes 24 and 32.
    block_size = 16

    # Generate a random key.
    key = random.randbytes(block_size)

    original_plaintexts = []
    ciphertexts = []

    plaintexts_file = open('challenges/files/20.txt')
    plaintexts_file_content = plaintexts_file.readlines()

    for plaintext in plaintexts_file_content:
        raw_plaintext = base64.b64decode(plaintext.strip())
        original_plaintexts.append(raw_plaintext)
        ciphertexts.append(challenge_18.aes_ctr(raw_plaintext, key, 0, block_size))

    # min_length_ciphertext = min(map(len,ciphertexts))

    # for i in range(0, len(ciphertexts)):
    #     ciphertexts[i] = ciphertexts[i][:min_length_ciphertext]

    plaintexts = crack_aes_ctr_same_nonce_v1(ciphertexts)

    for plaintext, original in zip(plaintexts, original_plaintexts):
        print(plaintext)
        # print(original)
        

if __name__ == '__main__':
    main()
