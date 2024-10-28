"""
Please use this file as the starter kit for your third CryptoPal challenge coding assignment.
Do not change the file name and the existing function names. You may add helper functions.
Please be careful with the return type of each function to make sure your function will pass the autograder tests.
Function documentations are provided as some simple guidance for you to write code, feel free to remove/change them.
"""
from base64 import b64decode
# please make sure you have the cryptography library installed to be able to import the following
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Hardcode a key and an IV; feel free to change them for testing purpose.
IV = b"\x00" * 16
KEY = b"YELLOW SUBMARINE"


def aes_cbc_encrypt(iv: bytes, key: bytes, message: bytes) -> bytes:
    """AES CBC mode encryption.

    :param iv: initialization vector, should be 16 bytes.
    :param key: encryption key, should be 16 bytes.
    :param message: message to encrypt, the number of bytes it contains should be a multiple of 16.
    :return: the ciphertext.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()


def aes_cbc_decrypt(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    """AES CBC mode decryption.

    :param iv: initialization vector, should be 16 bytes.
    :param key: encryption key, should be 16 bytes.
    :param ciphertext: ciphertext to decrypt, the number of bytes it contains should be a multiple of 16.
    :return: the plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def pkcs_pad(message: bytes) -> bytes:
    """Performs the PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message)
    return padded_data + padder.finalize()


def pkcs_unpad(message: bytes) -> bytes:
    """Removes the PKCS#7 padding."""
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(message)
    return unpadded_data + unpadder.finalize()


def check_pkcs7_padding(message: bytes) -> bool:
    """Check if a plaintext has a valid PKCS#7 padding.

    See https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method for details and examples of PKCS#7.
    :param message: byte representation of a message
    :return: boolean value that indicates whether this message contains a valid PKCS#7 padding.
    """

    try:
        pkcs_unpad(message)

    # Depends on whether an error occurred, return a boolean.
    except ValueError:
        return False
    else:
        return True

# TODO: You need to implement the following functions; functions above are provided for your convenience.
def encrypt_random_str(iv: bytes = b"\x00" * 16, key: bytes = b"YELLOW SUBMARINE") -> bytes:
    """Select a message from the provided list; pad it and use aes-cbc to encrypt it.

    Note that this function is the first function described in Challenge 17.
    :return: the ciphertext.
    """
    messages = list(map(b64decode, [
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
    ]))


def check_padding(iv: bytes, ciphertext: bytes) -> bool:
    """Decrypts a message using aes-cbc and checks whether it has a valid PKCS#7 padding.

    This should check aes_cbc_decrypt(iv, key, ciphertext) has a valid padding.
    We hardcoded the key because we want you to use this function as a black box. (Hence the key is not an input)
    Note that this function is the second function described in Challenge 17.
    :param iv: the initialization vector.
    :param ciphertext: some ciphertext that was encrypted using aes-cbc.
    :return: a boolean indicating whether the decrypted message has a valid PKCS#7 padding.
    """
    key = KEY


def question_17(iv: bytes, ciphertext: bytes, oracle: callable) -> bytes:
    """Performs the CBC padding oracle attack.

    Here you are given a ciphertext and oracle, which is a callable function, for example, the check_padding function.
    When you call oracle(ciphertext), it decrypts the ciphertext and tells you whether it has a valid padding.
    :param iv: The IV used to encrypt the ciphertext.
    :param ciphertext: some ciphertext that was encrypted using aes-cbc.
    :param oracle: a callable function that returns whether the input to it has a valid padding after decryption.
        This oracle takes input an IV, and a ciphertext. The oracle hardcodes the KEY that was used to encrypt the
        ciphertext.
    :return: the decrypted message. !!!PLEASE REMOVE the padding before return the decrypted message!!!
    """



