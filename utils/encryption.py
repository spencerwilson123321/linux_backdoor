"""
    This is the encryption module which contains the StreamEncryption class
    which contains all the functions necessary to perform stream encryption
    using shared secrets. It utilizes the ChaCha20 Stream Cipher.
"""
from os import urandom, system
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from secrets import token_bytes


class StreamEncryption:
    """
        The Stream Encryption class is a simple to use all in one
        stream encryption class. It uses the ChaCha20 stream cipher
        and provides functions to easily perform encryption and decryption.
    """
    def __init__(self):
        self.__secret = None
        self.__nonce = None
        self.__cipher = None
        self.__algorithm = None
        self.__encryptor = None
        self.__decryptor = None

    def generate_nonce(self):
        """
            Generates a random 16 byte nonce and saves it to nonce.bin
        """
        with open("nonce.bin", "wb") as f:
            f.write(urandom(16))

    def read_nonce(self, file_path) -> bool:
        """
            Reads a nonce from a file.
        """
        try:
            with open(file_path, "rb") as f:
                self.__nonce = f.read()
            return True
        except FileNotFoundError:
            return False

    def generate_secret(self):
        """
            Generates a cryptographically secure secret key that is
            32 bytes long. Saves it to secret.key
        """
        with open("secret.key", "wb") as f:
            f.write(token_bytes(32))

    def read_secret(self, file_path: str) -> bool:
        try:
            with open(file_path, "rb") as f:
                self.__secret = f.read()
            return True
        except FileNotFoundError:
            return False

    def initialize_encryption_context(self) -> bool:
        """
            Initializes instance variables that are necessary to perform
            encrypt and decrypt functions. Nonce and Secret must be defined
            prior to calling this function, otherwise it will do nothing.
        """
        if self.__nonce != None and self.__secret != None:
            self.__algorithm = ChaCha20(self.__secret, self.__nonce)
            self.__cipher = Cipher(self.__algorithm, mode=None)
            self.__encryptor = self.__cipher.encryptor()
            self.__decryptor = self.__cipher.decryptor()
            return True
        return False

    def encrypt(self, cleartext: bytes):
        """
            Encrypts the given cleartext using the ChaCha20 stream cipher and
            established secret key.
        """
        return self.__encryptor.update(cleartext)

    def decrypt(self, ciphertext: bytes):
        """
            Decrypts the given ciphertext using the ChaCha20 stream cipher and
            established secret key.
        """
        return self.__decryptor.update(ciphertext)
