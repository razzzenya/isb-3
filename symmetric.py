import logging
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger()
logger.setLevel("INFO")


def symmetric_key_generation() -> bytes:
    """Function that generates a key for or symmetric encryption algorithm.

    Returns:
        bytes: key for symmetric encryption algorithm.
    """
    key = os.urandom(16)
    logging.info("Symmetric key successfully generated!")
    return key


def symmetric_encryption(key: bytes, text: bytes) -> bytes:
    """Function that encrypts text with symmetric key.

    Args:
        key (bytes): symmetric key that is needed to encrypt the text.
        text (bytes): text for encryption.

    Returns:
        bytes: encrypted text with iv.
    """
    padder = padding.ANSIX923(128).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info("Symmetric encryption was successful!")
    return iv + cipher_text


def symmetric_decryption(key: bytes, cipher_text: bytes) -> bytes:
    """Function that decrypts cipher thext with symmetric key.

    Args:
        key (bytes): symmetric key that is needed to encrypt the text.
        cipher_text (bytes): ciphertext with iv.

    Returns:
        bytes: decrypted text.
    """
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(128).unpadder()
    result = unpadder.update(text) + unpadder.finalize()
    logging.info("Symmetric decryption was successful!")
    return result
