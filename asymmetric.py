import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger()
logger.setLevel("INFO")


def asymmetric_keys_generation() -> tuple:
    """Function that generates private and public keys.

    Returns:
        tuple: tuple with private and public keys.
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    logging.info(f"Asymmetric keys successfully generated!")
    return (private_key, public_key)


def asymmetric_key_encryption(public_key, symmetric_key: bytes) -> bytes:
    """Function that encrypts symmetric key.

    Args:
        public_key (_type_): public key for asymmetric encryption.
        symmetric_key (bytes): symmetric key for symmetric encryption.

    Returns:
        bytes: encrypted symmetric key.
    """
    encrypted_symmetric_key = public_key.encrypt(symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric encryption was successful!")
    return encrypted_symmetric_key


def asymmetric_key_decryption(private_key, symmetric_key: bytes) -> bytes:
    """Function that decrypts symmetric key.

    Args:
        private_key (_type_): private key for asymmetric encryption.
        symmetric_key (bytes): symmetric key for symmetric encryption.

    Returns:
        bytes: decrypted symmetric key.
    """
    decrypted_symmetric_key = private_key.decrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric decryption was successful!")
    return decrypted_symmetric_key
