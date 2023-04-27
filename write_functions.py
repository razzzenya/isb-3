import logging

from cryptography.hazmat.primitives import serialization

logger = logging.getLogger()
logger.setLevel("INFO")


def byte_write_text(text: bytes, file_name: str) -> None:
    """Function that write text in form of bytes.

    Args:
        text (bytes): text for writing.
        file_name (str): name of .txt file.
    """
    try:
        with open(file_name, "wb") as text_file:
            text_file.write(text)
        logging.info(f" Text was successfully written to file {file_name}!")
    except OSError as err:
        logging.warning(f" Text was not written to file {file_name}\n{err}!")


def write_private_key(private_key, private_pem: str) -> None:
    """Function that writes public and private keys into .pem files.

    Args:
        private_key (_type_): private key for asymmetric encoding algorithm.
        public_key (_type_): public key for asymmetric encoding algorithm.
        private_pem (str): name of .pem file for private key.
        public_pem (str): name of .pem file for public key.
    """
    try:
        with open(private_pem, "wb") as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f" Private key successfully saved to {private_pem}!")
    except OSError as err:
        logging.warning(
            f" Private key was not saved to file {private_pem}\n{err}!")
