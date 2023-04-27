import argparse
import json

from asymmetric import (asymmetric_key_decryption, asymmetric_key_encryption,
                        asymmetric_keys_generation)
from read_functions import (byte_read_text, read_private_key, read_settings,)
from symmetric import (symmetric_key_generation,
                       symmetric_decryption, symmetric_encryption)
from write_functions import (byte_write_text, write_private_key)


if (__name__ == "__main__"):
    parser = argparse.ArgumentParser()
    parser.add_argument("-set", "--settings", type=str, help="Позволяет использовать собственный json-файл с указанием "
                                                             "необходимых настроек"
                                                             "(Введите путь к файлу)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-gen", "--generation",
                       help="Запускает режим генерации ключей")
    group.add_argument("-enc", "--encryption",
                       help="Запускает режим шифрования")
    group.add_argument("-dec", "--decryption",
                       help="Запускает режим дешифрования")

    args = parser.parse_args()

    if args.settings:
        with open(args.settings) as file:
            settings = read_settings(args.settings)

    else:
        with open("settings.json") as file:
            settings = json.load(file)

    if args.generation:
        private_key, public_key = asymmetric_keys_generation()
        symmetric_key = symmetric_key_generation()
        write_private_key(private_key, settings['private_key'])
        encrypted_symmetric_key = asymmetric_key_encryption(
            public_key, symmetric_key)
        byte_write_text(encrypted_symmetric_key, settings['symmetric_key'])

    elif args.encryption:
        symmetric_key = asymmetric_key_decryption(read_private_key(
            settings['private_key']), byte_read_text(settings['symmetric_key']))
        text = byte_read_text(settings['text_file'])
        cipher_text = symmetric_encryption(symmetric_key, text)
        byte_write_text(cipher_text, settings['encrypted_file'])

    elif args.decryption:
        symmetric_key = asymmetric_key_decryption(read_private_key(
            settings['private_key']), byte_read_text(settings['symmetric_key']))
        text = symmetric_decryption(
            symmetric_key, byte_read_text(settings['encrypted_file']))
        byte_write_text(text, settings['decrypted_file'])
