import json

settings = {
    "text_file": "files/text_file.txt",
    "encrypted_file": "files/encrypted_file.txt",
    "decrypted_file": "files/decrypted_file.txt",
    "symmetric_key": "files/symmetric_key.txt",
    "public_key": "files/public_key.pem",
    "private_key": "files/private_key.pem"
}

if __name__ == "__main__":
    with open("settings.json", "w") as file:
        json.dump(settings, file)
