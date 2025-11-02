import json
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from getpass import getpass

CONFIG_PATH = "config.json"
SIG_PATH = "config.sig"
PRIVATE_KEY_PATH = "private_key.pem"

plain_config = {
    "project": "NeoAli Password Generator - Secure",
    "version": "1.0",
    "personal": {
        "owner": "Ali",
        "fixed_salt": "REPLACE_WITH_RANDOM_OR_KEEP"
    },
    "policy": {
        "default_length": 16,
        "min_length": 8,
        "max_length": 64
    }
}

def derive_key_from_passphrase(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=250_000
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))

def encrypt_personal_section(personal_obj, passphrase: str):
    salt = os.urandom(16)
    key = derive_key_from_passphrase(passphrase.encode(), salt)
    f = Fernet(key)
    plaintext = json.dumps(personal_obj).encode()
    token = f.encrypt(plaintext)
    return base64.b64encode(token).decode(), base64.b64encode(salt).decode()

def sign_config(config_bytes: bytes, private_key_path: str) -> bytes:
    with open(private_key_path, "rb") as f:
        pk = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(pk, ed25519.Ed25519PrivateKey):
        raise RuntimeError("Private key is not Ed25519")
    signature = pk.sign(config_bytes)
    return signature

def main():
    if not os.path.exists(PRIVATE_KEY_PATH):
        print("private_key.pem not found. Run generate_keys.py first and keep private key safe.")
        return

    passphrase = getpass("Enter a strong local passphrase (used to encrypt personal section): ")
    if not passphrase:
        print("Passphrase required.")
        return

    encrypted_personal, salt_b64 = encrypt_personal_section(plain_config["personal"], passphrase)
    config_to_write = {
        "project": plain_config["project"],
        "version": plain_config["version"],
        "personal_encrypted": encrypted_personal,
        "personal_salt": salt_b64,
        "policy": plain_config["policy"]
    }

    bytes_config = json.dumps(config_to_write, indent=2).encode()
    signature = sign_config(bytes_config, PRIVATE_KEY_PATH)

    with open(CONFIG_PATH, "wb") as f:
        f.write(bytes_config)
    with open(SIG_PATH, "wb") as f:
        f.write(signature)

    print(f"Wrote {CONFIG_PATH} and {SIG_PATH}. You can add public_key.pem and config.json + config.sig to repo.")
    print("Do NOT add private_key.pem to the repository.")

if __name__ == "__main__":
    main()
