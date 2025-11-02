import json
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass
import secrets
import string
from colorama import Fore, Style

CONFIG_PATH = "config.json"
SIG_PATH = "config.sig"
PUBLIC_KEY_PATH = "public_key.pem"

def verify_signature(config_bytes: bytes, sig_bytes: bytes, public_key_path: str) -> bool:
    with open(public_key_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise RuntimeError("Public key is not Ed25519")
    try:
        pub.verify(sig_bytes, config_bytes)
        return True
    except Exception:
        return False

def derive_key_from_passphrase(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=250_000
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))

def decrypt_personal_section(token_b64: str, salt_b64: str, passphrase: str) -> dict:
    token = base64.b64decode(token_b64)
    salt = base64.b64decode(salt_b64)
    key = derive_key_from_passphrase(passphrase.encode(), salt)
    f = Fernet(key)
    plaintext = f.decrypt(token)
    return json.loads(plaintext.decode())

def generate_strong_password(length: int = 24, entropy_source: str = "") -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    print(Fore.CYAN + "NeoAli Secure Password Generator\n" + Style.RESET_ALL)

    if not (os.path.exists(CONFIG_PATH) and os.path.exists(SIG_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        print(Fore.RED + "Missing required files: config.json, config.sig, or public_key.pem" + Style.RESET_ALL)
        return

    config_bytes = open(CONFIG_PATH, "rb").read()
    sig_bytes = open(SIG_PATH, "rb").read()

    if not verify_signature(config_bytes, sig_bytes, PUBLIC_KEY_PATH):
        print(Fore.RED + "Config signature invalid! Aborting. (Possible tampering detected)" + Style.RESET_ALL)
        return
    else:
        print(Fore.GREEN + "Config signature OK." + Style.RESET_ALL)

    config = json.loads(config_bytes.decode())
    passphrase = getpass("Enter your local passphrase to unlock personal section: ")
    try:
        personal = decrypt_personal_section(config["personal_encrypted"], config["personal_salt"], passphrase)
    except Exception:
        print(Fore.RED + "Failed to decrypt personal section. Wrong passphrase or corrupted data." + Style.RESET_ALL)
        return

    fixed_salt = personal.get("fixed_salt", "")
    owner = personal.get("owner", "owner")

    default_len = config.get("policy", {}).get("default_length", 24)
    try:
        length_input = input(f"Password length (default {default_len}): ")
        length = int(length_input) if length_input.strip() else default_len
    except ValueError:
        length = default_len

    password = generate_strong_password(length, entropy_source=f"{owner}{fixed_salt}")

    print(Fore.GREEN + "\n✅ Your strong password:\n" + Style.RESET_ALL + password + "\n")
    print(Fore.YELLOW + "Note: Personal section is encrypted and config is signature-verified." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
