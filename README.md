# NeoAli Secure Password Generator

This repository contains a secure password generator with *tamper-evident* configuration.

## Important security note
**private_key.pem is NOT included.** You must generate your own keypair using `generate_keys.py`
and keep the private key secret. Never commit `private_key.pem` to a public repository.

## Files
- `generate_keys.py` — generate an Ed25519 keypair (private_key.pem, public_key.pem)
- `create_config.py` — create and encrypt `config.json` and sign it (requires private_key.pem)
- `main.py` — verify signature, decrypt personal section, generate strong password
- `requirements.txt` — dependencies
- `README.md` — this file

## Quick start
```bash
python -m pip install -r requirements.txt
python generate_keys.py      # generate keys on your secure machine
python create_config.py      # create config.json and config.sig (requires private_key.pem)
python main.py               # run generator (requires config.json, config.sig, public_key.pem)
```
"# Password-Generator" 
