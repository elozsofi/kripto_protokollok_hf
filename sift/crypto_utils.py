from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def load_public_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def rsa_encrypt(pubkey, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data)

def rsa_decrypt(privkey, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(data)

def derive_key(client_random: bytes, server_random: bytes, salt: bytes) -> bytes:
    return HKDF(
        master=client_random + server_random,
        key_len=32,
        salt=salt,
        hashmod=SHA256
    )

def hash_password(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password=password,
        salt=salt,
        dkLen=32,
        count=100000,
        hmac_hash_module=SHA256
    )