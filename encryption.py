from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import hashlib
from Crypto.Random import get_random_bytes


auth_salt = get_random_bytes(16)
crypto_salt = get_random_bytes(16)


def password_hash(password: str, auth_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        auth_salt,
        200_000
    )


def verify_password(plain_password: str, hashed_password: str, auth_salt: bytes) -> bool:
    plain_password_hashed = password_hash(plain_password, auth_salt)
    if plain_password_hashed == hashed_password:
        return True
    return False


rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.public_key().export_key()


def key_to_encrypt_private(password: str):
    return PBKDF2(password, crypto_salt, dkLen=32)
