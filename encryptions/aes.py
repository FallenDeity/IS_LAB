import pathlib
from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


# AES CONFIGURATION VARIABLES
AES_KEY_SIZE = 16  # use 16 for AES128, 24 for AES192, 32 for AES256
AES_IV = b"1234567890123456"  # fixed for AES


class AESEncryption(BaseEncryption):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_OFB, iv=AES_IV)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_OFB, iv=AES_IV)
        return cipher.decrypt(data)

    @classmethod
    def from_user(cls, _: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/aes/aes.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                key = f.read()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = get_random_bytes(AES_KEY_SIZE)
            with key_path.open("wb") as f:
                f.write(key)
        return cls(key)
