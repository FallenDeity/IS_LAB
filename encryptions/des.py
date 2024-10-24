import pathlib
from typing import TYPE_CHECKING

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


# DES CONFIGURATION VARIABLES
DES_KEY_SIZE = 8  # fixed for DES
DES_IV = b"12345678"  # fixed for DES

# TRIPLE DES CONFIGURATION VARIABLES
TRIPLE_DES_KEY_SIZE = 24  # fixed for Triple DES


class DESEncryption(BaseEncryption):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        cipher = DES.new(self.key, DES.MODE_OFB, iv=DES_IV)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = DES.new(self.key, DES.MODE_OFB, iv=DES_IV)
        return cipher.decrypt(data)

    @classmethod
    def from_user(cls, _: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/des/des.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                key = f.read()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = get_random_bytes(DES_KEY_SIZE)
            with key_path.open("wb") as f:
                f.write(key)
        return cls(key)


class TripleDESEncryption(BaseEncryption):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        cipher = DES3.new(self.key, DES.MODE_OFB, iv=DES_IV)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = DES3.new(self.key, DES.MODE_OFB, iv=DES_IV)
        return cipher.decrypt(data)

    @classmethod
    def from_user(cls, _: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/des/triple_des.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                key = f.read()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = get_random_bytes(TRIPLE_DES_KEY_SIZE)
            with key_path.open("wb") as f:
                f.write(key)
        return cls(key)
