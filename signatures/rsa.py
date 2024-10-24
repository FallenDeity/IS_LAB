import pathlib
from typing import TYPE_CHECKING

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from utils.hash import get_hash

from .base import BaseSignature

if TYPE_CHECKING:
    from utils.models import User


# RSA CONFIGURATION VARIABLES
RSA_KEY_SIZE = 2048  # fixed for RSA


class RSASignature(BaseSignature):
    def __init__(self, key: bytes) -> None:
        self.key = RSA.import_key(key)

    def sign(self, data: bytes) -> bytes:
        h = get_hash(data)
        return pkcs1_15.new(self.key).sign(h)

    def verify(self, data: bytes, signature: bytes) -> bool:
        h = get_hash(data)
        try:
            pkcs1_15.new(self.key).verify(h, signature)
        except ValueError:
            return False
        return True

    @classmethod
    def from_user(cls, user: "User") -> "BaseSignature":
        key_path = pathlib.Path(f"keys/rsa/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                key = f.read()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = RSA.generate(RSA_KEY_SIZE).export_key()
            with key_path.open("wb") as f:
                f.write(key)
        return cls(key)
