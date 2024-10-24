import pathlib
from typing import TYPE_CHECKING, Generic, TypeVar

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY", bound=RSA.RsaKey)
PUBLIC_KEY = TypeVar("PUBLIC_KEY", bound=RSA.RsaKey)


# RSA CONFIGURATION VARIABLES
RSA_KEY_SIZE = 2048  # fixed for RSA


class RSAEncryption(BaseEncryption):
    def __init__(self, key: bytes) -> None:
        self.key = RSA.import_key(key)

    def encrypt(self, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(data)

    @property
    def public_key(self) -> PUBLIC_KEY:
        return self.key.publickey()

    @property
    def private_key(self) -> PRIVATE_KEY:
        return self.key

    @classmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
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


class HomomorphicRSAEncryption(RSAEncryption):
    def encrypt(self, data: bytes) -> bytes:
        m = bytes_to_long(data)
        return long_to_bytes(pow(m, self.key.e, self.key.n))

    def decrypt(self, data: bytes) -> bytes:
        c = bytes_to_long(data)
        return long_to_bytes(pow(c, self.key.d, self.key.n))
