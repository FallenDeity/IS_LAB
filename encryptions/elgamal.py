import pathlib
from typing import TYPE_CHECKING, Generic, TypeVar

from Crypto.Util.number import (bytes_to_long, getPrime, getRandomRange,
                                long_to_bytes)

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY", bound=int)
PUBLIC_KEY = TypeVar("PUBLIC_KEY", bound=tuple[int, int, int])

# ELGAMAL CONFIGURATION VARIABLES
ELGAMAL_KEY_SIZE = 1024  # fixed for ElGamal


class ElGamalEncryption(BaseEncryption, Generic[PRIVATE_KEY, PUBLIC_KEY]):
    def __init__(self, p: int, g: int, y: int, x: int) -> None:
        self.p = p
        self.g = g
        self.y = y
        self.x = x

    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        k = getRandomRange(2, self.p - 1)
        r = pow(self.g, k, self.p)
        s = (bytes_to_long(data) * pow(self.y, k, self.p)) % self.p
        return long_to_bytes(r), long_to_bytes(s)

    def decrypt(self, data: tuple[bytes, bytes]) -> bytes:
        r, s = map(bytes_to_long, data)
        return long_to_bytes((s * pow(r, self.p - 1 - self.x, self.p)) % self.p)

    @property
    def public_key(self) -> PUBLIC_KEY:
        return self.p, self.g, self.y

    @property
    def private_key(self) -> PRIVATE_KEY:
        return self.x

    @classmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/elgamal/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                p, g, y, x = map(int, f.read().split())
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            p = getPrime(ELGAMAL_KEY_SIZE)
            g = getPrime(ELGAMAL_KEY_SIZE)
            x = getRandomRange(2, p - 1)
            y = pow(g, x, p)
            with key_path.open("wb") as f:
                f.write(f"{p} {g} {y} {x}".encode())
        return cls(p, g, y, x)
