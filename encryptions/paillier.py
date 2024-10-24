import pathlib
from typing import TYPE_CHECKING, Generic, TypeVar

from Crypto.Util.number import (GCD, bytes_to_long, getPrime, getRandomRange,
                                inverse, long_to_bytes)

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY", bound=tuple[int, int])
PUBLIC_KEY = TypeVar("PUBLIC_KEY", bound=tuple[int, int])


# Paillier CONFIGURATION VARIABLES
PAILLIER_KEY_SIZE = 1024  # fixed for Paillier


class PaillierEncryption(BaseEncryption):
    def __init__(self, p: int, q: int) -> None:
        self.p = p
        self.q = q
        self.n = p * q
        self.g = self.n + 1
        self.l = (self.p - 1) * (self.q - 1)
        self.m = inverse(self.l, self.n)

    def encrypt(self, data: bytes) -> bytes:
        m = bytes_to_long(data)
        r = getRandomRange(2, self.n)
        c = pow(self.g, m, self.n**2) * pow(r, self.n, self.n**2) % (self.n**2)
        return long_to_bytes(c)

    def decrypt(self, data: bytes) -> bytes:
        c = bytes_to_long(data)
        m = (pow(c, self.l, self.n**2) - 1) // self.n * self.m % self.n
        return long_to_bytes(m)

    @property
    def public_key(self) -> PUBLIC_KEY:
        return self.n, self.g

    @property
    def private_key(self) -> PRIVATE_KEY:
        return self.l, self.m

    @classmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/paillier/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                p, q = map(int, f.read().split())
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            while True:
                p = getPrime(PAILLIER_KEY_SIZE)
                q = getPrime(PAILLIER_KEY_SIZE)
                if GCD(p, q) == 1:
                    break
            with key_path.open("wb") as f:
                f.write(f"{p}\n{q}".encode())
        return cls(p, q)
