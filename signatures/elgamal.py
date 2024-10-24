import pathlib
from typing import TYPE_CHECKING

from Crypto.Util.number import (GCD, bytes_to_long, getPrime, getRandomRange,
                                inverse, long_to_bytes)

from utils.hash import get_hash

from .base import BaseSignature

if TYPE_CHECKING:
    from utils.models import User


# ELGAMAL CONFIGURATION VARIABLES
ELGAMAL_KEY_SIZE = 1024  # fixed for ElGamal


class ElGamalSignature(BaseSignature):
    def __init__(self, p: int, g: int, y: int, x: int) -> None:
        self.p = p
        self.g = g
        self.y = y
        self.x = x

    def sign(self, data: bytes) -> tuple[bytes, bytes]:
        h = get_hash(data)
        digest = bytes_to_long(h.digest())
        while True:
            k = getRandomRange(2, self.p - 1)
            if GCD(k, self.p - 1) == 1:
                break
        r = pow(self.g, k, self.p)
        s = (digest - self.x * r) * inverse(k, self.p - 1) % (self.p - 1)
        return long_to_bytes(r), long_to_bytes(s)

    def verify(self, data: bytes, signature: tuple[bytes, bytes]) -> bool:
        h = get_hash(data)
        digest = bytes_to_long(h.digest())
        r, s = map(bytes_to_long, signature)
        if not 0 < r < self.p or not 0 < s < self.p - 1:
            return False
        v1 = pow(self.y, r, self.p) * pow(r, s, self.p) % self.p
        v2 = pow(self.g, digest, self.p)
        return v1 == v2

    @classmethod
    def from_user(cls, user: "User") -> "BaseSignature":
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
