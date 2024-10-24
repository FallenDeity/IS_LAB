import pathlib
from typing import TYPE_CHECKING, Generic, TypeVar

from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY", bound=tuple[int, int])
PUBLIC_KEY = TypeVar("PUBLIC_KEY", bound=int)


# RABIN CONFIGURATION VARIABLES
RABIN_KEY_SIZE = 1024  # fixed for Rabin


class RabinEncryption(BaseEncryption):
    def __init__(self, p: int, q: int) -> None:
        self.p = p
        self.q = q
        self.n = p * q
        self.m = p * q

    def encrypt(self, data: bytes) -> bytes:
        m = bytes_to_long(data)
        return long_to_bytes(pow(m, 2, self.n))

    def decrypt(self, data: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        c = bytes_to_long(data)
        mp = pow(c, (self.p + 1) // 4, self.p)
        mq = pow(c, (self.q + 1) // 4, self.q)
        yp, yq = self._extended_gcd(self.p, self.q)
        r = (yp * self.p * mq + yq * self.q * mp) % self.n
        return long_to_bytes(r), long_to_bytes(self.n - r), long_to_bytes(self.n + r), long_to_bytes(self.m - r)

    def _extended_gcd(self, a: int, b: int) -> tuple[int, int]:
        if a == 0:
            return 0, 1
        x, y = self._extended_gcd(b % a, a)
        return y - (b // a) * x, x

    @property
    def public_key(self) -> PUBLIC_KEY:
        return self.n

    @property
    def private_key(self) -> PRIVATE_KEY:
        return self.p, self.q

    @classmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/rabin/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                p, q = map(int, f.read().split())
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            while True:
                p = getPrime(RABIN_KEY_SIZE)
                q = getPrime(RABIN_KEY_SIZE)
                # check if p and q are congruent to 3 mod 4
                if p % 4 == 3 and q % 4 == 3:
                    break
            with key_path.open("wb") as f:
                f.write(f"{p} {q}".encode())
        return cls(p, q)
