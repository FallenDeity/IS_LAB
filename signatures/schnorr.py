# Schnorr Signature
import pathlib
from typing import TYPE_CHECKING

from ecdsa import NIST256p, SigningKey, VerifyingKey

from utils.hash import get_hash

from .base import BaseSignature

if TYPE_CHECKING:
    from utils.models import User


class SchnorrSignature(BaseSignature):
    def __init__(self, private_key: SigningKey, public_key: VerifyingKey) -> None:
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data: bytes) -> bytes:
        h = get_hash(data)
        return self.private_key.sign(h.digest())

    def verify(self, data: bytes, signature: bytes) -> bool:
        h = get_hash(data)
        return self.public_key.verify(signature, h.digest())

    @classmethod
    def from_user(cls, user: "User") -> "BaseSignature":
        key_path = pathlib.Path(f"keys/schnorr/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                private_key = SigningKey.from_pem(f.read())
                public_key = private_key.get_verifying_key()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            private_key = SigningKey.generate(curve=NIST256p)
            public_key = private_key.get_verifying_key()
            with key_path.open("wb") as f:
                f.write(private_key.to_pem())
        return cls(private_key, public_key)
