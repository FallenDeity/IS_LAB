import pathlib
from typing import TYPE_CHECKING, Generic, TypeVar

from ecies import decrypt, encrypt
from ecies.utils import generate_key

from .base import BaseEncryption

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY", bound=bytes)
PUBLIC_KEY = TypeVar("PUBLIC_KEY", bound=bytes)


class ECCEncryption(BaseEncryption, Generic[PRIVATE_KEY, PUBLIC_KEY]):
    def __init__(self, private_key: bytes, public_key: bytes) -> None:
        self._private_key = private_key
        self._public_key = public_key

    def encrypt(self, data: bytes) -> bytes:
        return encrypt(self._public_key, data)

    def decrypt(self, data: bytes) -> bytes:
        return decrypt(self._private_key, data)

    @property
    def public_key(self) -> PUBLIC_KEY:
        return self._public_key

    @property
    def private_key(self) -> PRIVATE_KEY:
        return self._private_key

    @classmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
        key_path = pathlib.Path(f"keys/ecc/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                private_key, public_key = f.read().split(b" ", 1)
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = generate_key()
            private_key = key.secret
            public_key = key.public_key.format(True)
            with key_path.open("wb") as f:
                f.write(b" ".join([private_key, public_key]))
        return cls(private_key, public_key)
