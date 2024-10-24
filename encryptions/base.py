import abc
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from utils.models import User


PRIVATE_KEY = TypeVar("PRIVATE_KEY")
PUBLIC_KEY = TypeVar("PUBLIC_KEY")


class BaseEncryption(abc.ABC, Generic[PRIVATE_KEY, PUBLIC_KEY]):
    @abc.abstractmethod
    def encrypt(self, data: bytes) -> bytes | tuple[bytes, bytes]:
        pass

    @abc.abstractmethod
    def decrypt(self, data: bytes | tuple[bytes, bytes]) -> bytes:
        pass

    @classmethod
    @abc.abstractmethod
    def from_user(cls, user: "User") -> "BaseEncryption":
        pass

    @property
    def public_key(self) -> PUBLIC_KEY:
        raise NotImplementedError

    @property
    def private_key(self) -> PRIVATE_KEY:
        raise NotImplementedError
