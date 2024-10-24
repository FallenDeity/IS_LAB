import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from utils.models import User


class BaseSignature(abc.ABC):
    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        pass

    @classmethod
    @abc.abstractmethod
    def from_user(cls, user: "User") -> "BaseSignature":
        pass
