import pathlib
from typing import TYPE_CHECKING

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from utils.hash import get_hash

from .base import BaseSignature

if TYPE_CHECKING:
    from utils.models import User


class ECDSASignature(BaseSignature):
    def __init__(self, private_key: ECC.EccKey, public_key: ECC.EccKey) -> None:
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data: bytes) -> bytes:
        h = get_hash(data)
        signer = DSS.new(self.private_key, "fips-186-3")
        return signer.sign(h)

    def verify(self, data: bytes, signature: bytes) -> bool:
        h = get_hash(data)
        verifier = DSS.new(self.public_key, "fips-186-3")
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    @classmethod
    def from_user(cls, user: "User") -> "BaseSignature":
        key_path = pathlib.Path(f"keys/ecdsa/{user.id}.key")
        if key_path.exists():
            with key_path.open("rb") as f:
                private_key = ECC.import_key(f.read())
                public_key = private_key.public_key()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            private_key = ECC.generate(curve="P-384")
            public_key = private_key.public_key()
            with key_path.open("wb") as f:
                f.write(private_key.export_key(format="PEM").encode())
        return cls(private_key, public_key)
