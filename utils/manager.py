import enum

from encryptions.aes import AESEncryption
from encryptions.base import BaseEncryption
from encryptions.des import DESEncryption, TripleDESEncryption
from encryptions.ecc import ECCEncryption
from encryptions.elgamal import ElGamalEncryption
from encryptions.paillier import PaillierEncryption
from encryptions.rsa import HomomorphicRSAEncryption, RSAEncryption
from signatures.base import BaseSignature
from signatures.ecdsa import ECDSASignature
from signatures.elgamal import ElGamalSignature
from signatures.rsa import RSASignature
from signatures.schnorr import SchnorrSignature
from utils.models import User


class EncryptionAlgorithm(enum.Enum):
    AES = 1
    DES = 2
    TRIPLE_DES = 3
    ECC = 4
    RSA = 5
    RSA_HOMOMORPHIC = 6
    ELGAMAL = 7
    PAILLIER = 8


ENCRYPTION_ALGORITHM = EncryptionAlgorithm.DES


def get_encryption_algorithm(user: User, algorithm: EncryptionAlgorithm = ENCRYPTION_ALGORITHM) -> BaseEncryption:
    if algorithm == EncryptionAlgorithm.AES:
        return AESEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.DES:
        return DESEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.TRIPLE_DES:
        return TripleDESEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.ECC:
        return ECCEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.RSA:
        return RSAEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.RSA_HOMOMORPHIC:
        return HomomorphicRSAEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.ELGAMAL:
        return ElGamalEncryption.from_user(user)
    elif algorithm == EncryptionAlgorithm.PAILLIER:
        return PaillierEncryption.from_user(user)
    else:
        raise ValueError("Invalid encryption algorithm")


class SignatureAlgorithm(enum.Enum):
    ECDSA = 1
    RSA = 2
    ELGAMAL = 3
    SCHNORR = 4


SIGNATURE_ALGORITHM = SignatureAlgorithm.RSA


def get_signature_algorithm(user: User, algorithm: SignatureAlgorithm = SIGNATURE_ALGORITHM) -> BaseSignature:
    if algorithm == SignatureAlgorithm.ECDSA:
        return ECDSASignature.from_user(user)
    elif algorithm == SignatureAlgorithm.RSA:
        return RSASignature.from_user(user)
    elif algorithm == SignatureAlgorithm.ELGAMAL:
        return ElGamalSignature.from_user(user)
    elif algorithm == SignatureAlgorithm.SCHNORR:
        return SchnorrSignature.from_user(user)
    else:
        raise ValueError("Invalid signature algorithm")
