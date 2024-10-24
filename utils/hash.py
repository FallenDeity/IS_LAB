import enum
import typing

from Crypto.Hash import new

"""
Possible type(s): 
(Literal["1.3.14.3.2.26"]) 
(Literal["SHA1"]) 
(Literal["2.16.840.1.101.3.4.2.4"]) 
(Literal["SHA224"]) 
(Literal["2.16.840.1.101.3.4.2.1"]) 
(Literal["SHA256"]) 
(Literal["2.16.840.1.101.3.4.2.2"]) 
(Literal["SHA384"]) 
(Literal["2.16.840.1.101.3.4.2.3"]) 
(Literal["SHA512"]) 
(Literal["2.16.840.1.101.3.4.2.5"]) 
(Literal["SHA512-224"]) 
(Literal["2.16.840.1.101.3.4.2.6"]) 
(Literal["SHA512-256"]) 
(Literal["2.16.840.1.101.3.4.2.7"]) 
(Literal["SHA3-224"]) 
(Literal["2.16.840.1.101.3.4.2.8"]) 
(Literal["SHA3-256"]) 
(Literal["2.16.840.1.101.3.4.2.9"]) 
(Literal["SHA3-384"]) 
(Literal["2.16.840.1.101.3.4.2.10"]) 
(Literal["SHA3-512"]) 
"""

HASH_TYPE = "SHA256"


def get_hash(data: bytes, hash_type: HASH_TYPE = HASH_TYPE) -> typing.Any:
    h = new(hash_type)
    h.update(data)
    return h
