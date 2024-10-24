from utils.models import User

print("=== User ===")
user = User(username="Alice")
print(user)

print()

# Encryptions

print("=== Encryptions ===")
print()

# AES

print("=== AES ===")

from encryptions.aes import AESEncryption

aes_encryption = AESEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = aes_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = aes_encryption.decrypt(encrypted_data)
print(decrypted_data)

# DES

print("=== DES ===")

from encryptions.des import DESEncryption, TripleDESEncryption

des_encryption = DESEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = des_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = des_encryption.decrypt(encrypted_data)
print(decrypted_data)

print("=== Triple DES ===")

triple_des_encryption = TripleDESEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = triple_des_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = triple_des_encryption.decrypt(encrypted_data)
print(decrypted_data)

# RSA

print("=== RSA ===")

from Crypto.Util.number import bytes_to_long, long_to_bytes

from encryptions.rsa import HomomorphicRSAEncryption, RSAEncryption

rsa_encryption = RSAEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = rsa_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = rsa_encryption.decrypt(encrypted_data)
print(decrypted_data)

print("=== Homomorphic RSA ===")

homomorphic_rsa_encryption = HomomorphicRSAEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = homomorphic_rsa_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = homomorphic_rsa_encryption.decrypt(encrypted_data)
print(decrypted_data)

# Proving correctness of homomorphic RSA
m1 = b"1"
m2 = b"2"
c1 = homomorphic_rsa_encryption.encrypt(m1)
c2 = homomorphic_rsa_encryption.encrypt(m2)
c3 = (bytes_to_long(c1) * bytes_to_long(c2)) % homomorphic_rsa_encryption.public_key.n
m3 = homomorphic_rsa_encryption.decrypt(long_to_bytes(c3))
assert bytes_to_long(m3) == bytes_to_long(m1) * bytes_to_long(m2), "Not Homomorphic"
print(
    f"{bytes_to_long(m3)=} == {bytes_to_long(m1)=} * {bytes_to_long(m2)=}",
    bytes_to_long(m3) == bytes_to_long(m1) * bytes_to_long(m2),
)

# Elgamal

print("=== Elgamal ===")

from encryptions.elgamal import ElGamalEncryption

elgamal_encryption = ElGamalEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = elgamal_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = elgamal_encryption.decrypt(encrypted_data)
print(decrypted_data)

# ECC

print("=== ECC ===")

from encryptions.ecc import ECCEncryption

ecc_encryption = ECCEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = ecc_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = ecc_encryption.decrypt(encrypted_data)
print(decrypted_data)

# Rabin

print("=== Rabin ===")

from encryptions.rabin import RabinEncryption

rabin_encryption = RabinEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = rabin_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = rabin_encryption.decrypt(encrypted_data)
print(decrypted_data)

# Paillier

print("=== Paillier ===")

from Crypto.Util.number import bytes_to_long, long_to_bytes

from encryptions.paillier import PaillierEncryption

paillier_encryption = PaillierEncryption.from_user(user)
data = b"Hello, World!"
encrypted_data = paillier_encryption.encrypt(data)
print(encrypted_data)
decrypted_data = paillier_encryption.decrypt(encrypted_data)
print(decrypted_data)

# Proving correctness of homomorphic Paillier
m1 = b"1"
m2 = b"2"
c1 = paillier_encryption.encrypt(m1)
c2 = paillier_encryption.encrypt(m2)
c3 = (bytes_to_long(c1) * bytes_to_long(c2)) % (paillier_encryption.public_key[0] ** 2)
m3 = paillier_encryption.decrypt(long_to_bytes(c3))
assert bytes_to_long(m3) == bytes_to_long(m1) + bytes_to_long(m2), "Not Homomorphic"
print(
    f"{bytes_to_long(m3)=} == {bytes_to_long(m1)=} + {bytes_to_long(m2)=}",
    bytes_to_long(m3) == bytes_to_long(m1) + bytes_to_long(m2),
)

# Signatures

print()
print("=== Signatures ===")
print()

print("=== RSA Signature ===")

from signatures.rsa import RSASignature

m = b"Hello, World!"
rsa_signature = RSASignature.from_user(user)
signature = rsa_signature.sign(m)
print(signature)
verified = rsa_signature.verify(m, signature)
assert verified, "Not Verified"
print(f"Verified: {verified}")

# Elgamal

print("=== Elgamal Signature ===")

from signatures.elgamal import ElGamalSignature

m = b"Hello, World!"
elgamal_signature = ElGamalSignature.from_user(user)
signature = elgamal_signature.sign(m)
print(signature)
verified = elgamal_signature.verify(m, signature)
assert verified, "Not Verified"
print(f"Verified: {verified}")

# Schnorr

print("=== Schnorr Signature ===")

from signatures.schnorr import SchnorrSignature

m = b"Hello, World!"
schnorr_signature = SchnorrSignature.from_user(user)
signature = schnorr_signature.sign(m)
print(signature)
verified = schnorr_signature.verify(m, signature)
assert verified, "Not Verified"
print(f"Verified: {verified}")

# ECDSA

print("=== ECDSA Signature ===")

from signatures.ecdsa import ECDSASignature

m = b"Hello, World!"
ecdsa_signature = ECDSASignature.from_user(user)
signature = ecdsa_signature.sign(m)
print(signature)
verified = ecdsa_signature.verify(m, signature)
assert verified, "Not Verified"
print(f"Verified: {verified}")

from utils.manager import get_encryption_algorithm
from utils.models import User

m = "Hmm"
user = User(username="Alice")
encryption = get_encryption_algorithm(user)
encrypted_data = encryption.encrypt(m.encode())
print(encrypted_data)
decrypted_data = get_encryption_algorithm(user).decrypt(encrypted_data)
print(decrypted_data)
