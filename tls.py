import os

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRESHARED_SECRET = bytes([0x50, 0x52, 0x45, 0x53, 0x48, 0x41, 0x52, 0x45, \
                          0x44, 0x5f, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54])

rsa_private_key = rsa.generate_private_key(65537, 2048)
rsa_public_key = rsa_private_key.public_key()
encoded_rsa_public_key = rsa_public_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

h = hmac.HMAC(PRESHARED_SECRET, hashes.SHA256())
h.update(encoded_rsa_public_key)
# mac = h.finalize()

# Python only supports os.getrandom() (which can use /dev/random) on Linux
decoded_rsa_public_key = serialization.load_der_public_key(encoded_rsa_public_key)
assert isinstance(decoded_rsa_public_key, RSAPublicKey)
master_secret = os.urandom(128)
encrypted_ms = decoded_rsa_public_key.encrypt(
    master_secret,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

decrypted_ms = rsa_private_key.decrypt(
    encrypted_ms,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
if master_secret != decrypted_ms:
    raise Exception("Master secrets don't match.")
sha256 = hashes.Hash(hashes.SHA256())
sha256.update(decrypted_ms)
aes_key = sha256.finalize()

plaintext = "Hello world!"
aad = b"authenticated but unencrypted data"
iv = os.urandom(12)
cipher = AESGCM(aes_key)
ciphertext = cipher.encrypt(iv, plaintext.encode(), aad)

decrypted = cipher.decrypt(iv, ciphertext, aad)
recovered = decrypted.decode()
if plaintext != recovered:
    raise Exception("Plaintexts don't match.")
