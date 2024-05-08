import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

encoded_rsa_public_key = open("public_key.der", "rb").read()
encoded_rsa_private_key = open("private_key.der", "rb").read()
rsa_private_key = serialization.load_der_private_key(encoded_rsa_private_key, password=None)
assert isinstance(rsa_private_key, RSAPrivateKey)  # For typing purposes

server_ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
encoded_server_ecdh_public_key = server_ecdh_private_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

sha256 = hashes.Hash(hashes.SHA256())
sha256.update(encoded_server_ecdh_public_key)
key_hash = sha256.finalize()
signature = rsa_private_key.sign(
    key_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(hashes.SHA256())
)

decoded_rsa_public_key = serialization.load_der_public_key(encoded_rsa_public_key)
assert isinstance(decoded_rsa_public_key, RSAPublicKey)  # For typing purposes
try:
    decoded_rsa_public_key.verify(
        signature,
        key_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
except InvalidSignature:
    raise Exception("RSA signature wasn't verified.")

# client should import "from cryptography.hazmat.primitives import constant_time"
# and use constant_time.bytes_eq() to compare server's hash with its own hash of
# the server's encoded ECDH public key to avoid timing attacks
decoded_server_ecdh_public_key = serialization.load_der_public_key(encoded_server_ecdh_public_key)
assert isinstance(decoded_server_ecdh_public_key, EllipticCurvePublicKey)  # For typing purposes
client_ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
encoded_client_ecdh_public_key = client_ecdh_private_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
client_master_secret = client_ecdh_private_key.exchange(ec.ECDH(), decoded_server_ecdh_public_key)
sha256 = hashes.Hash(hashes.SHA256())
sha256.update(client_master_secret)
aes_key = sha256.finalize()

decoded_client_ecdh_public_key = serialization.load_der_public_key(encoded_client_ecdh_public_key)
assert isinstance(decoded_client_ecdh_public_key, EllipticCurvePublicKey)  # For typing purposes
server_master_secret = server_ecdh_private_key.exchange(ec.ECDH(), decoded_client_ecdh_public_key)
if client_master_secret != server_master_secret:
    raise Exception("Master secrets don't match.")

plaintext = "Hello world!"
aad = b"authenticated but unencrypted data"
iv = os.urandom(12)
cipher = AESGCM(aes_key)
ciphertext = cipher.encrypt(iv, plaintext.encode(), aad)

decrypted = cipher.decrypt(iv, ciphertext, aad)
recovered = decrypted.decode()
if plaintext != recovered:
    raise Exception("Plaintexts don't match.")
