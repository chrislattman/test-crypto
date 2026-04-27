import argparse
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey, RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tpm2_pytss import (ESAPI, TPM2_ALG, TPM2B_DIGEST, TPM2B_PUBLIC, TPM2_RH, TPM2B_SENSITIVE_CREATE,
                        TPM2_ST, TPMA_OBJECT, TPMS_SCHEME_HASH, TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK, TPMU_SIG_SCHEME)

parser = argparse.ArgumentParser()
parser.add_argument("--tpm", action="store_true", help="Use TPM to sign server's ECDH public key")
parser.add_argument("-c", "--config", default=None, help="config file")
args = parser.parse_args()

if args.config is not None:
    print(f"Config file = {args.config}")

server_ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
encoded_server_ecdh_public_key = server_ecdh_private_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

if args.tpm:
    with ESAPI() as ectx:
        # Reconstruct the root key
        root_key_handle, _, _, _, _ = ectx.create_primary(
            TPM2B_SENSITIVE_CREATE()
        )

        # Only RSA-2048 (not RSA-4096) is mandated by the TPM 2.0 specification
        rsa_private_key, rsa_public_key, _, _, _ = ectx.create(
            root_key_handle,
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa2048:rsapss-sha256:null",
                objectAttributes=(
                    TPMA_OBJECT.SIGN_ENCRYPT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                    | TPMA_OBJECT.USERWITHAUTH
                )
            )
        )
        signing_handle = ectx.load(root_key_handle, rsa_private_key, rsa_public_key)

        # # To persist the key beyond a reboot:
        # from tpm2_pytss import ESYS_TR, TPM2_HANDLE
        # ectx.evict_control(ESYS_TR.RH_OWNER, signing_handle, 0x81000001)
        # # To reload the key:
        # handle = ectx.tr_from_tpmpublic(TPM2_HANDLE(0x81000001))
        # pub_key, _, _ = ectx.read_public(handle)
        # # To delete the key from storage, call evict_control with same args again

        # Only SHA-256 (not SHA-384) is mandated by the TPM 2.0 specification
        digest = hashlib.sha256(encoded_server_ecdh_public_key).digest()
        digest_obj = TPM2B_DIGEST(buffer=digest)
        signature_obj = ectx.sign(
            signing_handle,
            digest_obj, 
            TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSAPSS, details=TPMU_SIG_SCHEME(rsapss=TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA256))),
            TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.NULL)
        )

        hashing_algorithm = hashes.SHA256()
        rsa_padding = padding.PSS(
            mgf=padding.MGF1(hashing_algorithm),
            salt_length=hashing_algorithm.digest_size
        )
        signature = bytes(signature_obj.signature.rsapss.sig.buffer)

        n = int.from_bytes(bytes(rsa_public_key.publicArea.unique.rsa.buffer), byteorder="big")
        e = rsa_public_key.publicArea.parameters.rsaDetail.exponent
        if e == 0:
            e = 65537
        decoded_rsa_public_key = RSAPublicNumbers(e, n).public_key()
else:
    encoded_rsa_public_key = open("public_key.der", "rb").read()
    encoded_rsa_private_key = open("private_key.der", "rb").read()
    rsa_private_key = serialization.load_der_private_key(encoded_rsa_private_key, password=None)
    assert isinstance(rsa_private_key, RSAPrivateKey)  # For typing purposes

    hashing_algorithm = hashes.SHA384()
    rsa_padding = padding.PSS(
        mgf=padding.MGF1(hashing_algorithm),
        salt_length=padding.PSS.MAX_LENGTH
    )
    signature = rsa_private_key.sign(
        encoded_server_ecdh_public_key,
        rsa_padding,
        hashing_algorithm
    )

    decoded_rsa_public_key = serialization.load_der_public_key(encoded_rsa_public_key)
    assert isinstance(decoded_rsa_public_key, RSAPublicKey)  # For typing purposes

try:
    decoded_rsa_public_key.verify(
        signature,
        encoded_server_ecdh_public_key,
        rsa_padding,
        hashing_algorithm
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
# To get 12 truly random (TRNG) bytes:
# iv = bytes(ectx.get_random(12).buffer)
cipher = AESGCM(aes_key)
ciphertext = cipher.encrypt(iv, plaintext.encode(), aad)

decrypted = cipher.decrypt(iv, ciphertext, aad)
recovered = decrypted.decode()
if plaintext != recovered:
    raise Exception("Plaintexts don't match.")

# EllipticCurvePrivateKey has no manual destructor and Python bytes objects are immutable
