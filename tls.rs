use std::fs;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use p384::{PublicKey, ecdh::EphemeralSecret, pkcs8::EncodePublicKey};
use rand::{rngs::OsRng, RngCore};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, spki::SignatureBitStringEncoding},
    pss::{BlindedSigningKey, Signature, VerifyingKey},
    signature::{RandomizedSigner, Verifier},
};
use sha2::{Digest, Sha256, Sha384};

fn main() {
    let encoded_rsa_public_key = fs::read("public_key.der").unwrap();
    let encoded_rsa_private_key = fs::read("private_key.der").unwrap();
    let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&encoded_rsa_private_key).unwrap();

    let server_ecdh_private_key = EphemeralSecret::random(&mut OsRng);
    let encoded_server_ecdh_public_key = PublicKey::from(&server_ecdh_private_key)
        .to_public_key_der()
        .unwrap()
        .to_vec();

    let rsa_sign = BlindedSigningKey::<Sha384>::new(rsa_private_key);
    let sig = rsa_sign.sign_with_rng(&mut OsRng, &encoded_server_ecdh_public_key);
    let sig_bitstring = sig.to_bitstring().unwrap();
    let sig_bytes = sig_bitstring.raw_bytes();

    let decoded_rsa_public_key =
        RsaPublicKey::from_public_key_der(&encoded_rsa_public_key).unwrap();
    let rsa_verify = VerifyingKey::<Sha384>::new(decoded_rsa_public_key);
    let recovered_sig = Signature::try_from(sig_bytes).unwrap();
    rsa_verify
        .verify(&encoded_server_ecdh_public_key, &recovered_sig)
        .unwrap_or_else(|_| {
            panic!("RSA signature wasn't verified.");
        });

    // client should import "use subtle::ConstantTimeEq;" and use
    // bool::from(hash.ct_eq(&other_hash)) to compare server's hash with its own
    // hash of the server's encoded ECDH public key to avoid timing attacks
    let decoded_server_ecdh_public_key =
        PublicKey::from_public_key_der(&encoded_server_ecdh_public_key).unwrap();
    let client_ecdh_private_key = EphemeralSecret::random(&mut OsRng);
    let encoded_client_ecdh_public_key = PublicKey::from(&client_ecdh_private_key)
        .to_public_key_der()
        .unwrap()
        .to_vec();
    let client_exchange = client_ecdh_private_key.diffie_hellman(&decoded_server_ecdh_public_key);
    let client_master_secret = client_exchange.raw_secret_bytes();
    let hash = Sha256::digest(client_master_secret);
    let aes_key = Key::<Aes256Gcm>::from_slice(&hash);

    let decoded_client_ecdh_public_key =
        PublicKey::from_public_key_der(&encoded_client_ecdh_public_key).unwrap();
    let server_exchange = server_ecdh_private_key.diffie_hellman(&decoded_client_ecdh_public_key);
    let server_master_secret = server_exchange.raw_secret_bytes();
    if client_master_secret != server_master_secret {
        panic!("Master secrets don't match.");
    }

    let plaintext = "Hello world!";
    let aad = b"authenticated but unencrypted data";
    let mut iv = [0u8; 12]; // You will store this
    OsRng.try_fill_bytes(&mut iv).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let cipher = Aes256Gcm::new(aes_key);
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };
    let ciphertext = cipher.encrypt(nonce, payload).unwrap();

    let payload = Payload {
        msg: &ciphertext,
        aad,
    };
    let decrypted = cipher.decrypt(nonce, payload).unwrap();
    let recovered = std::str::from_utf8(&decrypted).unwrap();
    if plaintext != recovered {
        panic!("Plaintexts don't match.");
    }
}
