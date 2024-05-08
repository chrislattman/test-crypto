use std::fs;

use ring::{aead, agreement, digest, rand::{self, SecureRandom}, rsa, signature};

fn main() {
    let encoded_rsa_public_key = fs::read("public_key.der").unwrap();
    let encoded_rsa_private_key = fs::read("private_key.der").unwrap();
    let rsa_private_key = rsa::KeyPair::from_pkcs8(encoded_rsa_private_key.as_slice()).unwrap();

    let rng = rand::SystemRandom::new();
    let server_ecdh_private_key = agreement
        ::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
    let server_ecdh_public_key = server_ecdh_private_key.compute_public_key().unwrap();
    let server_ecdh_public_key_raw = server_ecdh_public_key.as_ref();
    // hack to encode secp384r1 public key in DER SPKI format manually since
    // ring doesn't support it yet :(
    let mut encoded_server_ecdh_public_key = hex::decode(
    "3076301006072a8648ce3d020106052b81040022036200").unwrap();
    encoded_server_ecdh_public_key.extend_from_slice(server_ecdh_public_key_raw);

    // SHA-256 hash of server's ECDH public key is computed by sign()
    let mut signature = vec![0; rsa_private_key.public().modulus_len()];
    rsa_private_key.sign(&signature::RSA_PKCS1_SHA256, &rng,
    encoded_server_ecdh_public_key.as_slice(), &mut signature).unwrap();

    let decoded_rsa_public_key = signature
        ::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,
        &encoded_rsa_public_key.as_slice()[24..]); // removing the encoding manually
    decoded_rsa_public_key.verify(encoded_server_ecdh_public_key.as_slice(),
    signature.as_slice()).unwrap_or_else(|_| {
        panic!("RSA signature wasn't verified.");
    });

    // client should import ring::constant_time and use
    // constant_time::verify_slices_are_equal() to compare server's hash with
    // its own hash of the server's encoded ECDH public key to avoid timing
    // attacks
    let decoded_server_ecdh_public_key = agreement
        ::UnparsedPublicKey::new(&agreement::ECDH_P384,
            &encoded_server_ecdh_public_key.as_slice()[23..]); // removing the encoding manually
    let client_ecdh_private_key = agreement
        ::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng).unwrap();
    let client_ecdh_public_key = client_ecdh_private_key.compute_public_key().unwrap();
    let client_ecdh_public_key_raw = client_ecdh_public_key.as_ref();
    // manual public key encoding again
    let mut encoded_client_ecdh_public_key = hex::decode(
    "3076301006072a8648ce3d020106052b81040022036200").unwrap();
    encoded_client_ecdh_public_key.extend_from_slice(client_ecdh_public_key_raw);
    let aes_key = agreement::agree_ephemeral(
        client_ecdh_private_key, &decoded_server_ecdh_public_key,
        |client_master_secret| {
            // perform SHA-256 hash of the master secret in here
            return digest::digest(&digest::SHA256, client_master_secret).as_ref().to_vec();
        }
    ).unwrap();

    let decoded_client_ecdh_public_key = agreement
        ::UnparsedPublicKey::new(&agreement::ECDH_P384,
            &encoded_client_ecdh_public_key.as_slice()[23..]); // removing the encoding manually
    let server_aes_key = agreement::agree_ephemeral(
        server_ecdh_private_key, &decoded_client_ecdh_public_key,
        |server_master_secret| {
            // perform SHA-256 hash of the master secret in here
            return digest::digest(&digest::SHA256, server_master_secret).as_ref().to_vec();
        }
    ).unwrap();
    if aes_key != server_aes_key {
        panic!("Master secrets don't match.");
    }

    let plaintext = "Hello world!";
    let mut ciphertext = plaintext.as_bytes().to_vec();
    let aad_bytes = b"authenticated but unencrypted data";
    let mut iv_bytes = [08; 12];
    rng.fill(&mut iv_bytes).unwrap();
    let iv = aead::Nonce::assume_unique_for_key(iv_bytes);
    let aad = aead::Aad::from(aad_bytes);
    let unbound_key = aead::UnboundKey::new(
    &aead::AES_256_GCM, aes_key.as_slice()).unwrap();
    let aes = aead::LessSafeKey::new(unbound_key);
    aes.seal_in_place_append_tag(iv, aad, &mut ciphertext).unwrap();

    let iv_copy = aead::Nonce::assume_unique_for_key(iv_bytes);
    let decrypted = aes.open_in_place(iv_copy, aad, &mut ciphertext).unwrap();
    let recovered = std::str::from_utf8(decrypted).unwrap();
    if plaintext != recovered {
        panic!("Plaintexts don't match.");
    }
}
