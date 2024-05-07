#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

static const unsigned char PRESHARED_SECRET[] = {0x50, 0x52, 0x45, 0x53, 0x48,
    0x41, 0x52, 0x45, 0x44, 0x5f, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54};

int main(void)
{
    EVP_PKEY_CTX *rsa_context, *rsa_encrypt_context, *rsa_decrypt_context;
    EVP_PKEY *rsa_key_pair = NULL, *hmac_key, *decoded_rsa_public_key = NULL;
    unsigned char *encoded_rsa_public_key, *ptr, *mac, *master_secret, *encrypted_ms,
        *decrypted_ms, *aes_key, iv[12], *ciphertext, tag[16], *decrypted;
    const unsigned char *const_ptr;
    int encoded_rsa_public_key_len, len, ciphertext_len, decrypted_len;
    EVP_MD_CTX *hmac_context, *sha256_context;
    size_t mac_len, encrypted_ms_len, decrypted_ms_len, i;
    unsigned int aes_key_len;
    const char *plaintext = "Hello world!", *aad = "authenticated but unencrypted data";
    EVP_CIPHER_CTX *aes_gcm_encrypt_context, *aes_gcm_decrypt_context;

    rsa_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(rsa_context);
    EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_context, 2048);
    EVP_PKEY_keygen(rsa_context, &rsa_key_pair);
    encoded_rsa_public_key_len = i2d_PUBKEY(rsa_key_pair, NULL);
    encoded_rsa_public_key = malloc(encoded_rsa_public_key_len);
    ptr = encoded_rsa_public_key;
    i2d_PUBKEY(rsa_key_pair, &ptr);

    hmac_context = EVP_MD_CTX_new();
    hmac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, PRESHARED_SECRET, sizeof(PRESHARED_SECRET));
    EVP_DigestSignInit(hmac_context, NULL, EVP_sha256(), NULL, hmac_key);
    EVP_DigestSignUpdate(hmac_context, encoded_rsa_public_key, encoded_rsa_public_key_len);
    EVP_DigestSignFinal(hmac_context, NULL, &mac_len);
    mac = malloc(mac_len);
    EVP_DigestSignFinal(hmac_context, mac, &mac_len);

    const_ptr = encoded_rsa_public_key;
    d2i_PUBKEY(&decoded_rsa_public_key, &const_ptr, encoded_rsa_public_key_len);
    master_secret = malloc(128);
    RAND_priv_bytes(master_secret, 128);
    rsa_encrypt_context = EVP_PKEY_CTX_new(decoded_rsa_public_key, NULL);
    EVP_PKEY_encrypt_init(rsa_encrypt_context);
    EVP_PKEY_CTX_set_rsa_padding(rsa_encrypt_context, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_encrypt_context, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_oaep_md(rsa_encrypt_context, EVP_sha256());
    EVP_PKEY_encrypt(rsa_encrypt_context, NULL, &encrypted_ms_len, master_secret, 128);
    encrypted_ms = malloc(encrypted_ms_len);
    EVP_PKEY_encrypt(rsa_encrypt_context, encrypted_ms, &encrypted_ms_len, master_secret, 128);

    rsa_decrypt_context = EVP_PKEY_CTX_new(rsa_key_pair, NULL);
    EVP_PKEY_decrypt_init(rsa_decrypt_context);
    EVP_PKEY_CTX_set_rsa_padding(rsa_decrypt_context, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_decrypt_context, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_oaep_md(rsa_decrypt_context, EVP_sha256());
    EVP_PKEY_decrypt(rsa_decrypt_context, NULL, &decrypted_ms_len, encrypted_ms, encrypted_ms_len);
    decrypted_ms = malloc(decrypted_ms_len);
    EVP_PKEY_decrypt(rsa_decrypt_context, decrypted_ms, &decrypted_ms_len, encrypted_ms, encrypted_ms_len);
    if (128 == decrypted_ms_len) {
        for (i = 0; i < 128; i++) {
            if (master_secret[i] != decrypted_ms[i]) {
                printf("Master secrets don't match.\n");
                exit(1);
            }
        }
    } else {
        printf("Master secrets don't match.\n");
        exit(1);
    }
    sha256_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256_context, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256_context, decrypted_ms, decrypted_ms_len);
    aes_key_len = EVP_MD_size(EVP_sha256());
    aes_key = malloc(aes_key_len);
    EVP_DigestFinal_ex(sha256_context, aes_key, &aes_key_len);

    RAND_bytes(iv, 12);
    aes_gcm_encrypt_context = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(aes_gcm_encrypt_context, EVP_aes_256_gcm(), NULL, aes_key, iv);
    EVP_EncryptUpdate(aes_gcm_encrypt_context, NULL, &len, (const unsigned char *) aad, strlen(aad));
    ciphertext = malloc(64);
    EVP_EncryptUpdate(aes_gcm_encrypt_context, ciphertext, &len,
        (const unsigned char *) plaintext, strlen(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(aes_gcm_encrypt_context, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(aes_gcm_encrypt_context, EVP_CTRL_GCM_GET_TAG, 16, tag);

    aes_gcm_decrypt_context = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(aes_gcm_decrypt_context, EVP_aes_256_gcm(), NULL, aes_key, iv);
    EVP_DecryptUpdate(aes_gcm_decrypt_context, NULL, &len, (const unsigned char *) aad, strlen(aad));
    decrypted = malloc(64);
    EVP_DecryptUpdate(aes_gcm_decrypt_context, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;
    EVP_CIPHER_CTX_ctrl(aes_gcm_decrypt_context, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal_ex(aes_gcm_decrypt_context, decrypted + len, &len);
    decrypted_len += len;
    decrypted[decrypted_len] = '\0';
    if (strncmp(plaintext, (const char *) decrypted, decrypted_len + 1)) {
        printf("Plaintexts don't match.\n");
        exit(1);
    }

    free(decrypted);
    EVP_CIPHER_CTX_free(aes_gcm_decrypt_context);
    free(ciphertext);
    EVP_CIPHER_CTX_free(aes_gcm_encrypt_context);
    free(aes_key);
    EVP_MD_CTX_free(sha256_context);
    free(decrypted_ms);
    EVP_PKEY_CTX_free(rsa_decrypt_context);
    free(encrypted_ms);
    EVP_PKEY_CTX_free(rsa_encrypt_context);
    free(master_secret);
    EVP_PKEY_free(decoded_rsa_public_key);
    free(mac);
    free(encoded_rsa_public_key);
    EVP_PKEY_free(hmac_key);
    EVP_MD_CTX_free(hmac_context);
    EVP_PKEY_free(rsa_key_pair);
    EVP_PKEY_CTX_free(rsa_context);
}
