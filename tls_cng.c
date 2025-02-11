#include <Windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main(void) {
    // HANDLE hFile;
    // ULONG encodedRsaPrivateKeyLen;
    ULONG encodedRsaPublicKeyLen, bytesRead, rsaPublicKeyBlobLen,
        serverEcdhPublicKeyBlobLen, encodedServerEcdhPublicKeyLen, hashObjLen,
        keyHashLen, signatureLen, clientEcdhPublicKeyBlobLen,
        encodedClientEcdhPublicKeyLen, clientMasterSecretLen, serverMasterSecretLen,
        ciphertextLen, decryptedLen;
    // PUCHAR encodedRsaPrivateKey;
    PUCHAR encodedRsaPublicKey, rsaPublicKeyBlob, serverEcdhPublicKeyBlob,
        encodedServerEcdhPublicKey, hashObj, keyHash, signature,
        clientEcdhPublicKeyBlob, encodedClientEcdhPublicKey, clientMasterSecret,
        aesKeyBytes, serverMasterSecret, ciphertext, decrypted;
    BCRYPT_ALG_HANDLE rsa, ecdh, sha256, aes, rng;
    BCRYPT_KEY_HANDLE rsaPrivateKey, serverEcdhKeyPair, rsaPublicKey,
        decodedServerEcdhPublicKey, clientEcdhKeyPair, aesKey, decodedClientEcdhPublicKey;
    BCRYPT_HASH_HANDLE hSha256;
    BCRYPT_PSS_PADDING_INFO paddingInfo = {
        .pszAlgId = BCRYPT_SHA256_ALGORITHM,
        .cbSalt = (2048 / 8) - (256 / 8) - 2 // 222 bytes, max salt length
    };
    NTSTATUS status;
    BCRYPT_SECRET_HANDLE clientSecret, serverSecret;
    const char *plaintext = "Hello world!", *aad = "authenticated but unencrypted data";
    UCHAR iv[12], tag[16];
    // UCHAR ivCopy[12];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    // hFile = CreateFileA("public_key.der", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // encodedRsaPublicKeyLen = GetFileSize(hFile, NULL);
    // encodedRsaPublicKey = HeapAlloc(GetProcessHeap(), 0, encodedRsaPublicKeyLen);
    // ReadFile(hFile, encodedRsaPublicKey, encodedRsaPublicKeyLen, &bytesRead, NULL);
    // CloseHandle(hFile);
    // hFile = CreateFileA("private_key.der", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // encodedRsaPrivateKeyLen = GetFileSize(hFile, NULL);
    // encodedRsaPrivateKey = HeapAlloc(GetProcessHeap(), 0, encodedRsaPrivateKeyLen);
    // ReadFile(hFile, encodedRsaPrivateKey, encodedRsaPrivateKeyLen, &bytesRead, NULL);
    // CloseHandle(hFile);

    // Generating our own RSA public/private key pair for now
    BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(rsa, &rsaPrivateKey, 2048, 0);
    BCryptFinalizeKeyPair(rsaPrivateKey, 0);
    BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &rsaPublicKeyBlobLen, 0);
    rsaPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, rsaPublicKeyBlobLen);
    BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, rsaPublicKeyBlob,
        rsaPublicKeyBlobLen, &rsaPublicKeyBlobLen, 0);
    // TODO: export rsaPublicKeyBlob in SPKI DER format (maybe 294 bytes?)
    encodedRsaPublicKey = rsaPublicKeyBlob;
    encodedRsaPublicKeyLen = rsaPublicKeyBlobLen; // currently 283

    BCryptOpenAlgorithmProvider(&ecdh, BCRYPT_ECDH_P384_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(ecdh, &serverEcdhKeyPair, 384, 0);
    BCryptFinalizeKeyPair(serverEcdhKeyPair, 0);
    BCryptExportKey(serverEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &serverEcdhPublicKeyBlobLen, 0);
    serverEcdhPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, serverEcdhPublicKeyBlobLen);
    BCryptExportKey(serverEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, serverEcdhPublicKeyBlob,
        serverEcdhPublicKeyBlobLen, &serverEcdhPublicKeyBlobLen, 0);
    // TODO: export serverEcdhPublicKeyBlob in SPKI DER format (should be 120 bytes)
    encodedServerEcdhPublicKey = serverEcdhPublicKeyBlob;
    encodedServerEcdhPublicKeyLen = serverEcdhPublicKeyBlobLen; // currently 104

    BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG);
    BCryptGetProperty(sha256, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjLen, sizeof(ULONG), &bytesRead, 0);
    hashObj = HeapAlloc(GetProcessHeap(), 0, hashObjLen);
    // BCryptHash(sha256, NULL, 0, encodedServerEcdhPublicKey,
    //     encodedServerEcdhPublicKeyLen, keyHash, 256);
    BCryptCreateHash(sha256, &hSha256, hashObj, hashObjLen, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
    BCryptHashData(hSha256, encodedServerEcdhPublicKey, encodedServerEcdhPublicKeyLen, 0);
    BCryptGetProperty(sha256, BCRYPT_HASH_LENGTH, (PUCHAR)&keyHashLen, sizeof(ULONG), &bytesRead, 0);
    keyHash = HeapAlloc(GetProcessHeap(), 0, keyHashLen);
    BCryptFinishHash(hSha256, keyHash, keyHashLen, 0);
    BCryptSignHash(rsaPrivateKey, &paddingInfo, keyHash, keyHashLen, NULL, 0, &signatureLen, BCRYPT_PAD_PSS);
    signature = HeapAlloc(GetProcessHeap(), 0, signatureLen);
    BCryptSignHash(rsaPrivateKey, &paddingInfo, keyHash, keyHashLen, signature,
        signatureLen, &signatureLen, BCRYPT_PAD_PSS);

    // TODO: will need to import RSA public key from SPKI DER into BLOB format
    BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &rsaPublicKey,
        encodedRsaPublicKey, encodedRsaPublicKeyLen, 0);
    status = BCryptVerifySignature(rsaPublicKey, &paddingInfo, keyHash, keyHashLen,
        signature, signatureLen, BCRYPT_PAD_PSS);
    if (!NT_SUCCESS(status)) {
        puts("RSA signature wasn't verified.");
        exit(1);
    }

    // No built-in constant-time buffer comparison algorithms
    // TODO: will need to import server ECDH public key from SPKI DER into BLOB format
    BCryptImportKeyPair(ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &decodedServerEcdhPublicKey,
        encodedServerEcdhPublicKey, encodedServerEcdhPublicKeyLen, 0);
    BCryptGenerateKeyPair(ecdh, &clientEcdhKeyPair, 384, 0);
    BCryptFinalizeKeyPair(clientEcdhKeyPair, 0);
    BCryptExportKey(clientEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &clientEcdhPublicKeyBlobLen, 0);
    clientEcdhPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, clientEcdhPublicKeyBlobLen);
    BCryptExportKey(clientEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, clientEcdhPublicKeyBlob,
        clientEcdhPublicKeyBlobLen, &clientEcdhPublicKeyBlobLen, 0);
    // TODO: export clientEcdhPublicKeyBlob in SPKI DER format (should be 120 bytes)
    encodedClientEcdhPublicKey = clientEcdhPublicKeyBlob;
    encodedClientEcdhPublicKeyLen = clientEcdhPublicKeyBlobLen;
    BCryptSecretAgreement(clientEcdhKeyPair, decodedServerEcdhPublicKey, &clientSecret, 0);
    BCryptDeriveKey(clientSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &clientMasterSecretLen, 0);
    clientMasterSecret = HeapAlloc(GetProcessHeap(), 0, clientMasterSecretLen);
    BCryptDeriveKey(clientSecret, BCRYPT_KDF_RAW_SECRET, NULL, clientMasterSecret,
        clientMasterSecretLen, &clientMasterSecretLen, 0);
    BCryptHashData(hSha256, clientMasterSecret, clientMasterSecretLen, 0);
    aesKeyBytes = HeapAlloc(GetProcessHeap(), 0, keyHashLen);
    BCryptFinishHash(hSha256, aesKeyBytes, keyHashLen, 0);
    BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(aes, &aesKey, NULL, 0, aesKeyBytes, keyHashLen, 0);

    // TODO: will need to import client ECDH public key from SPKI DER into BLOB format
    BCryptImportKeyPair(ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &decodedClientEcdhPublicKey,
        encodedClientEcdhPublicKey, encodedClientEcdhPublicKeyLen, 0);
    BCryptSecretAgreement(serverEcdhKeyPair, decodedClientEcdhPublicKey, &serverSecret, 0);
    BCryptDeriveKey(serverSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &serverMasterSecretLen, 0);
    serverMasterSecret = HeapAlloc(GetProcessHeap(), 0, serverMasterSecretLen);
    BCryptDeriveKey(serverSecret, BCRYPT_KDF_RAW_SECRET, NULL, serverMasterSecret,
        serverMasterSecretLen, &serverMasterSecretLen, 0);
    if (clientMasterSecretLen != serverMasterSecretLen ||
            memcmp(clientMasterSecret, serverMasterSecret, clientMasterSecretLen) != 0) {
        puts("Master secrets don't match.");
        exit(1);
    }

    BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    BCryptGenRandom(rng, iv, sizeof(iv), 0);
    // memcpy(ivCopy, iv, sizeof(iv));
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = sizeof(iv);
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = strlen(aad);
    authInfo.pbTag = tag;
    authInfo.cbTag = sizeof(tag);
    ciphertextLen = strlen(plaintext);
    ciphertext = HeapAlloc(GetProcessHeap(), 0, ciphertextLen);
    BCryptEncrypt(aesKey, (PUCHAR)plaintext, strlen(plaintext), &authInfo, iv, sizeof(iv),
        ciphertext, ciphertextLen, &ciphertextLen, 0);

    // memcpy(iv, ivCopy, sizeof(iv));
    // authInfo.pbNonce = iv;
    // authInfo.cbNonce = sizeof(iv);
    decryptedLen = ciphertextLen;
    decrypted = HeapAlloc(GetProcessHeap(), 0, decryptedLen + 1);
    BCryptDecrypt(aesKey, ciphertext, ciphertextLen, &authInfo, iv, sizeof(iv),
        decrypted, decryptedLen, &decryptedLen, 0);
    decrypted[decryptedLen] = '\0';
    if (strcmp(plaintext, (const char *)decrypted) != 0) {
        puts("Plaintexts don't match.");
        exit(1);
    }

    BCryptCloseAlgorithmProvider(rsa, 0);
    BCryptCloseAlgorithmProvider(ecdh, 0);
    BCryptCloseAlgorithmProvider(sha256, 0);
    BCryptCloseAlgorithmProvider(aes, 0);
    BCryptCloseAlgorithmProvider(rng, 0);
    BCryptDestroyKey(rsaPrivateKey);
    BCryptDestroyKey(serverEcdhKeyPair);
    BCryptDestroyKey(rsaPublicKey);
    BCryptDestroyKey(decodedServerEcdhPublicKey);
    BCryptDestroyKey(clientEcdhKeyPair);
    BCryptDestroyKey(aesKey);
    BCryptDestroyKey(decodedClientEcdhPublicKey);
    BCryptDestroyHash(hSha256);
    BCryptDestroySecret(clientSecret);
    BCryptDestroySecret(serverSecret);
    // HeapFree(GetProcessHeap(), 0, encodedRsaPublicKey);
    // HeapFree(GetProcessHeap(), 0, encodedRsaPrivateKey);
    HeapFree(GetProcessHeap(), 0, rsaPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, serverEcdhPublicKeyBlob);
    // HeapFree(GetProcessHeap(), 0, encodedServerEcdhPublicKey);
    HeapFree(GetProcessHeap(), 0, hashObj);
    HeapFree(GetProcessHeap(), 0, keyHash);
    HeapFree(GetProcessHeap(), 0, signature);
    HeapFree(GetProcessHeap(), 0, clientEcdhPublicKeyBlob);
    // HeapFree(GetProcessHeap(), 0, encodedClientEcdhPublicKey);
    HeapFree(GetProcessHeap(), 0, clientMasterSecret);
    HeapFree(GetProcessHeap(), 0, aesKeyBytes);
    HeapFree(GetProcessHeap(), 0, serverMasterSecret);
    HeapFree(GetProcessHeap(), 0, ciphertext);
    HeapFree(GetProcessHeap(), 0, decrypted);
    return 0;
}
