#include <stdio.h>
#include <Windows.h>

// #pragma comment(lib, "bcrypt.lib")
// #pragma comment(lib, "crypt32.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BOOL ConvertRSABlobToSPKI(PUCHAR rsaPubKeyBlob, PUCHAR *spkiBuf, ULONG *spkiBufLen) {
    BOOL status;
    PUCHAR derBuf = NULL, spkiOutBuf = NULL;
    DWORD derBufLen, spkiOutBufLen;
    CRYPT_ALGORITHM_IDENTIFIER algId = {0};
    CRYPT_BIT_BLOB publicKey = {0};
    CERT_PUBLIC_KEY_INFO pubKeyInfo = {0};

    // TODO: could be doing more specific error checking with the magic bits of rsaPubKeyBlob
    if (!rsaPubKeyBlob || !spkiBuf || !spkiBufLen) {
        return FALSE;
    }
    status = CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
        rsaPubKeyBlob, CRYPT_ENCODE_ALLOC_FLAG, NULL, &derBuf, &derBufLen);
    if (!status) {
        return FALSE;
    }
    algId.pszObjId = szOID_RSA_RSA;
    publicKey.pbData = derBuf;
    publicKey.cbData = derBufLen;
    pubKeyInfo.Algorithm = algId;
    pubKeyInfo.PublicKey = publicKey;
    status = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        &pubKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &spkiOutBuf, &spkiOutBufLen);
    if (!status) {
        LocalFree(derBuf);
        return FALSE;
    }
    *spkiBuf = HeapAlloc(GetProcessHeap(), 0, spkiOutBufLen);
    if (!*spkiBuf) {
        LocalFree(derBuf);
        LocalFree(spkiOutBuf);
        return FALSE;
    }
    memcpy(*spkiBuf, spkiOutBuf, spkiOutBufLen);
    *spkiBufLen = spkiOutBufLen;

    LocalFree(derBuf);
    LocalFree(spkiOutBuf);
    return TRUE;
}

BOOL ConvertRSASPKIToBlob(PUCHAR spkiBuf, ULONG spkiBufLen, PUCHAR *rsaPubKeyBlob,
        ULONG *rsaPubKeyBlobLen) {
    BOOL status;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD pPubKeyInfoLen, derBufLen;
    PUCHAR derBuf = NULL;

    if (!spkiBuf || spkiBufLen <= 0 || !rsaPubKeyBlob || !rsaPubKeyBlobLen) {
        return FALSE;
    }
    status = CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        spkiBuf, spkiBufLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &pPubKeyInfoLen);
    if (!status) {
        return FALSE;
    }
    status = CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
        pPubKeyInfo->PublicKey.pbData, pPubKeyInfo->PublicKey.cbData,
        CRYPT_DECODE_ALLOC_FLAG, NULL, &derBuf, &derBufLen);
    if (!status) {
        LocalFree(pPubKeyInfo);
        return FALSE;
    }
    *rsaPubKeyBlob = HeapAlloc(GetProcessHeap(), 0, derBufLen);
    if (!*rsaPubKeyBlob) {
        LocalFree(pPubKeyInfo);
        LocalFree(derBuf);
        return FALSE;
    }
    memcpy(*rsaPubKeyBlob, derBuf, derBufLen);
    *rsaPubKeyBlobLen = derBufLen;

    LocalFree(pPubKeyInfo);
    LocalFree(derBuf);
    return TRUE;
}

BOOL ConvertECCBlobToSPKI(PUCHAR eccPubKeyBlob, PUCHAR *spkiBuf, ULONG *spkiBufLen) {
    PUCHAR x, y, spkiOutBuf = NULL;
    // secp384r1 OID (1.3.132.0.34)
    // openssl ecparam -name secp384r1 -outform DER | xxd -p | head -n 1
    UCHAR encodedPubKey[97], secp384r1OID[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    CRYPT_ALGORITHM_IDENTIFIER algId = {0};
    CRYPT_BIT_BLOB publicKey = {0};
    CERT_PUBLIC_KEY_INFO pubKeyInfo = {0};
    BOOL status;
    DWORD spkiOutBufLen;

    // TODO: could be doing more specific error checking with the magic bits of eccPubKeyBlob
    if (!eccPubKeyBlob || !spkiBuf || !spkiBufLen) {
        return FALSE;
    }
    // CryptEncodeObjectEx doesn't create uncompressed elliptic curve points,
    // so we're doing that manually with encodedPubKey
    x = eccPubKeyBlob + sizeof(BCRYPT_ECCKEY_BLOB);
    y = x + 48;
    // Uncompressed format is 0x04 + X + Y
    encodedPubKey[0] = 4;
    memcpy(encodedPubKey + 1, x, 48);
    memcpy(encodedPubKey + 49, y, 48);
    algId.pszObjId = szOID_ECC_PUBLIC_KEY;
    // Windows doesn't store the right DER-formatted OID for secp381r1
    // PCCRYPT_OID_INFO pOidInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, szOID_ECC_CURVE_P384, 0);
    // if (!pOidInfo) {
    //     return FALSE;
    // }
    // printf("OID = %s\n", szOID_ECC_CURVE_P384);
    // printf("Encoded OID: ");
    // for (DWORD i = 0; i < pOidInfo->ExtraInfo.cbData; i++) {
    //     printf("%02X ", pOidInfo->ExtraInfo.pbData[i]);
    // }
    // printf("\n");
    // printf("bytes: %lu\n", pOidInfo->ExtraInfo.cbData);
    algId.Parameters.pbData = secp384r1OID;
    algId.Parameters.cbData = sizeof(secp384r1OID);
    publicKey.pbData = encodedPubKey;
    publicKey.cbData = sizeof(encodedPubKey);
    pubKeyInfo.Algorithm = algId;
    pubKeyInfo.PublicKey = publicKey;
    status = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        &pubKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &spkiOutBuf, &spkiOutBufLen);
    if (!status) {
        return FALSE;
    }
    *spkiBuf = HeapAlloc(GetProcessHeap(), 0, spkiOutBufLen);
    if (!*spkiBuf) {
        LocalFree(spkiOutBuf);
        return FALSE;
    }
    memcpy(*spkiBuf, spkiOutBuf, spkiOutBufLen);
    *spkiBufLen = spkiOutBufLen;

    LocalFree(spkiOutBuf);
    return TRUE;
}

BOOL ConvertECCSPKIToBlob(PUCHAR spkiBuf, ULONG spkiBufLen, PUCHAR *eccPubKeyBlob,
        ULONG *eccPubKeyBlobLen) {
    BOOL status;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD pPubKeyInfoLen;
    PUCHAR encodedPubKey;

    if (!spkiBuf || spkiBufLen <= 0 || !eccPubKeyBlob || !eccPubKeyBlobLen) {
        return FALSE;
    }
    status = CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spkiBuf,
        spkiBufLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &pPubKeyInfoLen);
    if (!status) {
        return FALSE;
    }
    *eccPubKeyBlob = HeapAlloc(GetProcessHeap(), 0, 96 + sizeof(BCRYPT_ECCKEY_BLOB));
    if (!*eccPubKeyBlob) {
        LocalFree(pPubKeyInfo);
        return FALSE;
    }
    ((BCRYPT_ECCKEY_BLOB*)*eccPubKeyBlob)->dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    ((BCRYPT_ECCKEY_BLOB*)*eccPubKeyBlob)->cbKey = 48;
    encodedPubKey = pPubKeyInfo->PublicKey.pbData;
    memcpy(*eccPubKeyBlob + sizeof(BCRYPT_ECCKEY_BLOB), encodedPubKey + 1, 96);

    LocalFree(pPubKeyInfo);
    return TRUE;
}

int main(void) {
    HANDLE hFile;
    DWORD encodedRsaPrivateKeyLen, pPrivKeyInfoLen, derBufLen;
    // ULONG rsaPublicKeyBlobLen;
    ULONG encodedRsaPublicKeyLen, bytesRead, serverEcdhPublicKeyBlobLen,
        encodedServerEcdhPublicKeyLen, hashObjLen, keyHashLen, signatureLen,
        decodedRsaPublicKeyBlobLen, decodedServerEcdhPublicKeyBlobLen,
        clientEcdhPublicKeyBlobLen, encodedClientEcdhPublicKeyLen,
        clientMasterSecretLen, decodedClientEcdhPublicKeyBlobLen,
        serverMasterSecretLen, ciphertextLen, decryptedLen;
    PUCHAR encodedRsaPrivateKey, derBuf = NULL;
    // PUCHAR rsaPublicKeyBlob;
    PUCHAR encodedRsaPublicKey, serverEcdhPublicKeyBlob, encodedServerEcdhPublicKey,
        hashObj, keyHash, signature, decodedRsaPublicKeyBlob,
        decodedServerEcdhPublicKeyBlob, clientEcdhPublicKeyBlob,
        encodedClientEcdhPublicKey, clientMasterSecret, aesKeyBytes,
        decodedClientEcdhPublicKeyBlob, serverMasterSecret,
        ciphertext, decrypted;
    PCRYPT_PRIVATE_KEY_INFO pPrivKeyInfo = NULL;
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

    BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    hFile = CreateFileA("public_key.der", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    encodedRsaPublicKeyLen = GetFileSize(hFile, NULL);
    encodedRsaPublicKey = HeapAlloc(GetProcessHeap(), 0, encodedRsaPublicKeyLen);
    ReadFile(hFile, encodedRsaPublicKey, encodedRsaPublicKeyLen, &bytesRead, NULL);
    CloseHandle(hFile);
    hFile = CreateFileA("private_key.der", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    encodedRsaPrivateKeyLen = GetFileSize(hFile, NULL);
    encodedRsaPrivateKey = HeapAlloc(GetProcessHeap(), 0, encodedRsaPrivateKeyLen);
    ReadFile(hFile, encodedRsaPrivateKey, encodedRsaPrivateKeyLen, &bytesRead, NULL);
    CloseHandle(hFile);
    CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
        encodedRsaPrivateKey, encodedRsaPrivateKeyLen, CRYPT_DECODE_ALLOC_FLAG, NULL,
        &pPrivKeyInfo, &pPrivKeyInfoLen);
    CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB,
        pPrivKeyInfo->PrivateKey.pbData, pPrivKeyInfo->PrivateKey.cbData,
        CRYPT_DECODE_ALLOC_FLAG, NULL, &derBuf, &derBufLen);
    BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPRIVATE_BLOB, &rsaPrivateKey, derBuf, derBufLen, 0);
    LocalFree(pPrivKeyInfo);
    LocalFree(derBuf);
    // BCryptGenerateKeyPair(rsa, &rsaPrivateKey, 2048, 0);
    // BCryptFinalizeKeyPair(rsaPrivateKey, 0);
    // BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &rsaPublicKeyBlobLen, 0);
    // rsaPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, rsaPublicKeyBlobLen);
    // BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, rsaPublicKeyBlob,
    //     rsaPublicKeyBlobLen, &rsaPublicKeyBlobLen, 0);
    // ConvertRSABlobToSPKI(rsaPublicKeyBlob, &encodedRsaPublicKey, &encodedRsaPublicKeyLen);

    BCryptOpenAlgorithmProvider(&ecdh, BCRYPT_ECDH_P384_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(ecdh, &serverEcdhKeyPair, 384, 0);
    BCryptFinalizeKeyPair(serverEcdhKeyPair, 0);
    BCryptExportKey(serverEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &serverEcdhPublicKeyBlobLen, 0);
    serverEcdhPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, serverEcdhPublicKeyBlobLen);
    BCryptExportKey(serverEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, serverEcdhPublicKeyBlob,
        serverEcdhPublicKeyBlobLen, &serverEcdhPublicKeyBlobLen, 0);
    ConvertECCBlobToSPKI(serverEcdhPublicKeyBlob, &encodedServerEcdhPublicKey, &encodedServerEcdhPublicKeyLen);

    BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG);
    // Tried replacing {hashObj, hashObjLen} with {NULL, 0} but ran into issues
    // Maybe has to do with reusing hash function for AES key?
    BCryptGetProperty(sha256, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjLen, sizeof(ULONG), &bytesRead, 0);
    hashObj = HeapAlloc(GetProcessHeap(), 0, hashObjLen);
    BCryptCreateHash(sha256, &hSha256, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
    BCryptHashData(hSha256, encodedServerEcdhPublicKey, encodedServerEcdhPublicKeyLen, 0);
    BCryptGetProperty(sha256, BCRYPT_HASH_LENGTH, (PUCHAR)&keyHashLen, sizeof(ULONG), &bytesRead, 0);
    keyHash = HeapAlloc(GetProcessHeap(), 0, keyHashLen);
    BCryptFinishHash(hSha256, keyHash, keyHashLen, 0);
    BCryptSignHash(rsaPrivateKey, &paddingInfo, keyHash, keyHashLen, NULL, 0, &signatureLen, BCRYPT_PAD_PSS);
    signature = HeapAlloc(GetProcessHeap(), 0, signatureLen);
    BCryptSignHash(rsaPrivateKey, &paddingInfo, keyHash, keyHashLen, signature,
        signatureLen, &signatureLen, BCRYPT_PAD_PSS);

    ConvertRSASPKIToBlob(encodedRsaPublicKey, encodedRsaPublicKeyLen, &decodedRsaPublicKeyBlob,
        &decodedRsaPublicKeyBlobLen);
    BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &rsaPublicKey,
        decodedRsaPublicKeyBlob, decodedRsaPublicKeyBlobLen, 0);
    status = BCryptVerifySignature(rsaPublicKey, &paddingInfo, keyHash, keyHashLen,
        signature, signatureLen, BCRYPT_PAD_PSS);
    if (!NT_SUCCESS(status)) {
        puts("RSA signature wasn't verified.");
        exit(1);
    }

    /*
     * No built-in constant-time buffer comparison algorithm to compare server's
     * hash with client's hash of server's ECDH public key. Need to implement
     * your own.
     */
    ConvertECCSPKIToBlob(encodedServerEcdhPublicKey, encodedServerEcdhPublicKeyLen,
        &decodedServerEcdhPublicKeyBlob, &decodedServerEcdhPublicKeyBlobLen);
    BCryptImportKeyPair(ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &decodedServerEcdhPublicKey,
        decodedServerEcdhPublicKeyBlob, decodedServerEcdhPublicKeyBlobLen, 0);
    BCryptGenerateKeyPair(ecdh, &clientEcdhKeyPair, 384, 0);
    BCryptFinalizeKeyPair(clientEcdhKeyPair, 0);
    BCryptExportKey(clientEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &clientEcdhPublicKeyBlobLen, 0);
    clientEcdhPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, clientEcdhPublicKeyBlobLen);
    BCryptExportKey(clientEcdhKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, clientEcdhPublicKeyBlob,
        clientEcdhPublicKeyBlobLen, &clientEcdhPublicKeyBlobLen, 0);
    ConvertECCBlobToSPKI(clientEcdhPublicKeyBlob, &encodedClientEcdhPublicKey, &encodedClientEcdhPublicKeyLen);
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

    ConvertECCSPKIToBlob(encodedClientEcdhPublicKey, encodedClientEcdhPublicKeyLen,
        &decodedClientEcdhPublicKeyBlob, &decodedClientEcdhPublicKeyBlobLen);
    BCryptImportKeyPair(ecdh, NULL, BCRYPT_ECCPUBLIC_BLOB, &decodedClientEcdhPublicKey,
        decodedClientEcdhPublicKeyBlob, decodedClientEcdhPublicKeyBlobLen, 0);
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
    HeapFree(GetProcessHeap(), 0, encodedRsaPublicKey);
    HeapFree(GetProcessHeap(), 0, encodedRsaPrivateKey);
    // HeapFree(GetProcessHeap(), 0, rsaPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, serverEcdhPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, encodedServerEcdhPublicKey);
    HeapFree(GetProcessHeap(), 0, hashObj);
    HeapFree(GetProcessHeap(), 0, keyHash);
    HeapFree(GetProcessHeap(), 0, signature);
    HeapFree(GetProcessHeap(), 0, decodedRsaPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, decodedServerEcdhPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, clientEcdhPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, encodedClientEcdhPublicKey);
    HeapFree(GetProcessHeap(), 0, decodedClientEcdhPublicKeyBlob);
    HeapFree(GetProcessHeap(), 0, clientMasterSecret);
    HeapFree(GetProcessHeap(), 0, aesKeyBytes);
    HeapFree(GetProcessHeap(), 0, serverMasterSecret);
    HeapFree(GetProcessHeap(), 0, ciphertext);
    HeapFree(GetProcessHeap(), 0, decrypted);
    return 0;
}
