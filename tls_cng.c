#include <stdio.h>
#include <Windows.h>

// #pragma comment(lib, "bcrypt.lib")
// #pragma comment(lib, "crypt32.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/**
 * Converts an RSA public key BLOB to ASN.1 DER format and then to SPKI DER
 * format, which can be used in a X.509 certificate.
 */
BOOL ConvertRSABlobToSPKI(PUCHAR rsaPubKeyBlob, PUCHAR *spkiBuf, ULONG *spkiBufLen) {
    BOOL status;
    PUCHAR encodedPubKey = NULL, spkiOutBuf = NULL;
    DWORD encodedPubKeyLen, spkiOutBufLen;
    CRYPT_ALGORITHM_IDENTIFIER algId = {0};
    CERT_PUBLIC_KEY_INFO pubKeyInfo = {0};

    // TODO: could be doing more specific error checking with the magic bits of rsaPubKeyBlob
    if (!rsaPubKeyBlob || !spkiBuf || !spkiBufLen) {
        return FALSE;
    }

    /*
    // If the first call to CryptEncodeObjectEx is undesired
    // (manual ASN.1 encoding follows):
    BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)rsaPubKeyBlob;
    PUCHAR exponent = rsaPubKeyBlob + sizeof(BCRYPT_RSAKEY_BLOB);
    PUCHAR modulus = exponent + pBlob->cbPublicExp;
    // 11 bytes come from the ASN.1 encoding standard:
    // 0x30 (sequence tag)
    // 0x82 (this byte is needed because total length > 128 bytes so 2 bytes follow)
    // [2 bytes for total length of modulus and exponent]
    // 0x02 (integer tag)
    // 0x82 (this byte is needed because 1 + modulus length > 128 bytes so 2 bytes follow)
    // [2 bytes for 1 + modulus length]
    // 0x00 (leading byte to denote positive integer)
    // ... (modulus)
    // 0x02 (integer tag; no 0x82 byte follows since exponent length < 128 bytes)
    // [1 byte for exponent length]
    // ... (exponent)
    // If you exclude ... you get 11 bytes of overhead
    encodedPubKeyLen = 11 + pBlob->cbPublicExp + pBlob->cbModulus;
    encodedPubKey = LocalAlloc(LMEM_FIXED, encodedPubKeyLen);
    if (!encodedPubKey) {
        return FALSE;
    }
    encodedPubKey[0] = 0x30;
    encodedPubKey[1] = 0x82;
    ULONG totalLen = 1 + pBlob->cbModulus + pBlob->cbPublicExp + 6;
    // Windows endianness is switching byte order so memcpy(encodedPubKey + 2, &totalLen, 2); won't work
    encodedPubKey[2] = (totalLen >> 8) & 0xFF;
    encodedPubKey[3] = totalLen & 0xFF;
    encodedPubKey[4] = 0x02;
    encodedPubKey[5] = 0x82;
    ULONG modLenPlus1 = 1 + pBlob->cbModulus;
    // memcpy(encodedPubKey + 6, &modLenPlus1, 2); // endianness issue again
    encodedPubKey[6] = (modLenPlus1 >> 8) & 0xFF;
    encodedPubKey[7] = modLenPlus1 & 0xFF;
    encodedPubKey[8] = 0x00;
    memcpy(encodedPubKey + 9, modulus, pBlob->cbModulus);
    encodedPubKey[9 + pBlob->cbModulus] = 0x02;
    encodedPubKey[9 + pBlob->cbModulus + 1] = (UCHAR)pBlob->cbPublicExp;
    memcpy(encodedPubKey + 9 + pBlob->cbModulus + 2, exponent, pBlob->cbPublicExp);
    */
    status = CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
        rsaPubKeyBlob, CRYPT_ENCODE_ALLOC_FLAG, NULL, &encodedPubKey, &encodedPubKeyLen);
    if (!status) {
        return FALSE;
    }

    /*
    // If the second call to CryptObjectEncodeEx is undesired
    // (manual SPKI encoding follows):
    // $ openssl asn1parse -genconf <(echo -e "[default]\nasn1 = OID:rsaEncryption") -noout -out >(xxd -p)
    // Might have to use temporary files instead of bash process substitution
    UCHAR algIdEncoded[] = {
        0x30, 0x0D, // sequence tag, length of remainder of this byte array (13)
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // RSA OID (1.2.840.113549.1.1.1)
        0x05, 0x00  // null tag, 0 byte for 0 length array
    };
    // 3 bytes comes from the SPKI encoding standard:
    // ... (algIdEncoded)
    // 0x03 (bit string tag)
    // [1 byte for 1 + encodedPubKeyLen]
    // 0x00 (leading byte to denote positive integer)
    // ... (encodedPubKey)
    // If you exclude ... you get 3 bytes of overhead
    spkiOutBufLen = sizeof(algIdEncoded) + 3 + encodedPubKeyLen;
    spkiOutBuf = LocalAlloc(LMEM_FIXED, spkiOutBufLen);
    if (!spkiOutBuf) {
        return FALSE;
    }
    memcpy(spkiOutBuf, algIdEncoded, sizeof(algIdEncoded));
    spkiOutBuf[sizeof(algIdEncoded)] = 0x03;
    spkiOutBuf[sizeof(algIdEncoded) + 1] = (UCHAR)(1 + encodedPubKeyLen);
    spkiOutBuf[sizeof(algIdEncoded) + 2] = 0x00;
    memcpy(spkiOutBuf + sizeof(algIdEncoded) + 3, encodedPubKey, encodedPubKeyLen);
    */
    algId.pszObjId = szOID_RSA_RSA;
    pubKeyInfo.Algorithm = algId;
    pubKeyInfo.PublicKey.pbData = encodedPubKey;
    pubKeyInfo.PublicKey.cbData = encodedPubKeyLen;
    status = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        &pubKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &spkiOutBuf, &spkiOutBufLen);
    if (!status) {
        LocalFree(encodedPubKey);
        return FALSE;
    }

    *spkiBuf = HeapAlloc(GetProcessHeap(), 0, spkiOutBufLen);
    if (!*spkiBuf) {
        LocalFree(encodedPubKey);
        LocalFree(spkiOutBuf);
        return FALSE;
    }
    memcpy(*spkiBuf, spkiOutBuf, spkiOutBufLen);
    *spkiBufLen = spkiOutBufLen;

    LocalFree(encodedPubKey);
    LocalFree(spkiOutBuf);
    return TRUE;
}

/**
 * Converts an RSA public key in SPKI DER format to ASN.1 DER format and then to
 * the BLOB format, which can be used by `BCryptImportKeyPair`.
 */
BOOL ConvertRSASPKIToBlob(PUCHAR spkiBuf, ULONG spkiBufLen, PUCHAR *rsaPubKeyBlob,
        ULONG *rsaPubKeyBlobLen) {
    BOOL status;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD pPubKeyInfoLen, decodedPubKeyLen;
    PUCHAR decodedPubKey = NULL;

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
        CRYPT_DECODE_ALLOC_FLAG, NULL, &decodedPubKey, &decodedPubKeyLen);
    if (!status) {
        LocalFree(pPubKeyInfo);
        return FALSE;
    }

    *rsaPubKeyBlob = HeapAlloc(GetProcessHeap(), 0, decodedPubKeyLen);
    if (!*rsaPubKeyBlob) {
        LocalFree(pPubKeyInfo);
        LocalFree(decodedPubKey);
        return FALSE;
    }
    memcpy(*rsaPubKeyBlob, decodedPubKey, decodedPubKeyLen);
    *rsaPubKeyBlobLen = decodedPubKeyLen;

    LocalFree(pPubKeyInfo);
    LocalFree(decodedPubKey);
    return TRUE;
}

/**
 * Converts an ECC public key BLOB to an uncompressed EC point and then to SPKI
 * DER format, which can be used in a X.509 certificate.
 */
BOOL ConvertECCBlobToSPKI(PUCHAR eccPubKeyBlob, PUCHAR *spkiBuf, ULONG *spkiBufLen) {
    PUCHAR x, y, spkiOutBuf = NULL;
    // secp384r1 OID (1.3.132.0.34)
    // $ openssl ecparam -name secp384r1 -outform DER | xxd -p | head -n 1
    UCHAR encodedPubKey[97];
    UCHAR secp384r1OID[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    CRYPT_ALGORITHM_IDENTIFIER algId = {0};
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
    // Uncompressed format is 0x04 || X-coordinate || Y-coordinate
    encodedPubKey[0] = 4;
    memcpy(encodedPubKey + 1, x, 48);
    memcpy(encodedPubKey + 49, y, 48);

    /*
    // If the call to CryptEncodeObjectEx is undesired
    // (manual SPKI encoding follows):
    // $ openssl asn1parse -genconf <(echo -e "[default]\nasn1 = OID:id-ecPublicKey") -noout -out >(xxd -p)
    // Might have to use temporary files instead of bash process substitution
    UCHAR algIdEncoded[] = {
        0x30, 0x10, // sequence tag, length of remainder of this byte array (16)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // ECC public key OID (1.2.840.10045.2.1)
        0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 // secp384r1 OID
    };
    // 5 bytes comes from the SPKI encoding standard:
    // 0x30 (sequence tag)
    // [1 byte for sizeof(algIdEncoded) + 3 + sizeof(encodedPubKey)]
    // ... (algIdEncoded)
    // 0x03 (bit string tag)
    // [1 byte for 1 + sizeof(encodedPubKey)]
    // 0x00 (for "unused" bits)
    // ... (encodedPubKey)
    // If you exclude ... you get 5 bytes of overhead
    spkiOutBufLen = 2 + sizeof(algIdEncoded) + 3 + sizeof(encodedPubKey);
    spkiOutBuf = LocalAlloc(LMEM_FIXED, spkiOutBufLen);
    if (!spkiOutBuf) {
        return FALSE;
    }
    spkiOutBuf[0] = 0x30;
    spkiOutBuf[1] = (UCHAR)(sizeof(algIdEncoded) + 3 + sizeof(encodedPubKey));
    memcpy(spkiOutBuf + 2, algIdEncoded, sizeof(algIdEncoded));
    spkiOutBuf[2 + sizeof(algIdEncoded)] = 0x03;
    spkiOutBuf[2 + sizeof(algIdEncoded) + 1] = (UCHAR)(1 + sizeof(encodedPubKey));
    spkiOutBuf[2 + sizeof(algIdEncoded) + 2] = 0x00;
    memcpy(spkiOutBuf + 2 + sizeof(algIdEncoded) + 3, encodedPubKey, sizeof(encodedPubKey));
    */

    algId.pszObjId = szOID_ECC_PUBLIC_KEY;
    algId.Parameters.pbData = secp384r1OID;
    algId.Parameters.cbData = sizeof(secp384r1OID);
    pubKeyInfo.Algorithm = algId;
    pubKeyInfo.PublicKey.pbData = encodedPubKey;
    pubKeyInfo.PublicKey.cbData = sizeof(encodedPubKey);
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

/**
 * Converts an ECC public key in SPKI DER format to an uncompressed EC point and
 * then to the BLOB format, which can be used by `BCryptImportKeyPair`.
 */
BOOL ConvertECCSPKIToBlob(PUCHAR spkiBuf, ULONG spkiBufLen, PUCHAR *eccPubKeyBlob,
        ULONG *eccPubKeyBlobLen) {
    BOOL status;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD pPubKeyInfoLen;
    PUCHAR decodedPubKey;

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
    decodedPubKey = pPubKeyInfo->PublicKey.pbData;
    memcpy(*eccPubKeyBlob + sizeof(BCRYPT_ECCKEY_BLOB), decodedPubKey + 1, 96);
    *eccPubKeyBlobLen = 96 + sizeof(BCRYPT_ECCKEY_BLOB);

    LocalFree(pPubKeyInfo);
    return TRUE;
}

int main(void) {
    HANDLE hFile;
    DWORD encodedRsaPrivateKeyLen, pPrivKeyInfoLen, derBufLen;
    PUCHAR encodedRsaPrivateKey, derBuf = NULL;
    PCRYPT_PRIVATE_KEY_INFO pPrivKeyInfo = NULL;
    // ULONG rsaPublicKeyBlobLen;
    // PUCHAR rsaPublicKeyBlob;
    ULONG encodedRsaPublicKeyLen, bytesRead, serverEcdhPublicKeyBlobLen,
        encodedServerEcdhPublicKeyLen, hashObjLen, keyHashLen, signatureLen,
        decodedRsaPublicKeyBlobLen, decodedServerEcdhPublicKeyBlobLen,
        clientEcdhPublicKeyBlobLen, encodedClientEcdhPublicKeyLen,
        clientMasterSecretLen, decodedClientEcdhPublicKeyBlobLen,
        serverMasterSecretLen, ciphertextLen, decryptedLen;
    PUCHAR encodedRsaPublicKey, serverEcdhPublicKeyBlob, encodedServerEcdhPublicKey,
        hashObj, keyHash, signature, decodedRsaPublicKeyBlob,
        decodedServerEcdhPublicKeyBlob, clientEcdhPublicKeyBlob,
        encodedClientEcdhPublicKey, clientMasterSecret, aesKeyBytes,
        decodedClientEcdhPublicKeyBlob, serverMasterSecret,
        ciphertext, decrypted;
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
    HeapFree(GetProcessHeap(), 0, encodedRsaPrivateKey);
    LocalFree(pPrivKeyInfo);
    LocalFree(derBuf);
    // BCryptGenerateKeyPair(rsa, &rsaPrivateKey, 2048, 0);
    // BCryptFinalizeKeyPair(rsaPrivateKey, 0);
    // BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &rsaPublicKeyBlobLen, 0);
    // rsaPublicKeyBlob = HeapAlloc(GetProcessHeap(), 0, rsaPublicKeyBlobLen);
    // BCryptExportKey(rsaPrivateKey, NULL, BCRYPT_RSAPUBLIC_BLOB, rsaPublicKeyBlob,
    //     rsaPublicKeyBlobLen, &rsaPublicKeyBlobLen, 0);
    // ConvertRSABlobToSPKI(rsaPublicKeyBlob, &encodedRsaPublicKey, &encodedRsaPublicKeyLen);
    // HeapFree(GetProcessHeap(), 0, rsaPublicKeyBlob);

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
    BCryptCreateHash(sha256, &hSha256, hashObj, hashObjLen, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
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
