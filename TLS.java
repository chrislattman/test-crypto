import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TLS
{
    public static void main(String[] args) throws Exception {
        /*
         * The server reads public and private keys from .der files for RSA
         * signatures
         *
         * Note: you could also use ECDSA (DSA is obsolete)
         */
        byte[] encodedRsaPublicKey = Files.readAllBytes(Paths.get("public_key.der"));
        byte[] encodedRsaPrivateKey = Files.readAllBytes(Paths.get("private_key.der"));
        PKCS8EncodedKeySpec rsaPrivateKeySpec = new PKCS8EncodedKeySpec(encodedRsaPrivateKey);
        PrivateKey rsaPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(rsaPrivateKeySpec);

        /*
         * The server generates a random secp384r1 key pair for ECDH
         *
         * Note: you could also use DH (RSA is obsolete for key agreement)
         */
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstanceStrong();
        ECGenParameterSpec ecGen = new ECGenParameterSpec("secp384r1");
        keyPairGen.initialize(ecGen, random);
        KeyPair serverEcdhKeyPair = keyPairGen.generateKeyPair();
        byte[] encodedServerEcdhPublicKey = serverEcdhKeyPair.getPublic().getEncoded();

        /*
         * In the absence of a certificate authority, the server's RSA public
         * key is assumed to be known and trusted by both parties.
         *
         * Nonetheless, the server sends: its encoded ECDH public key (120 bytes
         * long), the SHA-256 hash of the encoded ECDH public key (32 bytes
         * long), the RSA signature of the hash (256 bytes long), and its
         * encoded RSA public key (used to verify the signature) to the client
         * (294 bytes long). This example chooses to sign with PSS instead of
         * PKCS#1 v1.5 for better security.
         *
         * Normally, the RSA public key is part of an X.509 certificate, which
         * itself is part of a chain of signed certificates, ultimately ending
         * with a root certificate installed on the computer.
         */
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyHash = sha256.digest(encodedServerEcdhPublicKey);
        Signature rsaSign = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pssSpec = new PSSParameterSpec("SHA-256",
            "MGF1", MGF1ParameterSpec.SHA256, (2048 / 8) - (256 / 8) - 2, 1);
        rsaSign.setParameter(pssSpec);
        rsaSign.initSign(rsaPrivateKey);
        rsaSign.update(keyHash);
        byte[] signature = rsaSign.sign();

        /*
         * The client then attempts to verify the signature of the hash using
         * the server's decoded RSA public key.
         */
        X509EncodedKeySpec decodedRsaPublicKeySpec = new X509EncodedKeySpec(encodedRsaPublicKey);
        PublicKey decodedRsaPublicKey = KeyFactory
            .getInstance("RSA")
            .generatePublic(decodedRsaPublicKeySpec);
        rsaSign.initVerify(decodedRsaPublicKey);
        rsaSign.update(keyHash);
        if (!rsaSign.verify(signature)) {
            throw new Exception("RSA signature wasn't verified.");
        }

        /*
         * If the signature is verified, the client checks that the hash of the
         * server's encoded ECDH public key is correct (use
         * MessageDigest.isEqual() to avoid timing attacks). If so, the client
         * decodes the server's ECDH public key, generates its own ECDH keypair,
         * then generates the master secret (sometimes called premaster secret
         * or shared secret) using its ECDH private key and the server's ECDH
         * public key, and hashes that master secret with SHA-256 to generate a
         * 256-bit AES secret key. It then sends its encoded ECDH public key to
         * the server (also 120 bytes long).
         */
        X509EncodedKeySpec decodedServerEcdhPublicKeySpec = new X509EncodedKeySpec(
            encodedServerEcdhPublicKey);
        PublicKey decodedServerEcdhPublicKey = KeyFactory
            .getInstance("EC")
            .generatePublic(decodedServerEcdhPublicKeySpec);
        KeyPair clientEcdhKeyPair = keyPairGen.generateKeyPair();
        byte[] encodedClientEcdhPublicKey = clientEcdhKeyPair.getPublic().getEncoded();
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(clientEcdhKeyPair.getPrivate());
        agreement.doPhase(decodedServerEcdhPublicKey, true);
        byte[] clientMasterSecret = agreement.generateSecret();
        sha256.reset();
        byte[] aesKeyBytes = sha256.digest(clientMasterSecret);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        /*
         * The server decodes the client's ECDH public key and generates the
         * master secret using its ECDH private key and the client's ECDH public
         * key. Then it generates the AES secret key the same way the client
         * does. Both master secrets should be 48 bytes long.
         */
        X509EncodedKeySpec decodedClientEcdhPublicKeySpec = new X509EncodedKeySpec(
            encodedClientEcdhPublicKey);
        PublicKey decodedClientEcdhPublicKey = KeyFactory
            .getInstance("EC")
            .generatePublic(decodedClientEcdhPublicKeySpec);
        agreement.init(serverEcdhKeyPair.getPrivate());
        agreement.doPhase(decodedClientEcdhPublicKey, true);
        byte[] serverMasterSecret = agreement.generateSecret();
        if (!Arrays.equals(clientMasterSecret, serverMasterSecret)) {
            throw new Exception("Master secrets don't match.");
        }

        /*
         * AES-256-GCM is used to encrypt a message. The ciphertext (should be
         * 28 bytes long, 12 bytes of data followed by 16 bytes for the tag),
         * initialization vector (IV, sometimes called a nonce), and additional
         * associated data (AAD) is sent over.
         *
         * GCM uses an unencrypted AAD to generate a tag after encryption, which
         * is appended to the ciphertext. The tag is validated during decryption
         * using the same AAD.
         *
         * The benefit AES-256-GCM has over AES-256-CBC with HMAC-SHA256 is that
         * GCM is parallelizable and therefore more efficient with
         * multithreading. However, GCM requires a different random IV for every
         * single plaintext.
         */
        String plaintext = "Hello world!";
        byte[] aad = "authenticated but unencrypted data".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[12];
        random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        /*
         * Decrypting the message with the ciphertext, IV (in gcmSpec), and AAD
         * using AES-256-GCM.
         */
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);
        String recovered = new String(decrypted, StandardCharsets.UTF_8);
        if (!plaintext.equals(recovered)) {
            throw new Exception("Plaintexts don't match.");
        }
    }
}
