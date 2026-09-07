using System.Security.Cryptography;
using System.Text;

byte[] encodedRsaPublicKey = File.ReadAllBytes("public_key.der");
byte[] encodedRsaPrivateKey = File.ReadAllBytes("private_key.der");
using RSA rsaPrivateKey = RSA.Create();
rsaPrivateKey.ImportPkcs8PrivateKey(encodedRsaPrivateKey, out _);

using ECDiffieHellman serverEcdhKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
byte[] encodedServerEcdhPublicKey = serverEcdhKeyPair.ExportSubjectPublicKeyInfo();

byte[] signature = rsaPrivateKey.SignData(encodedServerEcdhPublicKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

using RSA decodedRsaPublicKey = RSA.Create();
decodedRsaPublicKey.ImportSubjectPublicKeyInfo(encodedRsaPublicKey, out _);
if (!decodedRsaPublicKey.VerifyData(encodedServerEcdhPublicKey, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss))
{
    throw new Exception("RSA signature wasn't verified.");
}

// client should use CryptographicOperations.FixedTimeEquals() to compare server's hash with
// its own hash of the server's encoded ECDH public key to avoid timing attacks
using ECDiffieHellman decodedServerEcdhPublicKey = ECDiffieHellman.Create();
decodedServerEcdhPublicKey.ImportSubjectPublicKeyInfo(encodedServerEcdhPublicKey, out _);
using ECDiffieHellman clientEcdhKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
byte[] encodedClientEcdhPublicKey = clientEcdhKeyPair.ExportSubjectPublicKeyInfo();
byte[] clientMasterSecret = clientEcdhKeyPair.DeriveKeyMaterial(decodedServerEcdhPublicKey.PublicKey);
byte[] aesKey = SHA256.HashData(clientMasterSecret);

using ECDiffieHellman decodedClientEcdhPublicKey = ECDiffieHellman.Create();
decodedClientEcdhPublicKey.ImportSubjectPublicKeyInfo(encodedClientEcdhPublicKey, out _);
byte[] serverMasterSecret = serverEcdhKeyPair.DeriveKeyMaterial(decodedClientEcdhPublicKey.PublicKey);
if (!clientMasterSecret.SequenceEqual(serverMasterSecret))
{
    throw new Exception("Master secrets don't match.");
}
CryptographicOperations.ZeroMemory(clientMasterSecret);
CryptographicOperations.ZeroMemory(serverMasterSecret);

string plaintext = "Hello world!";
byte[] ciphertext = new byte[plaintext.Length];
byte[] aad = Encoding.UTF8.GetBytes("authenticated but unencrypted data");
byte[] iv = RandomNumberGenerator.GetBytes(12);
byte[] tag = new byte[16];
using AesGcm cipher = new(aesKey, tag.Length);
cipher.Encrypt(iv, Encoding.UTF8.GetBytes(plaintext), ciphertext, tag, aad);

byte[] decrypted = new byte[ciphertext.Length];
cipher.Decrypt(iv, ciphertext, tag, decrypted, aad);
string recovered = Encoding.UTF8.GetString(decrypted);
if (plaintext != recovered)
{
    throw new Exception("Plaintexts don't match.");
}

CryptographicOperations.ZeroMemory(aesKey);
