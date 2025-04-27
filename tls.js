const crypto = require("node:crypto");
const fs = require("node:fs");

const encodedRsaPublicKey = fs.readFileSync("public_key.der");
const encodedRsaPrivateKey = fs.readFileSync("private_key.der");
const rsaPrivateKey = crypto.createPrivateKey({
    key: encodedRsaPrivateKey,
    format: "der",
    type: "pkcs8",
});

const serverEcdh = crypto.createECDH("secp384r1");
const serverEcdhPublicKeyRaw = serverEcdh.generateKeys();
// hack to encode secp384r1 public key in DER SPKI format manually since Node.js
// doesn't support it yet :(
const prefix = Buffer.from("3076301006072a8648ce3d020106052b81040022036200", "hex");
const newLength = prefix.length + serverEcdhPublicKeyRaw.length;
const encodedServerEcdhPublicKey = Buffer.concat(
    [prefix, serverEcdhPublicKeyRaw],
    newLength,
);

rsaPrivateKey.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
rsaPrivateKey.saltLength = crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;
const signature = crypto.sign("sha384", encodedServerEcdhPublicKey, rsaPrivateKey);

const decodedRsaPublicKey = crypto.createPublicKey({
    key: encodedRsaPublicKey,
    format: "der",
    type: "spki",
});
decodedRsaPublicKey.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
decodedRsaPublicKey.saltLength = crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;
if (!crypto.verify("sha384", encodedServerEcdhPublicKey, decodedRsaPublicKey, signature)) {
    throw new Error("RSA signature wasn't verified.");
}

// client should use crypto.timingSafeEqual() to compare server's hash with
// its own hash of the server's encoded ECDH public key to avoid timing attacks
const decodedServerEcdhPublicKey = encodedServerEcdhPublicKey.subarray(prefix.length);
const clientEcdh = crypto.createECDH("secp384r1");
const clientEcdhPublicKeyRaw = clientEcdh.generateKeys();
// manual public key encoding again
const encodedClientEcdhPublicKey = Buffer.concat(
    [prefix, clientEcdhPublicKeyRaw],
    newLength,
);
const clientMasterSecret = clientEcdh.computeSecret(decodedServerEcdhPublicKey);
sha256 = crypto.createHash("sha256");
sha256.update(clientMasterSecret);
const aesKeyBytes = sha256.digest();
const aesKey = crypto.createSecretKey(aesKeyBytes);

const decodedClientEcdhPublicKey = encodedClientEcdhPublicKey.subarray(prefix.length);
const serverMasterSecret = serverEcdh.computeSecret(decodedClientEcdhPublicKey);
if (!clientMasterSecret.equals(serverMasterSecret)) {
    throw new Error("Master secrets don't match.");
}

const plaintext = "Hello world!";
const aad = Buffer.from("authenticated but unencrypted data");
// no known way of choosing between /dev/random and /dev/urandom
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
cipher.setAAD(aad);
let ciphertext = cipher.update(plaintext);
ciphertext = Buffer.concat([ciphertext, cipher.final()]);
const authTag = cipher.getAuthTag();

const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
decipher.setAAD(aad);
decipher.setAuthTag(authTag);
let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);
const recovered = decrypted.toString();
if (plaintext !== recovered) {
    throw new Error("Plaintexts don't match.");
}
