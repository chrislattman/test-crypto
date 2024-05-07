const crypto = require("node:crypto");

const PRESHARED_SECRET = Buffer.from([0x50, 0x52, 0x45, 0x53, 0x48, 0x41, 0x52,
     0x45, 0x44, 0x5f, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54]);

const {
    publicKey: encodedRsaPublicKey,
    privateKey: rsaPrivateKeyBytes,
} = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: "spki",
        format: "der",
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "der",
    },
});

const hmac = crypto.createHmac("sha256", PRESHARED_SECRET);
hmac.update(encodedRsaPublicKey);
// const mac = hmac.digest();

const decodedRsaPublicKey = crypto.createPublicKey({
    key: encodedRsaPublicKey,
    format: "der",
    type: "spki",
});
const masterSecret = crypto.randomBytes(128);
const encryptedMS = crypto.publicEncrypt({
    key: decodedRsaPublicKey,
    oaepHash: "sha256",
}, masterSecret);

const rsaPrivateKey = crypto.createPrivateKey({
    key: rsaPrivateKeyBytes,
    format: "der",
    type: "pkcs8",
});
const decryptedMS = crypto.privateDecrypt({
    key: rsaPrivateKey,
    oaepHash: "sha256",
}, encryptedMS);
if (!masterSecret.equals(decryptedMS)) {
    throw new Error("Master secrets don't match.");
}
const sha256 = crypto.createHash("sha256");
sha256.update(decryptedMS);
const aesKeyBytes = sha256.digest();
const aesKey = crypto.createSecretKey(aesKeyBytes);

const plaintext = "Hello world!";
const aad = Buffer.from("authenticated but unencrypted data");
// no known way of choosing between /dev/random and /dev/urandom
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
cipher.setAAD(aad);
let ciphertext = cipher.update(Buffer.from(plaintext));
// ciphertext += cipher.final();

const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
decipher.setAAD(aad);
let decrypted = decipher.update(ciphertext);
// decrypted += decipher.final();
const recovered = decrypted.toString();
if (plaintext !== recovered) {
    throw new Error("Plaintexts don't match.");
}
