# Cryptography library examples

While not quite TLS (no certificate chain validation), these examples try to replicate what a TLS session would look like. It demonstrates perfect forward secrecy.

Use the provided Makefile to run the examples.

Note: these examples use a pre-generated RSA key pair used to sign the "server" ephemeral ECDH public key.

The key pair (sometimes just called the RSA "key") in PEM (text) format was generated with:

```
openssl genrsa -out keypair.pem 3072
```

The private key in PKCS#8 DER (binary) format was derived with:

```
openssl pkcs8 -topk8 -nocrypt -inform PEM -in keypair.pem -outform DER -out private_key.der
```

The public key in SPKI DER format was derived with:

```
openssl rsa -pubout -inform PEM -in keypair.pem -outform DER -out public_key.der
```

These commands use OpenSSL. Popular TLS libraries for embedded platforms are wolfSSL and Mbed TLS.

> Note: C# offers a cryptography interface, but it's not fully cross-platform, as it requires either using the Cryptography API: Next Generation (CNG) library (bcrypt.dll) on Windows, or OpenSSL for non-Windows platforms.

> Windows CNG stores cryptographic public/private key pairs as blobs, which aren't compatible with OpenSSL-generated key pairs. This is something to consider when importing private keys or exporting public keys.

> The major operating systems use different sources of entropy to generate cryptographically secure pseudorandom numbers. Linux uses `genrandom()` which polls from `/dev/urandom`, macOS uses `arc4random_buf()`, and Windows uses `BCryptGenRandom()`.
