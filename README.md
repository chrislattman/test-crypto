# Cryptography library examples

While not quite TLS (no certificate chain validation), these examples try to replicate what a TLS session would look like. It demonstrates perfect forward secrecy.

Use the provided Makefile to run the examples.

Note: these examples use a pre-generated RSA key pair used to sign the "server" ephemeral ECDH public key.

The key pair (sometimes just called the RSA "key") in PEM (text) format was generated with:

```
openssl genrsa -out keypair.pem 2048
```

The private key in PKCS#8 DER (binary) format was derived with:

```
openssl pkcs8 -topk8 -nocrypt -inform PEM -in keypair.pem -outform DER -out private_key.der
```

The public key in SPKI DER format was derived with:

```
openssl rsa -pubout -inform PEM -in keypair.pem -outform DER -out public_key.der
```

> Note: C# offers a cryptography interface, but it's not fully cross-platform, as it requires either using the Cryptography API: Next Generation (CNG) library (bcrypt.dll) on Windows, or OpenSSL for non-Windows platforms.

> Windows CNG stores cryptographic public/private key pairs as blobs, which aren't compatible with OpenSSL-generated key pairs. This is something to consider when importing private keys or exporting public keys.
