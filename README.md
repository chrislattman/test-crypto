# Cryptography library examples

While not quite TLS (no certificate chain validation), these examples try to replicate what a TLS session would look like. It demonstrates perfect forward secrecy.

Use the provided Makefile to run the examples.

Note: these examples use a pre-generated RSA key pair used to sign the "server" ephemeral ECDH public key.

The key pair (sometimes just called the RSA "key") in PEM (text) format was generated with:

```
openssl genrsa -out keypair.pem 2048
```

The private key in DER (binary) format was derived with:

```
openssl pkcs8 -topk8 -nocrypt -inform PEM -in keypair.pem -outform DER -out private_key.der
```

The public key in DER format was derived with:

```
openssl rsa -pubout -inform PEM -in keypair.pem -outform DER -out public_key.der
```
