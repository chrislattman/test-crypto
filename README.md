# Cryptography library examples

While not quite TLS (no certificate chain validation), these examples try to replicate what a TLS session would look like. It demonstrates perfect forward secrecy.

Use the provided Makefile to run the examples. Before running any of them, make sure to create a Python virtual environment, install the dependencies in requirements.txt, and run

```
conan profile detect --force
conan install . --output-folder=build --build=missing -s build_type=Debug
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug
```

to generate the build files for the POSIX C project.

Note: these examples allow you to use a pre-generated RSA key pair used to sign the "server" ephemeral ECDH public key. However, some of the examples allow you to use the Trusted Platform Module (TPM, if available) to securely generate a key pair and sign the server's public key that way; use the `--tpm` flag.

- Run `sudo chmod 666 /dev/tpm0 && sudo chmod 666 /dev/tpmrm0` first
- If using the TPM, the securely generated key pair is lost on reboot by default
- TPMs are also used to store biometric information and other secrets

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

These commands use OpenSSL. Popular TLS libraries for embedded platforms are wolfCrypt (part of wolfSSL) and TF-PSA-Crypto (part of Mbed TLS)

- These embedded crypto libraries are also used for secure bootloaders: wolfBoot and MCUboot respectively

> C# offers a cryptography interface, but it's not fully cross-platform, as it requires either using the Cryptography API: Next Generation (CNG) library (bcrypt.dll) on Windows, or OpenSSL for non-Windows platforms.

> Windows CNG stores cryptographic public/private key pairs as blobs, which aren't compatible with OpenSSL-generated key pairs. This is something to consider when importing private keys or exporting public keys.

> The major operating systems use different sources of entropy to generate cryptographically secure pseudorandom numbers. Linux uses `genrandom()` which polls from `/dev/urandom`, macOS uses `arc4random_buf()`, and Windows uses `BCryptGenRandom()`.

> For Swift, Apple CryptoKit (Swift Crypto on Linux and Windows) uses corecrypto on macOS, which is a C library but isn't exposed via headers. On other platforms, Swift Crypto uses BoringSSL. However, CommonCrypto, also built on top of corecrypto, is still usable as a C library on macOS, but only older symmetric cryptography is supported (e.g. no AES-256-GCM support). Security.framework, again built on top of corecrypto, exposes several asymmetric cryptographic algorithms in C, but is not being updated for modern post-quantum algorithms (unlike corecrypto/Apple CryptoKit).

> A related technology to a TPM is Arm TrustZone. It is used to establish a secure "area" of the CPU for tasks like secure boot and firmware update (Intel SGX once played this role, but has been discontinued). Even if the non-secure area is completely compromised, the secure area is inaccessible. Intel TDX and AMD SEV are related concepts for server CPUs (Xeon and EPYC), but those enforce hardware VM isolation from an untrusted hypervisor.

> Hardware Security Modules (HSMs) are physically separate devices that perform cryptographic operations and secure key storage (possibly for multiple servers) at a high rate.
