package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"log"
	"os"
)

func zeroize(input []byte) {
	for i := range input {
		input[i] = 0
	}
}

func main() {
	encodedRsaPublicKey, _ := os.ReadFile("public_key.der")
	encodedRsaPrivateKey, _ := os.ReadFile("private_key.der")
	var rsaPrivateKey *rsa.PrivateKey
	key, _ := x509.ParsePKCS8PrivateKey(encodedRsaPrivateKey)
	switch key := key.(type) {
	case *rsa.PrivateKey:
		rsaPrivateKey = key
	default:
		log.Fatalln("Error parsing encodedRsaPrivateKey")
	}

	rng := rand.Reader
	serverEcdhPrivateKey, _ := ecdh.P384().GenerateKey(rng)
	encodedServerEcdhPublicKey, _ := x509.MarshalPKIXPublicKey(serverEcdhPrivateKey.PublicKey())

	// Go requires the key to be hashed manually before signing it
	keyHash := sha512.Sum384(encodedServerEcdhPublicKey)
	opts := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	signature, _ := rsa.SignPSS(rng, rsaPrivateKey, crypto.SHA384, keyHash[:], &opts)

	var decodedRsaPublicKey *rsa.PublicKey
	key, _ = x509.ParsePKIXPublicKey(encodedRsaPublicKey)
	switch key := key.(type) {
	case *rsa.PublicKey:
		decodedRsaPublicKey = key
	default:
		log.Fatalln("Error parsing encodedRsaPublicKey")
	}
	err := rsa.VerifyPSS(decodedRsaPublicKey, crypto.SHA384, keyHash[:], signature, &opts)
	if err != nil {
		log.Fatalln("RSA signature wasn't verified.")
	}

	// client should use subtle.ConstantTimeCompare() from crypto/subtle to
	// compare server's hash with its own hash of the server's encoded ECDH
	// public key to avoid timing attacks
	var decodedServerEcdhPublicKey *ecdh.PublicKey
	key, _ = x509.ParsePKIXPublicKey(encodedServerEcdhPublicKey)
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		decodedServerEcdhPublicKey, _ = key.ECDH()
	default:
		log.Fatalln("Error parsing encodedServerEcdhPublicKey")
	}
	clientEcdhPrivateKey, _ := ecdh.P384().GenerateKey(rng)
	encodedClientEcdhPublicKey, _ := x509.MarshalPKIXPublicKey(clientEcdhPrivateKey.PublicKey())
	clientMasterSecret, _ := clientEcdhPrivateKey.ECDH(decodedServerEcdhPublicKey)
	aesKey := sha256.Sum256(clientMasterSecret)

	var decodedClientEcdhPublicKey *ecdh.PublicKey
	key, _ = x509.ParsePKIXPublicKey(encodedClientEcdhPublicKey)
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		decodedClientEcdhPublicKey, _ = key.ECDH()
	default:
		log.Fatalln("Error parsing encodedClientEcdhPublicKey")
	}
	serverMasterSecret, _ := serverEcdhPrivateKey.ECDH(decodedClientEcdhPublicKey)
	if !bytes.Equal(clientMasterSecret, serverMasterSecret) {
		log.Fatalln("Master secrets don't match.")
	}
	zeroize(clientMasterSecret)
	zeroize(serverMasterSecret)

	plaintext := "Hello world!"
	aad := []byte("authenticated but unencrypted data")
	var iv [12]byte
	rng.Read(iv[:])
	block, _ := aes.NewCipher(aesKey[:])
	aesgcm, _ := cipher.NewGCM(block)
	ciphertext := aesgcm.Seal(nil, iv[:], []byte(plaintext), aad)

	decrypted, _ := aesgcm.Open(nil, iv[:], ciphertext, aad)
	recovered := string(decrypted)
	if plaintext != recovered {
		log.Fatalln("Plaintexts don't match.")
	}

	// *ecdh.PrivateKey currently doesn't have a manual destructor
	zeroize(aesKey[:])
}
