package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"log"
)

var PRESHARED_SECRET = [...]byte{0x50, 0x52, 0x45, 0x53, 0x48, 0x41, 0x52,
	0x45, 0x44, 0x5f, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54}

func main() {
	rng := rand.Reader

	rsaPrivateKey, _ := rsa.GenerateKey(rng, 2048)
	rsaPublicKey := rsaPrivateKey.PublicKey
	encodedRsaPublicKey, _ := x509.MarshalPKIXPublicKey(&rsaPublicKey)

	h := hmac.New(sha256.New, PRESHARED_SECRET[:])
	h.Write(encodedRsaPublicKey)
	// mac := h.Sum(nil)

	var decodedRsaPublicKey *rsa.PublicKey
	pub, _ := x509.ParsePKIXPublicKey(encodedRsaPublicKey)
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		decodedRsaPublicKey = pub
	default:
		log.Fatalln("Error parsing encodedRsaPublicKey")
	}
	var masterSecret [128]byte
	rng.Read(masterSecret[:])
	encryptedMS, _ := rsa.EncryptOAEP(sha256.New(), rng, decodedRsaPublicKey, masterSecret[:], nil)

	decryptedMS, _ := rsa.DecryptOAEP(sha256.New(), rng, rsaPrivateKey, encryptedMS, nil)
	if !bytes.Equal(masterSecret[:], decryptedMS) {
		log.Fatalln("Master secrets don't match.")
	}
	aesKey := sha256.Sum256(decryptedMS)

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
}
