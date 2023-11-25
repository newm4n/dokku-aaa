package tools

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	p, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pkey, ok := p.(*rsa.PublicKey); ok {
		return pkey, nil
	}
	return nil, fmt.Errorf("not rsa.PublicKey")
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha256.New()
	// return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	return rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
}

// SignWithPrivateKeyPSS will sign the data using RSA-PSS padding mechanism
func SignWithPrivateKeyPSS(msg []byte, priv *rsa.PrivateKey) (signature []byte, err error) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, msgHashSum, nil)
	//signature, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, msg, nil)
	//rsa.si
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifyWithPublicKeyPSS will verify a signature that was previously signed using RSA-PSS padding
func VerifyWithPublicKeyPSS(signature, msg []byte, pub *rsa.PublicKey) (verified bool, err error) {
	// Before verifying, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		return false, err
	}
	msgHashSum := msgHash.Sum(nil)

	err = rsa.VerifyPSS(pub, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false, nil
	}

	return true, nil
}

// SignWithPrivateKeyPKCS1 will sign the data using RSA-PKCS1 padding mechanism
func SignWithPrivateKeyPKCS1(msg []byte, priv *rsa.PrivateKey) (signature []byte, err error) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, msgHashSum)
	//signature, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, msg, nil)
	//rsa.si
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifyWithPublicKeyPKCS1 will verify a signature that was previously signed using RSA-PKCS1 padding
func VerifyWithPublicKeyPKCS1(signature, msg []byte, pub *rsa.PublicKey) (verified bool, err error) {
	// Before verifying, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		return false, err
	}
	msgHashSum := msgHash.Sum(nil)

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, msgHashSum, signature)

	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false, nil
	}

	return true, nil
}
