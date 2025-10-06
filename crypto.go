package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/twofish"
)

// CryptoTools provides encryption and decryption utilities
type CryptoTools struct{}

// AESEncrypt encrypts plaintext using AES-256-GCM
func (c *CryptoTools) AESEncrypt(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// AESDecrypt decrypts ciphertext using AES-256-GCM
func (c *CryptoTools) AESDecrypt(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DESEncrypt encrypts plaintext using DES
func (c *CryptoTools) DESEncrypt(plaintext, key []byte) (string, error) {
	if len(key) != 8 {
		return "", errors.New("key must be 8 bytes for DES")
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad plaintext to block size
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := append(plaintext, make([]byte, padding)...)

	ciphertext := make([]byte, len(padtext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	result := append(iv, ciphertext...)
	return hex.EncodeToString(result), nil
}

// DESDecrypt decrypts ciphertext using DES
func (c *CryptoTools) DESDecrypt(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 8 {
		return nil, errors.New("key must be 8 bytes for DES")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// RSAGenerateKeyPair generates RSA public/private key pair
func (c *CryptoTools) RSAGenerateKeyPair(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// RSAEncrypt encrypts data using RSA public key
func (c *CryptoTools) RSAEncrypt(plaintext []byte, publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not an RSA public key")
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

// RSADecrypt decrypts data using RSA private key
func (c *CryptoTools) RSADecrypt(ciphertextHex, privateKeyPEM string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// BlowfishEncrypt encrypts plaintext using Blowfish
func (c *CryptoTools) BlowfishEncrypt(plaintext, key []byte) (string, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad plaintext to block size
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := append(plaintext, make([]byte, padding)...)

	ciphertext := make([]byte, len(padtext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	result := append(iv, ciphertext...)
	return hex.EncodeToString(result), nil
}

// TwofishEncrypt encrypts plaintext using Twofish
func (c *CryptoTools) TwofishEncrypt(plaintext, key []byte) (string, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad plaintext to block size
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := append(plaintext, make([]byte, padding)...)

	ciphertext := make([]byte, len(padtext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	result := append(iv, ciphertext...)
	return hex.EncodeToString(result), nil
}

// ChaCha20Poly1305Encrypt encrypts plaintext using ChaCha20-Poly1305
func (c *CryptoTools) ChaCha20Poly1305Encrypt(plaintext, key []byte) (string, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// ChaCha20Poly1305Decrypt decrypts ciphertext using ChaCha20-Poly1305
func (c *CryptoTools) ChaCha20Poly1305Decrypt(ciphertextHex string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateRandomKey generates a random cryptographic key
func (c *CryptoTools) GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DisplayCryptoTools shows available cryptography tools
func DisplayCryptoTools() {
	fmt.Println("\n=== Cryptography Tools ===")
	fmt.Println("1. AES-256-GCM Encryption/Decryption")
	fmt.Println("2. DES Encryption/Decryption")
	fmt.Println("3. RSA Key Generation")
	fmt.Println("4. RSA Encryption/Decryption")
	fmt.Println("5. Blowfish Encryption")
	fmt.Println("6. Twofish Encryption")
	fmt.Println("7. ChaCha20-Poly1305 Encryption/Decryption")
	fmt.Println("8. Random Key Generation")
}

// AESEncryptCBC encrypts plaintext using AES-256-CBC
func (c *CryptoTools) AESEncryptCBC(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad plaintext to block size
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := append(plaintext, make([]byte, padding)...)

	ciphertext := make([]byte, len(padtext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	result := append(iv, ciphertext...)
	return hex.EncodeToString(result), nil
}

// AESDecryptCBC decrypts ciphertext using AES-256-CBC
func (c *CryptoTools) AESDecryptCBC(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// AESEncryptCFB encrypts plaintext using AES-256-CFB
func (c *CryptoTools) AESEncryptCFB(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

// AESDecryptCFB decrypts ciphertext using AES-256-CFB
func (c *CryptoTools) AESDecryptCFB(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// AESEncryptCTR encrypts plaintext using AES-256-CTR
func (c *CryptoTools) AESEncryptCTR(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

// AESDecryptCTR decrypts ciphertext using AES-256-CTR
func (c *CryptoTools) AESDecryptCTR(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// TripleDESEncrypt encrypts plaintext using 3DES
func (c *CryptoTools) TripleDESEncrypt(plaintext, key []byte) (string, error) {
	if len(key) != 24 {
		return "", errors.New("key must be 24 bytes for 3DES")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := append(plaintext, make([]byte, padding)...)

	ciphertext := make([]byte, len(padtext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	result := append(iv, ciphertext...)
	return hex.EncodeToString(result), nil
}

// TripleDESDecrypt decrypts ciphertext using 3DES
func (c *CryptoTools) TripleDESDecrypt(ciphertextHex string, key []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, errors.New("key must be 24 bytes for 3DES")
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// GenerateRSAKeyPairWithSize generates RSA key pair with custom size
func (c *CryptoTools) GenerateRSAKeyPairWithSize(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, errors.New("key size must be at least 2048 bits")
	}
	
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	
	return privateKey, nil
}

// RSAEncryptOAEP encrypts data using RSA-OAEP
func (c *CryptoTools) RSAEncryptOAEP(plaintext []byte, publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not an RSA public key")
	}

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		nil,
	)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

// RSADecryptOAEP decrypts data using RSA-OAEP
func (c *CryptoTools) RSADecryptOAEP(ciphertextHex, privateKeyPEM string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateKeyPair generates a generic key pair
func (c *CryptoTools) GenerateKeyPair(keyType string, size int) (string, string, error) {
	switch keyType {
	case "rsa":
		return c.RSAGenerateKeyPair(size)
	default:
		return "", "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// EncryptWithPadding encrypts with PKCS7 padding
func (c *CryptoTools) EncryptWithPadding(plaintext, key []byte, algorithm string) (string, error) {
	switch algorithm {
	case "aes":
		return c.AESEncrypt(plaintext, key)
	case "des":
		if len(key) != 8 {
			return "", errors.New("DES requires 8-byte key")
		}
		return c.DESEncrypt(plaintext, key)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// DecryptWithPadding decrypts with PKCS7 padding
func (c *CryptoTools) DecryptWithPadding(ciphertextHex string, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "aes":
		return c.AESDecrypt(ciphertextHex, key)
	case "des":
		if len(key) != 8 {
			return nil, errors.New("DES requires 8-byte key")
		}
		return c.DESDecrypt(ciphertextHex, key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
