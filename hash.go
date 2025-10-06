package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// HashTools provides hashing and checksum utilities
type HashTools struct{}

// MD5Hash calculates MD5 hash of data
func (h *HashTools) MD5Hash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// SHA1Hash calculates SHA-1 hash of data
func (h *HashTools) SHA1Hash(data []byte) string {
	hash := sha1.Sum(data)
	return hex.EncodeToString(hash[:])
}

// SHA256Hash calculates SHA-256 hash of data
func (h *HashTools) SHA256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SHA512Hash calculates SHA-512 hash of data
func (h *HashTools) SHA512Hash(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// SHA3Hash calculates SHA3-256 hash of data
func (h *HashTools) SHA3Hash(data []byte) string {
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Blake2bHash calculates BLAKE2b-256 hash of data
func (h *HashTools) Blake2bHash(data []byte) (string, error) {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return "", err
	}
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Blake2sHash calculates BLAKE2s-256 hash of data
func (h *HashTools) Blake2sHash(data []byte) (string, error) {
	hash, err := blake2s.New256(nil)
	if err != nil {
		return "", err
	}
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CRC32Checksum calculates CRC32 checksum of data
func (h *HashTools) CRC32Checksum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// FileHash calculates hash of a file
func (h *HashTools) FileHash(filepath, algorithm string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var result []byte

	switch algorithm {
	case "md5":
		hasher := md5.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		result = hasher.Sum(nil)
	case "sha1":
		hasher := sha1.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		result = hasher.Sum(nil)
	case "sha256":
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		result = hasher.Sum(nil)
	case "sha512":
		hasher := sha512.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		result = hasher.Sum(nil)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return hex.EncodeToString(result), nil
}

// VerifyChecksum verifies if data matches expected hash
func (h *HashTools) VerifyChecksum(data []byte, expected, algorithm string) bool {
	var actual string
	
	switch algorithm {
	case "md5":
		actual = h.MD5Hash(data)
	case "sha1":
		actual = h.SHA1Hash(data)
	case "sha256":
		actual = h.SHA256Hash(data)
	case "sha512":
		actual = h.SHA512Hash(data)
	case "sha3":
		actual = h.SHA3Hash(data)
	default:
		return false
	}
	
	return actual == expected
}

// HMACHash calculates HMAC hash with SHA256
func (h *HashTools) HMACHash(data, key []byte) string {
	// Simplified HMAC implementation
	blockSize := 64
	if len(key) > blockSize {
		hash := sha256.Sum256(key)
		key = hash[:]
	}
	if len(key) < blockSize {
		padded := make([]byte, blockSize)
		copy(padded, key)
		key = padded
	}

	opad := make([]byte, blockSize)
	ipad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		opad[i] = key[i] ^ 0x5c
		ipad[i] = key[i] ^ 0x36
	}

	innerHash := sha256.New()
	innerHash.Write(ipad)
	innerHash.Write(data)
	innerResult := innerHash.Sum(nil)

	outerHash := sha256.New()
	outerHash.Write(opad)
	outerHash.Write(innerResult)
	
	return hex.EncodeToString(outerHash.Sum(nil))
}

// MultiHash calculates multiple hashes at once
func (h *HashTools) MultiHash(data []byte) map[string]string {
	hashes := make(map[string]string)
	
	hashes["md5"] = h.MD5Hash(data)
	hashes["sha1"] = h.SHA1Hash(data)
	hashes["sha256"] = h.SHA256Hash(data)
	hashes["sha512"] = h.SHA512Hash(data)
	hashes["sha3"] = h.SHA3Hash(data)
	
	blake2b, _ := h.Blake2bHash(data)
	hashes["blake2b"] = blake2b
	
	blake2s, _ := h.Blake2sHash(data)
	hashes["blake2s"] = blake2s
	
	return hashes
}

// DisplayHashTools shows available hash and checksum tools
func DisplayHashTools() {
	fmt.Println("\n=== Hash & Checksum Tools ===")
	fmt.Println("1. MD5 Hash")
	fmt.Println("2. SHA-256 Hash")
	fmt.Println("3. SHA-512 Hash")
	fmt.Println("4. File Checksum Verification")
	fmt.Println("5. Multiple Hash Calculator")
}

// SHA224Hash calculates SHA-224 hash of data
func (h *HashTools) SHA224Hash(data []byte) string {
	hash := sha256.Sum224(data)
	return hex.EncodeToString(hash[:])
}

// SHA384Hash calculates SHA-384 hash of data
func (h *HashTools) SHA384Hash(data []byte) string {
	hash := sha512.Sum384(data)
	return hex.EncodeToString(hash[:])
}

// SHA3_224Hash calculates SHA3-224 hash of data
func (h *HashTools) SHA3_224Hash(data []byte) string {
	hash := sha3.Sum224(data)
	return hex.EncodeToString(hash[:])
}

// SHA3_384Hash calculates SHA3-384 hash of data
func (h *HashTools) SHA3_384Hash(data []byte) string {
	hash := sha3.Sum384(data)
	return hex.EncodeToString(hash[:])
}

// SHA3_512Hash calculates SHA3-512 hash of data
func (h *HashTools) SHA3_512Hash(data []byte) string {
	hash := sha3.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// Blake2b512Hash calculates BLAKE2b-512 hash of data
func (h *HashTools) Blake2b512Hash(data []byte) (string, error) {
	hash, err := blake2b.New512(nil)
	if err != nil {
		return "", err
	}
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CalculateHashWithSalt calculates hash with salt
func (h *HashTools) CalculateHashWithSalt(data, salt []byte, algorithm string) (string, error) {
	combined := append(data, salt...)
	
	switch algorithm {
	case "sha256":
		return h.SHA256Hash(combined), nil
	case "sha512":
		return h.SHA512Hash(combined), nil
	case "sha3":
		return h.SHA3Hash(combined), nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// CompareHashes compares two hashes in constant time
func (h *HashTools) CompareHashes(hash1, hash2 string) bool {
	b1, err1 := hex.DecodeString(hash1)
	b2, err2 := hex.DecodeString(hash2)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	if len(b1) != len(b2) {
		return false
	}
	
	result := 0
	for i := 0; i < len(b1); i++ {
		result |= int(b1[i]) ^ int(b2[i])
	}
	
	return result == 0
}

// CalculateStreamHash calculates hash for large data streams
func (h *HashTools) CalculateStreamHash(data []byte, chunkSize int, algorithm string) (string, error) {
	var hasher interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
	
	switch algorithm {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		hasher.Write(data[i:end])
	}
	
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// GenerateFingerprintHash generates a fingerprint-style hash
func (h *HashTools) GenerateFingerprintHash(data []byte, algorithm string) (string, error) {
	var hashBytes []byte
	
	switch algorithm {
	case "md5":
		hash := md5.Sum(data)
		hashBytes = hash[:]
	case "sha1":
		hash := sha1.Sum(data)
		hashBytes = hash[:]
	case "sha256":
		hash := sha256.Sum256(data)
		hashBytes = hash[:]
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	
	// Format as fingerprint XX:XX:XX...
	var parts []string
	for i := 0; i < len(hashBytes); i += 2 {
		if i+1 < len(hashBytes) {
			parts = append(parts, fmt.Sprintf("%02x%02x", hashBytes[i], hashBytes[i+1]))
		} else {
			parts = append(parts, fmt.Sprintf("%02x", hashBytes[i]))
		}
	}
	
	return strings.Join(parts, ":"), nil
}

// CalculateMerkleRoot calculates Merkle tree root hash
func (h *HashTools) CalculateMerkleRoot(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return "", fmt.Errorf("no hashes provided")
	}
	
	if len(hashes) == 1 {
		return hashes[0], nil
	}
	
	var currentLevel []string = hashes
	
	for len(currentLevel) > 1 {
		var nextLevel []string
		
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := currentLevel[i] + currentLevel[i+1]
				hash := h.SHA256Hash([]byte(combined))
				nextLevel = append(nextLevel, hash)
			} else {
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		
		currentLevel = nextLevel
	}
	
	return currentLevel[0], nil
}

// GenerateHashChain generates a chain of hashes
func (h *HashTools) GenerateHashChain(seed []byte, length int, algorithm string) ([]string, error) {
	chain := make([]string, length)
	current := seed
	
	for i := 0; i < length; i++ {
		var hash string
		switch algorithm {
		case "sha256":
			hash = h.SHA256Hash(current)
		case "sha512":
			hash = h.SHA512Hash(current)
		default:
			return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
		}
		
		chain[i] = hash
		current = []byte(hash)
	}
	
	return chain, nil
}

// VerifyHashChain verifies a hash chain
func (h *HashTools) VerifyHashChain(chain []string, algorithm string) bool {
	if len(chain) < 2 {
		return true
	}
	
	for i := 1; i < len(chain); i++ {
		var expectedHash string
		switch algorithm {
		case "sha256":
			expectedHash = h.SHA256Hash([]byte(chain[i-1]))
		case "sha512":
			expectedHash = h.SHA512Hash([]byte(chain[i-1]))
		default:
			return false
		}
		
		if expectedHash != chain[i] {
			return false
		}
	}
	
	return true
}

// CalculateDirectoryHash calculates hash for directory contents
func (h *HashTools) CalculateDirectoryHash(dirPath string) (string, error) {
	var allHashes []string
	
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", err
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			filepath := filepath.Join(dirPath, entry.Name())
			hash, err := h.FileHash(filepath, "sha256")
			if err != nil {
				continue
			}
			allHashes = append(allHashes, hash)
		}
	}
	
	// Combine all hashes and hash the result
	combined := strings.Join(allHashes, "")
	return h.SHA256Hash([]byte(combined)), nil
}

// CalculatePasswordHash calculates specialized password hash
func (h *HashTools) CalculatePasswordHash(password, salt string, iterations int) string {
	hash := []byte(password + salt)
	
	for i := 0; i < iterations; i++ {
		h := sha256.Sum256(hash)
		hash = h[:]
	}
	
	return hex.EncodeToString(hash)
}

// ValidateHashFormat validates hash format
func (h *HashTools) ValidateHashFormat(hash, algorithm string) bool {
	var expectedLength int
	
	switch algorithm {
	case "md5":
		expectedLength = 32
	case "sha1":
		expectedLength = 40
	case "sha256":
		expectedLength = 64
	case "sha512":
		expectedLength = 128
	default:
		return false
	}
	
	if len(hash) != expectedLength {
		return false
	}
	
	// Check if all characters are hex
	for _, char := range hash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	
	return true
}

// GenerateHashSignature generates a signature hash
func (h *HashTools) GenerateHashSignature(data []byte, key []byte) string {
	combined := append(data, key...)
	return h.SHA256Hash(combined)
}

// VerifyHashSignature verifies a signature hash
func (h *HashTools) VerifyHashSignature(data []byte, key []byte, signature string) bool {
	expected := h.GenerateHashSignature(data, key)
	return h.CompareHashes(expected, signature)
}
