package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileTools provides file security utilities
type FileTools struct{}

// EncryptFile encrypts a file using AES-256-GCM
func (f *FileTools) EncryptFile(inputPath, outputPath string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(outputPath, ciphertext, 0644)
}

// DecryptFile decrypts a file encrypted with AES-256-GCM
func (f *FileTools) DecryptFile(inputPath, outputPath string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, plaintext, 0644)
}

// SecureDelete securely deletes a file by overwriting it
func (f *FileTools) SecureDelete(filepath string) error {
	file, err := os.OpenFile(filepath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()
	
	// Overwrite with random data multiple times
	for i := 0; i < 3; i++ {
		_, err = file.Seek(0, 0)
		if err != nil {
			return err
		}

		randomData := make([]byte, fileSize)
		_, err = rand.Read(randomData)
		if err != nil {
			return err
		}

		_, err = file.Write(randomData)
		if err != nil {
			return err
		}

		err = file.Sync()
		if err != nil {
			return err
		}
	}

	file.Close()
	return os.Remove(filepath)
}

// CalculateFileEntropy calculates the entropy of a file
func (f *FileTools) CalculateFileEntropy(filepath string) (float64, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return 0, err
	}

	if len(data) == 0 {
		return 0, nil
	}

	frequency := make(map[byte]int)
	for _, b := range data {
		frequency[b]++
	}

	var entropy float64
	length := float64(len(data))
	
	for _, count := range frequency {
		if count > 0 {
			probability := float64(count) / length
			entropy -= probability * (float64(log2(probability)))
		}
	}

	return entropy, nil
}

// Helper function for log base 2
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Simple log2 approximation
	result := 0.0
	temp := x
	for temp > 1 {
		temp /= 2
		result++
	}
	return result
}

// ScanDirectory scans a directory for files and returns file information
func (f *FileTools) ScanDirectory(dirPath string, recursive bool) ([]map[string]interface{}, error) {
	var files []map[string]interface{}

	if recursive {
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fileInfo := make(map[string]interface{})
				fileInfo["path"] = path
				fileInfo["size"] = info.Size()
				fileInfo["mode"] = info.Mode().String()
				fileInfo["modTime"] = info.ModTime().Format("2006-01-02 15:04:05")
				files = append(files, fileInfo)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				fileInfo := make(map[string]interface{})
				fileInfo["path"] = filepath.Join(dirPath, entry.Name())
				fileInfo["size"] = info.Size()
				fileInfo["mode"] = info.Mode().String()
				fileInfo["modTime"] = info.ModTime().Format("2006-01-02 15:04:05")
				files = append(files, fileInfo)
			}
		}
	}

	return files, nil
}

// GenerateFileKey generates a random key for file encryption
func (f *FileTools) GenerateFileKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// CheckFilePermissions checks file permissions and ownership
func (f *FileTools) CheckFilePermissions(filepath string) (map[string]interface{}, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	result["path"] = filepath
	result["mode"] = info.Mode().String()
	result["isDirectory"] = info.IsDir()
	result["size"] = info.Size()
	result["modTime"] = info.ModTime().Format("2006-01-02 15:04:05")

	return result, nil
}

// DisplayFileTools shows available file security tools
func DisplayFileTools() {
	fmt.Println("\n=== File Security Tools ===")
	fmt.Println("1. Encrypt File")
	fmt.Println("2. Decrypt File")
	fmt.Println("3. Secure File Delete")
	fmt.Println("4. File Integrity Check")
}

// EncryptFileWithMetadata encrypts file with metadata
func (f *FileTools) EncryptFileWithMetadata(inputPath, outputPath string, key []byte, metadata map[string]string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Add metadata
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Combine metadata and file data
	combined := append(metadataJSON, []byte("||")...)
	combined = append(combined, plaintext...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, combined, nil)
	return os.WriteFile(outputPath, ciphertext, 0644)
}

// DecryptFileWithMetadata decrypts file and extracts metadata
func (f *FileTools) DecryptFileWithMetadata(inputPath string, key []byte) ([]byte, map[string]string, error) {
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	combined, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	// Split metadata and data
	parts := strings.SplitN(string(combined), "||", 2)
	if len(parts) != 2 {
		return combined, nil, nil
	}

	var metadata map[string]string
	err = json.Unmarshal([]byte(parts[0]), &metadata)
	if err != nil {
		return combined, nil, nil
	}

	return []byte(parts[1]), metadata, nil
}

// SecureWipe performs multiple-pass secure file deletion
func (f *FileTools) SecureWipe(filepath string, passes int) error {
	file, err := os.OpenFile(filepath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()

	patterns := []byte{0x00, 0xFF, 0xAA, 0x55}

	for pass := 0; pass < passes; pass++ {
		_, err = file.Seek(0, 0)
		if err != nil {
			return err
		}

		pattern := patterns[pass%len(patterns)]
		data := make([]byte, fileSize)
		for i := range data {
			data[i] = pattern
		}

		_, err = file.Write(data)
		if err != nil {
			return err
		}

		err = file.Sync()
		if err != nil {
			return err
		}
	}

	file.Close()
	return os.Remove(filepath)
}

// CompareFiles compares two files
func (f *FileTools) CompareFiles(file1, file2 string) (bool, error) {
	data1, err := os.ReadFile(file1)
	if err != nil {
		return false, err
	}

	data2, err := os.ReadFile(file2)
	if err != nil {
		return false, err
	}

	if len(data1) != len(data2) {
		return false, nil
	}

	for i := range data1 {
		if data1[i] != data2[i] {
			return false, nil
		}
	}

	return true, nil
}

// CreateFileChecksum creates checksum file
func (f *FileTools) CreateFileChecksum(filepath string) (map[string]string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	checksums := make(map[string]string)

	// MD5
	md5Hash := md5.Sum(data)
	checksums["md5"] = hex.EncodeToString(md5Hash[:])

	// SHA256
	sha256Hash := sha256.Sum256(data)
	checksums["sha256"] = hex.EncodeToString(sha256Hash[:])

	// SHA512
	sha512Hash := sha512.Sum512(data)
	checksums["sha512"] = hex.EncodeToString(sha512Hash[:])

	return checksums, nil
}

// VerifyFileIntegrity verifies file integrity using checksum
func (f *FileTools) VerifyFileIntegrity(filepath string, expectedChecksum, algorithm string) (bool, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return false, err
	}

	var actualChecksum string
	switch algorithm {
	case "md5":
		hash := md5.Sum(data)
		actualChecksum = hex.EncodeToString(hash[:])
	case "sha256":
		hash := sha256.Sum256(data)
		actualChecksum = hex.EncodeToString(hash[:])
	case "sha512":
		hash := sha512.Sum512(data)
		actualChecksum = hex.EncodeToString(hash[:])
	default:
		return false, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return actualChecksum == expectedChecksum, nil
}

// SplitFile splits large file into chunks
func (f *FileTools) SplitFile(filepath string, chunkSize int64) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	_, err = file.Stat()
	if err != nil {
		return nil, err
	}

	var chunks []string
	buffer := make([]byte, chunkSize)
	chunkNum := 0

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}

		if n == 0 {
			break
		}

		chunkFilename := fmt.Sprintf("%s.part%d", filepath, chunkNum)
		err = os.WriteFile(chunkFilename, buffer[:n], 0644)
		if err != nil {
			return nil, err
		}

		chunks = append(chunks, chunkFilename)
		chunkNum++
	}

	return chunks, nil
}

// MergeFiles merges file chunks back together
func (f *FileTools) MergeFiles(outputPath string, chunks []string) error {
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	for _, chunk := range chunks {
		data, err := os.ReadFile(chunk)
		if err != nil {
			return err
		}

		_, err = output.Write(data)
		if err != nil {
			return err
		}
	}

	return nil
}

// BackupFile creates a backup of a file
func (f *FileTools) BackupFile(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	backupPath := fmt.Sprintf("%s.backup.%s", filepath, time.Now().Format("20060102-150405"))
	err = os.WriteFile(backupPath, data, 0644)
	if err != nil {
		return "", err
	}

	return backupPath, nil
}

// RestoreFile restores a file from backup
func (f *FileTools) RestoreFile(backupPath, originalPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}

	return os.WriteFile(originalPath, data, 0644)
}

// CalculateFileHash calculates hash for large files in chunks
func (f *FileTools) CalculateFileHash(filepath string, algorithm string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hasher hash.Hash
	switch algorithm {
	case "md5":
		hasher = md5.New()
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	buffer := make([]byte, 8192)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return "", err
		}

		if n == 0 {
			break
		}

		hasher.Write(buffer[:n])
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CreateFileSignature creates digital signature for file
func (f *FileTools) CreateFileSignature(filepath string, key []byte) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFileSignature verifies file digital signature
func (f *FileTools) VerifyFileSignature(filepath string, key []byte, expectedSignature string) (bool, error) {
	actualSignature, err := f.CreateFileSignature(filepath, key)
	if err != nil {
		return false, err
	}

	return hmac.Equal([]byte(actualSignature), []byte(expectedSignature)), nil
}
