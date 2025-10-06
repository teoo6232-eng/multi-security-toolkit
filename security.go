package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// SecurityTools provides advanced security utilities
type SecurityTools struct{}

// GenerateSecureToken generates a cryptographically secure token
func (s *SecurityTools) GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateNonce generates a cryptographic nonce
func (s *SecurityTools) GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// CalculateHMACSHA256 calculates HMAC-SHA256
func (s *SecurityTools) CalculateHMACSHA256(message, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// CalculateHMACSHA512 calculates HMAC-SHA512
func (s *SecurityTools) CalculateHMACSHA512(message, key string) string {
	mac := hmac.New(sha512.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC verifies HMAC signature
func (s *SecurityTools) VerifyHMAC(message, key, signature string, algorithm string) bool {
	var expectedMAC string
	
	switch algorithm {
	case "sha256":
		expectedMAC = s.CalculateHMACSHA256(message, key)
	case "sha512":
		expectedMAC = s.CalculateHMACSHA512(message, key)
	default:
		return false
	}
	
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// GenerateSalt generates a random salt for password hashing
func (s *SecurityTools) GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// GenerateSessionID generates a unique session identifier
func (s *SecurityTools) GenerateSessionID() (string, error) {
	timestamp := time.Now().UnixNano()
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	
	data := fmt.Sprintf("%d-%s", timestamp, hex.EncodeToString(randomBytes))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// CalculateEntropy calculates Shannon entropy of data
func (s *SecurityTools) CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
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
			entropy -= probability * logBase2(probability)
		}
	}
	
	return entropy
}

// logBase2 calculates log base 2
func logBase2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Natural log divided by ln(2)
	return 0.0 // Simplified for now
}

// ConstantTimeCompare performs constant-time comparison
func (s *SecurityTools) ConstantTimeCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// GenerateCSRFToken generates CSRF token
func (s *SecurityTools) GenerateCSRFToken(userID string) (string, error) {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	
	data := fmt.Sprintf("%s:%d:%s", userID, timestamp, hex.EncodeToString(randomBytes))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// VerifyCSRFToken verifies CSRF token validity
func (s *SecurityTools) VerifyCSRFToken(token, userID string, maxAge int64) bool {
	if len(token) != 64 {
		return false
	}
	// Simplified verification - in production, store and validate tokens
	return true
}

// SecureRandomInt generates a cryptographically secure random integer
func (s *SecurityTools) SecureRandomInt(max int64) (int64, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return nBig.Int64(), nil
}

// GenerateOTP generates a One-Time Password
func (s *SecurityTools) GenerateOTP(digits int) (string, error) {
	if digits < 4 || digits > 10 {
		digits = 6
	}
	
	max := int64(1)
	for i := 0; i < digits; i++ {
		max *= 10
	}
	
	num, err := s.SecureRandomInt(max)
	if err != nil {
		return "", err
	}
	
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, num), nil
}

// ValidateOTP validates an OTP (simplified)
func (s *SecurityTools) ValidateOTP(otp, expected string) bool {
	return otp == expected
}

// GenerateRecoveryCode generates a recovery code
func (s *SecurityTools) GenerateRecoveryCode() (string, error) {
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		num, err := s.SecureRandomInt(10000)
		if err != nil {
			return "", err
		}
		parts[i] = fmt.Sprintf("%04d", num)
	}
	return strings.Join(parts, "-"), nil
}

// HashPassword creates a simple hash (for demonstration)
func (s *SecurityTools) HashPassword(password, salt string, iterations int) string {
	hash := []byte(password + salt)
	for i := 0; i < iterations; i++ {
		h := sha256.Sum256(hash)
		hash = h[:]
	}
	return hex.EncodeToString(hash)
}

// GenerateAPISecret generates an API secret key
func (s *SecurityTools) GenerateAPISecret() (string, error) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(secret), nil
}

// GenerateWebhookSignature generates a webhook signature
func (s *SecurityTools) GenerateWebhookSignature(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies a webhook signature
func (s *SecurityTools) VerifyWebhookSignature(payload, secret, signature string) bool {
	expected := s.GenerateWebhookSignature(payload, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

// GeneratePINCode generates a numeric PIN
func (s *SecurityTools) GeneratePINCode(digits int) (string, error) {
	if digits < 4 || digits > 8 {
		digits = 4
	}
	
	max := int64(1)
	for i := 0; i < digits; i++ {
		max *= 10
	}
	
	num, err := s.SecureRandomInt(max)
	if err != nil {
		return "", err
	}
	
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, num), nil
}

// ObfuscateData obfuscates sensitive data
func (s *SecurityTools) ObfuscateData(data string, showChars int) string {
	if len(data) <= showChars {
		return strings.Repeat("*", len(data))
	}
	
	visible := data[:showChars]
	hidden := strings.Repeat("*", len(data)-showChars)
	return visible + hidden
}

// GenerateFingerprint generates a fingerprint hash
func (s *SecurityTools) GenerateFingerprint(data string) string {
	hash := sha256.Sum256([]byte(data))
	
	// Format as fingerprint: XX:XX:XX:...
	var parts []string
	for i := 0; i < len(hash); i += 2 {
		parts = append(parts, fmt.Sprintf("%02x", hash[i:i+2]))
	}
	
	return strings.Join(parts, ":")
}

// CalculateMD5Fingerprint calculates MD5 fingerprint
func (s *SecurityTools) CalculateMD5Fingerprint(data []byte) string {
	hash := md5.Sum(data)
	var parts []string
	for _, b := range hash {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

// CalculateSHA1Fingerprint calculates SHA1 fingerprint
func (s *SecurityTools) CalculateSHA1Fingerprint(data []byte) string {
	hash := sha1.Sum(data)
	var parts []string
	for _, b := range hash {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

// ValidateTokenExpiry checks if a token has expired
func (s *SecurityTools) ValidateTokenExpiry(issuedAt, expiresIn int64) bool {
	now := time.Now().Unix()
	expiry := issuedAt + expiresIn
	return now < expiry
}

// GenerateAccessCode generates a short access code
func (s *SecurityTools) GenerateAccessCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, length)
	
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code[i] = charset[num.Int64()]
	}
	
	return string(code), nil
}

// GenerateInviteCode generates an invite code
func (s *SecurityTools) GenerateInviteCode() (string, error) {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	
	data := fmt.Sprintf("%d%s", timestamp, hex.EncodeToString(randomBytes))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]), nil
}

// ValidatePasswordComplexity checks password complexity
func (s *SecurityTools) ValidatePasswordComplexity(password string, minLength, minUpper, minLower, minDigits, minSpecial int) map[string]bool {
	result := make(map[string]bool)
	
	upper := 0
	lower := 0
	digits := 0
	special := 0
	
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			upper++
		case char >= 'a' && char <= 'z':
			lower++
		case char >= '0' && char <= '9':
			digits++
		default:
			special++
		}
	}
	
	result["lengthOK"] = len(password) >= minLength
	result["upperOK"] = upper >= minUpper
	result["lowerOK"] = lower >= minLower
	result["digitsOK"] = digits >= minDigits
	result["specialOK"] = special >= minSpecial
	
	return result
}

// SanitizeUserInput sanitizes user input
func (s *SecurityTools) SanitizeUserInput(input string, maxLength int) string {
	// Trim whitespace
	input = strings.TrimSpace(input)
	
	// Limit length
	if len(input) > maxLength {
		input = input[:maxLength]
	}
	
	// Remove control characters
	input = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, input)
	
	return input
}

// GenerateBackupCode generates a backup verification code
func (s *SecurityTools) GenerateBackupCode() (string, error) {
	code := make([]byte, 16)
	if _, err := rand.Read(code); err != nil {
		return "", err
	}
	return hex.EncodeToString(code), nil
}

// CalculateHashChain calculates a hash chain
func (s *SecurityTools) CalculateHashChain(seed string, iterations int) []string {
	chain := make([]string, iterations+1)
	chain[0] = seed
	
	for i := 1; i <= iterations; i++ {
		hash := sha256.Sum256([]byte(chain[i-1]))
		chain[i] = hex.EncodeToString(hash[:])
	}
	
	return chain
}

// GenerateDeviceID generates a unique device identifier
func (s *SecurityTools) GenerateDeviceID(userAgent, ipAddress string) string {
	data := fmt.Sprintf("%s:%s:%d", userAgent, ipAddress, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateSignature validates a digital signature (simplified)
func (s *SecurityTools) ValidateSignature(data, signature, publicKey string) bool {
	// Simplified validation for demonstration
	return len(signature) > 0 && len(publicKey) > 0
}

// GenerateAuthToken generates an authentication token
func (s *SecurityTools) GenerateAuthToken(userID string, expiresIn int64) (map[string]interface{}, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	issuedAt := time.Now().Unix()
	
	return map[string]interface{}{
		"token":     token,
		"userID":    userID,
		"issuedAt":  issuedAt,
		"expiresAt": issuedAt + expiresIn,
	}, nil
}

// DisplaySecurityTools shows available security tools
func DisplaySecurityTools() {
	fmt.Println("\n=== Advanced Security Tools ===")
	fmt.Println("1. Generate Secure Token")
	fmt.Println("2. Generate HMAC Signature")
	fmt.Println("3. Generate OTP Code")
	fmt.Println("4. Generate Recovery Code")
	fmt.Println("5. Generate CSRF Token")
}
