package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// PasswordTools provides password security utilities
type PasswordTools struct{}

// GeneratePassword generates a random secure password
func (p *PasswordTools) GeneratePassword(length int, includeUpper, includeLower, includeNumbers, includeSpecial bool) (string, error) {
	var charset string
	if includeUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if includeLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if includeNumbers {
		charset += "0123456789"
	}
	if includeSpecial {
		charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	if charset == "" {
		return "", fmt.Errorf("at least one character set must be selected")
	}

	password := make([]byte, length)
	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

// CheckPasswordStrength analyzes password strength
func (p *PasswordTools) CheckPasswordStrength(password string) map[string]interface{} {
	result := make(map[string]interface{})
	
	length := len(password)
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	score := 0
	if length >= 8 {
		score++
	}
	if length >= 12 {
		score++
	}
	if length >= 16 {
		score++
	}
	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasNumber {
		score++
	}
	if hasSpecial {
		score++
	}
	
	var strength string
	if score <= 3 {
		strength = "Weak"
	} else if score <= 5 {
		strength = "Medium"
	} else if score <= 6 {
		strength = "Strong"
	} else {
		strength = "Very Strong"
	}
	
	result["length"] = length
	result["hasUppercase"] = hasUpper
	result["hasLowercase"] = hasLower
	result["hasNumbers"] = hasNumber
	result["hasSpecialChars"] = hasSpecial
	result["score"] = score
	result["strength"] = strength
	
	return result
}

// HashPasswordBcrypt hashes a password using bcrypt
func (p *PasswordTools) HashPasswordBcrypt(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	
	return string(hash), nil
}

// VerifyPasswordBcrypt verifies a password against a bcrypt hash
func (p *PasswordTools) VerifyPasswordBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPasswordScrypt hashes a password using scrypt
func (p *PasswordTools) HashPasswordScrypt(password, salt string) (string, error) {
	if salt == "" {
		saltBytes := make([]byte, 16)
		_, err := rand.Read(saltBytes)
		if err != nil {
			return "", err
		}
		salt = fmt.Sprintf("%x", saltBytes)
	}
	
	hash, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%x:%s", hash, salt), nil
}

// CheckCommonPasswords checks if password is in common passwords list
func (p *PasswordTools) CheckCommonPasswords(password string) bool {
	commonPasswords := []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"monkey", "1234567", "letmein", "trustno1", "dragon",
		"baseball", "iloveyou", "master", "sunshine", "ashley",
		"bailey", "passw0rd", "shadow", "123123", "654321",
		"superman", "qazwsx", "michael", "football", "password1",
	}
	
	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return true
		}
	}
	
	return false
}

// GeneratePassphrase generates a random passphrase from word list
func (p *PasswordTools) GeneratePassphrase(wordCount int, separator string) string {
	words := []string{
		"correct", "horse", "battery", "staple", "dragon", "mountain",
		"river", "forest", "ocean", "desert", "valley", "canyon",
		"island", "plateau", "glacier", "volcano", "meadow", "prairie",
		"jungle", "savanna", "tundra", "marsh", "swamp", "reef",
		"eagle", "falcon", "hawk", "owl", "raven", "sparrow",
		"dolphin", "whale", "shark", "octopus", "starfish", "jellyfish",
		"lion", "tiger", "bear", "wolf", "fox", "deer",
		"sunset", "sunrise", "thunder", "lightning", "rainbow", "aurora",
	}
	
	var selectedWords []string
	for i := 0; i < wordCount; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		selectedWords = append(selectedWords, words[num.Int64()])
	}
	
	return strings.Join(selectedWords, separator)
}

// DisplayPasswordTools shows available password security tools
func DisplayPasswordTools() {
	fmt.Println("\n=== Password Security Tools ===")
	fmt.Println("1. Password Generator")
	fmt.Println("2. Password Strength Checker")
	fmt.Println("3. Bcrypt Password Hashing")
	fmt.Println("4. Scrypt Password Hashing")
	fmt.Println("5. Passphrase Generator")
}

// GeneratePasswordWithRules generates password with custom rules
func (p *PasswordTools) GeneratePasswordWithRules(rules map[string]int) (string, error) {
	length := rules["length"]
	if length < 8 {
		length = 8
	}
	
	upper := rules["upper"]
	lower := rules["lower"]
	numbers := rules["numbers"]
	special := rules["special"]
	
	var charset string
	var required []byte
	
	// Add required characters
	if upper > 0 {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		for i := 0; i < upper; i++ {
			num, _ := rand.Int(rand.Reader, big.NewInt(26))
			required = append(required, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[num.Int64()])
		}
	}
	
	if lower > 0 {
		charset += "abcdefghijklmnopqrstuvwxyz"
		for i := 0; i < lower; i++ {
			num, _ := rand.Int(rand.Reader, big.NewInt(26))
			required = append(required, "abcdefghijklmnopqrstuvwxyz"[num.Int64()])
		}
	}
	
	if numbers > 0 {
		charset += "0123456789"
		for i := 0; i < numbers; i++ {
			num, _ := rand.Int(rand.Reader, big.NewInt(10))
			required = append(required, "0123456789"[num.Int64()])
		}
	}
	
	if special > 0 {
		charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
		for i := 0; i < special; i++ {
			num, _ := rand.Int(rand.Reader, big.NewInt(25))
			required = append(required, "!@#$%^&*()_+-=[]{}|;:,.<>?"[num.Int64()])
		}
	}
	
	if charset == "" {
		return "", fmt.Errorf("no character sets selected")
	}
	
	// Fill remaining length
	remaining := length - len(required)
	password := make([]byte, remaining)
	for i := range password {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password[i] = charset[num.Int64()]
	}
	
	// Combine and shuffle
	password = append(password, required...)
	
	// Simple shuffle
	for i := len(password) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}
	
	return string(password), nil
}

// AnalyzePasswordPatterns analyzes common patterns in password
func (p *PasswordTools) AnalyzePasswordPatterns(password string) []string {
	var patterns []string
	
	// Check for sequential characters
	for i := 0; i < len(password)-2; i++ {
		if password[i]+1 == password[i+1] && password[i+1]+1 == password[i+2] {
			patterns = append(patterns, "Sequential characters detected")
			break
		}
	}
	
	// Check for repeated characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			patterns = append(patterns, "Repeated characters detected")
			break
		}
	}
	
	// Check for common patterns
	commonPatterns := []string{
		"123", "abc", "qwe", "asd", "zxc",
		"password", "admin", "user", "test",
	}
	
	lower := strings.ToLower(password)
	for _, pattern := range commonPatterns {
		if strings.Contains(lower, pattern) {
			patterns = append(patterns, fmt.Sprintf("Common pattern '%s' found", pattern))
		}
	}
	
	// Check for keyboard patterns
	keyboardPatterns := []string{"qwerty", "asdfgh", "zxcvbn"}
	for _, kp := range keyboardPatterns {
		if strings.Contains(lower, kp) {
			patterns = append(patterns, "Keyboard pattern detected")
			break
		}
	}
	
	return patterns
}

// EstimatePasswordCrackTime estimates time to crack password
func (p *PasswordTools) EstimatePasswordCrackTime(password string) string {
	strength := p.CheckPasswordStrength(password)
	score := strength["score"].(int)
	
	// Simplified estimation
	var estimate string
	switch {
	case score <= 2:
		estimate = "Seconds to minutes"
	case score <= 4:
		estimate = "Hours to days"
	case score <= 5:
		estimate = "Weeks to months"
	case score <= 6:
		estimate = "Years"
	default:
		estimate = "Centuries"
	}
	
	return estimate
}

// GenerateMemorablePassword generates a memorable password
func (p *PasswordTools) GenerateMemorablePassword() (string, error) {
	adjectives := []string{
		"Happy", "Bright", "Swift", "Brave", "Calm",
		"Clever", "Eager", "Gentle", "Noble", "Proud",
		"Quick", "Silent", "Strong", "Wise", "Bold",
	}
	
	nouns := []string{
		"Tiger", "Eagle", "Dragon", "Phoenix", "Wolf",
		"Lion", "Hawk", "Bear", "Falcon", "Panther",
		"Fox", "Shark", "Leopard", "Raven", "Cobra",
	}
	
	adjIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	numIdx, _ := rand.Int(rand.Reader, big.NewInt(9999))
	
	return fmt.Sprintf("%s%s%04d!", adjectives[adjIdx.Int64()], nouns[nounIdx.Int64()], numIdx.Int64()), nil
}

// PasswordStrengthScore calculates numerical password strength score
func (p *PasswordTools) PasswordStrengthScore(password string) int {
	score := 0
	
	// Length bonus
	score += len(password) * 4
	
	// Character variety
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	varietyCount := 0
	if hasUpper {
		varietyCount++
	}
	if hasLower {
		varietyCount++
	}
	if hasNumber {
		varietyCount++
	}
	if hasSpecial {
		varietyCount++
	}
	
	score += varietyCount * 10
	
	// Penalty for common patterns
	patterns := p.AnalyzePasswordPatterns(password)
	score -= len(patterns) * 10
	
	if score < 0 {
		score = 0
	}
	
	return score
}

// HashPasswordArgon2 hashes password using Argon2 (simplified)
func (p *PasswordTools) HashPasswordArgon2(password, salt string) (string, error) {
	// Simplified Argon2-like hashing using scrypt
	hash, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%s", hash, salt), nil
}

// ComparePasswords compares two passwords securely
func (p *PasswordTools) ComparePasswords(password1, password2 string) bool {
	// Constant-time comparison
	if len(password1) != len(password2) {
		return false
	}
	
	result := 0
	for i := 0; i < len(password1); i++ {
		result |= int(password1[i]) ^ int(password2[i])
	}
	
	return result == 0
}

// GeneratePronounceablePassword generates pronounceable password
func (p *PasswordTools) GeneratePronounceablePassword(length int) (string, error) {
	consonants := "bcdfghjklmnpqrstvwxyz"
	vowels := "aeiou"
	
	var password strings.Builder
	useConsonant := true
	
	for password.Len() < length {
		if useConsonant {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(consonants))))
			password.WriteByte(consonants[idx.Int64()])
		} else {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(vowels))))
			password.WriteByte(vowels[idx.Int64()])
		}
		useConsonant = !useConsonant
	}
	
	// Add number and special char
	numIdx, _ := rand.Int(rand.Reader, big.NewInt(10))
	password.WriteString(fmt.Sprintf("%d", numIdx.Int64()))
	
	specials := "!@#$"
	spIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(specials))))
	password.WriteByte(specials[spIdx.Int64()])
	
	return password.String(), nil
}

// PasswordHistoryCheck checks if password was used before
func (p *PasswordTools) PasswordHistoryCheck(newPassword string, history []string) bool {
	for _, oldPassword := range history {
		if newPassword == oldPassword {
			return true
		}
	}
	return false
}

// GeneratePasswordHash generates multiple hashes for password
func (p *PasswordTools) GeneratePasswordHash(password string) map[string]string {
	hashes := make(map[string]string)
	
	// Bcrypt
	bcryptHash, _ := p.HashPasswordBcrypt(password, 10)
	hashes["bcrypt"] = bcryptHash
	
	// Scrypt
	scryptHash, _ := p.HashPasswordScrypt(password, "")
	hashes["scrypt"] = scryptHash
	
	return hashes
}
