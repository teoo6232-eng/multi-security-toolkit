package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"
)

// UtilityTools provides general utility functions
type UtilityTools struct{}

// GenerateUUID generates a UUID v4
func (u *UtilityTools) GenerateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC4122
	
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// FormatJSON formats JSON string with indentation
func (u *UtilityTools) FormatJSON(jsonStr string) (string, error) {
	var data interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return "", err
	}

	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}

// ValidateJSON validates if a string is valid JSON
func (u *UtilityTools) ValidateJSON(jsonStr string) (bool, error) {
	var data interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return false, err
	}
	return true, nil
}

// TimestampConverter converts between different timestamp formats
func (u *UtilityTools) TimestampConverter(timestamp interface{}) map[string]string {
	result := make(map[string]string)

	var t time.Time
	switch v := timestamp.(type) {
	case int64:
		t = time.Unix(v, 0)
	case string:
		var err error
		t, err = time.Parse(time.RFC3339, v)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", v)
			if err != nil {
				result["error"] = "Unable to parse timestamp"
				return result
			}
		}
	default:
		result["error"] = "Unsupported timestamp type"
		return result
	}

	result["unix"] = fmt.Sprintf("%d", t.Unix())
	result["rfc3339"] = t.Format(time.RFC3339)
	result["iso8601"] = t.Format("2006-01-02T15:04:05Z07:00")
	result["human"] = t.Format("2006-01-02 15:04:05")
	result["utc"] = t.UTC().Format(time.RFC3339)

	return result
}

// GenerateRandomString generates a random alphanumeric string
func (u *UtilityTools) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// MaskSensitiveData masks sensitive information in a string
func (u *UtilityTools) MaskSensitiveData(data string) string {
	// Mask email addresses
	emailRegex := regexp.MustCompile(`([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)
	data = emailRegex.ReplaceAllStringFunc(data, func(email string) string {
		parts := strings.Split(email, "@")
		if len(parts[0]) > 2 {
			return parts[0][:2] + "***@" + parts[1]
		}
		return "***@" + parts[1]
	})

	// Mask phone numbers
	phoneRegex := regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
	data = phoneRegex.ReplaceAllString(data, "***-***-****")

	// Mask credit cards
	ccRegex := regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	data = ccRegex.ReplaceAllString(data, "****-****-****-****")

	// Mask SSN
	ssnRegex := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	data = ssnRegex.ReplaceAllString(data, "***-**-****")

	return data
}

// CompareStringsSecure performs constant-time string comparison
func (u *UtilityTools) CompareStringsSecure(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
}

// ExtractURLs extracts all URLs from text
func (u *UtilityTools) ExtractURLs(text string) []string {
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	return urlRegex.FindAllString(text, -1)
}

// ExtractIPAddresses extracts IP addresses from text
func (u *UtilityTools) ExtractIPAddresses(text string) []string {
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	return ipRegex.FindAllString(text, -1)
}

// SanitizeFilename sanitizes a filename for safe filesystem usage
func (u *UtilityTools) SanitizeFilename(filename string) string {
	// Remove path separators
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

	// Remove special characters
	unsafeChars := regexp.MustCompile(`[<>:"|?*]`)
	filename = unsafeChars.ReplaceAllString(filename, "_")

	// Remove control characters
	filename = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, filename)

	// Trim spaces and dots
	filename = strings.Trim(filename, " .")

	// Limit length
	if len(filename) > 255 {
		filename = filename[:255]
	}

	return filename
}

// CalculateChecksumString calculates a simple checksum for a string
func (u *UtilityTools) CalculateChecksumString(data string) uint32 {
	var checksum uint32
	for _, char := range data {
		checksum += uint32(char)
	}
	return checksum
}

// IsValidDomain checks if a string is a valid domain name
func (u *UtilityTools) IsValidDomain(domain string) bool {
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// GenerateSecureID generates a cryptographically secure random ID
func (u *UtilityTools) GenerateSecureID(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b), nil
}

// ParseUserAgent parses basic user agent information
func (u *UtilityTools) ParseUserAgent(ua string) map[string]string {
	result := make(map[string]string)
	result["userAgent"] = ua

	if strings.Contains(ua, "Windows") {
		result["os"] = "Windows"
	} else if strings.Contains(ua, "Mac") {
		result["os"] = "macOS"
	} else if strings.Contains(ua, "Linux") {
		result["os"] = "Linux"
	} else if strings.Contains(ua, "Android") {
		result["os"] = "Android"
	} else if strings.Contains(ua, "iOS") {
		result["os"] = "iOS"
	}

	if strings.Contains(ua, "Chrome") {
		result["browser"] = "Chrome"
	} else if strings.Contains(ua, "Firefox") {
		result["browser"] = "Firefox"
	} else if strings.Contains(ua, "Safari") {
		result["browser"] = "Safari"
	} else if strings.Contains(ua, "Edge") {
		result["browser"] = "Edge"
	}

	return result
}

// WriteToFile writes data to a file securely
func (u *UtilityTools) WriteToFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0600)
}

// ReadFromFile reads data from a file
func (u *UtilityTools) ReadFromFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// DisplayUtilityTools shows available utility tools
func DisplayUtilityTools() {
	fmt.Println("\n=== Utility Tools ===")
	fmt.Println("1. UUID Generator")
	fmt.Println("2. JSON Formatter/Validator")
	fmt.Println("3. Timestamp Converter")
	fmt.Println("4. Data Masking")
}
