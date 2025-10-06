package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// EncodingTools provides encoding and decoding utilities
type EncodingTools struct{}

// Base64Encode encodes data to Base64
func (e *EncodingTools) Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes Base64 encoded data
func (e *EncodingTools) Base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// Base64URLEncode encodes data to Base64 URL-safe format
func (e *EncodingTools) Base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes Base64 URL-safe encoded data
func (e *EncodingTools) Base64URLDecode(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(encoded)
}

// HexEncode encodes data to hexadecimal
func (e *EncodingTools) HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode decodes hexadecimal encoded data
func (e *EncodingTools) HexDecode(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}

// URLEncode encodes a string for use in URL
func (e *EncodingTools) URLEncode(data string) string {
	return url.QueryEscape(data)
}

// URLDecode decodes a URL-encoded string
func (e *EncodingTools) URLDecode(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}

// HTMLEncode encodes special HTML characters
func (e *EncodingTools) HTMLEncode(data string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(data)
}

// HTMLDecode decodes HTML entities
func (e *EncodingTools) HTMLDecode(encoded string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
	)
	return replacer.Replace(encoded)
}

// BinaryEncode encodes string to binary representation
func (e *EncodingTools) BinaryEncode(data string) string {
	var result strings.Builder
	for _, char := range data {
		result.WriteString(fmt.Sprintf("%08b ", char))
	}
	return strings.TrimSpace(result.String())
}

// BinaryDecode decodes binary representation to string
func (e *EncodingTools) BinaryDecode(binary string) (string, error) {
	parts := strings.Split(binary, " ")
	var result strings.Builder
	
	for _, part := range parts {
		if part == "" {
			continue
		}
		num, err := strconv.ParseInt(part, 2, 64)
		if err != nil {
			return "", err
		}
		result.WriteRune(rune(num))
	}
	
	return result.String(), nil
}

// ROT13 applies ROT13 encoding (Caesar cipher with shift 13)
func (e *EncodingTools) ROT13(data string) string {
	var result strings.Builder
	
	for _, char := range data {
		switch {
		case char >= 'a' && char <= 'z':
			result.WriteRune('a' + (char-'a'+13)%26)
		case char >= 'A' && char <= 'Z':
			result.WriteRune('A' + (char-'A'+13)%26)
		default:
			result.WriteRune(char)
		}
	}
	
	return result.String()
}

// CaesarCipher applies Caesar cipher with custom shift
func (e *EncodingTools) CaesarCipher(data string, shift int) string {
	var result strings.Builder
	shift = shift % 26
	
	for _, char := range data {
		switch {
		case char >= 'a' && char <= 'z':
			result.WriteRune('a' + (char-'a'+rune(shift)+26)%26)
		case char >= 'A' && char <= 'Z':
			result.WriteRune('A' + (char-'A'+rune(shift)+26)%26)
		default:
			result.WriteRune(char)
		}
	}
	
	return result.String()
}

// XOREncode applies XOR encoding with a key
func (e *EncodingTools) XOREncode(data, key string) string {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return hex.EncodeToString(result)
}

// XORDecode decodes XOR encoded data
func (e *EncodingTools) XORDecode(encoded, key string) (string, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	
	return string(result), nil
}

// MorseEncode encodes text to Morse code
func (e *EncodingTools) MorseEncode(data string) string {
	morseMap := map[rune]string{
		'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".",
		'F': "..-.", 'G': "--.", 'H': "....", 'I': "..", 'J': ".---",
		'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.", 'O': "---",
		'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-",
		'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--",
		'Z': "--..", '0': "-----", '1': ".----", '2': "..---",
		'3': "...--", '4': "....-", '5': ".....", '6': "-....",
		'7': "--...", '8': "---..", '9': "----.", ' ': "/",
	}
	
	var result strings.Builder
	for _, char := range strings.ToUpper(data) {
		if morse, ok := morseMap[char]; ok {
			result.WriteString(morse)
			result.WriteString(" ")
		}
	}
	
	return strings.TrimSpace(result.String())
}

// DisplayEncodingTools shows available encoding/decoding tools
func DisplayEncodingTools() {
	fmt.Println("\n=== Encoding & Decoding Tools ===")
	fmt.Println("1. Base64 Encode/Decode")
	fmt.Println("2. Hex Encode/Decode")
	fmt.Println("3. URL Encode/Decode")
	fmt.Println("4. ROT13 / Caesar Cipher")
	fmt.Println("5. XOR Encode/Decode")
}

// Base32Encode encodes data to Base32
func (e *EncodingTools) Base32Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // Simplified
}

// AtbashCipher applies Atbash cipher (reverse alphabet)
func (e *EncodingTools) AtbashCipher(text string) string {
	var result strings.Builder
	
	for _, char := range text {
		switch {
		case char >= 'a' && char <= 'z':
			result.WriteRune('z' - (char - 'a'))
		case char >= 'A' && char <= 'Z':
			result.WriteRune('Z' - (char - 'A'))
		default:
			result.WriteRune(char)
		}
	}
	
	return result.String()
}

// VigenereCipher applies Vigenere cipher
func (e *EncodingTools) VigenereCipher(text, key string, encrypt bool) string {
	var result strings.Builder
	keyIndex := 0
	
	for _, char := range text {
		if char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' {
			isUpper := char >= 'A' && char <= 'Z'
			base := rune('a')
			if isUpper {
				base = 'A'
			}
			
			keyChar := rune(strings.ToUpper(key)[keyIndex%len(key)])
			shift := int(keyChar - 'A')
			
			if !encrypt {
				shift = -shift
			}
			
			char = char - base
			char = (char + rune(shift) + 26) % 26
			char = char + base
			
			keyIndex++
		}
		result.WriteRune(char)
	}
	
	return result.String()
}

// RunLengthEncode applies run-length encoding
func (e *EncodingTools) RunLengthEncode(data string) string {
	if len(data) == 0 {
		return ""
	}
	
	var result strings.Builder
	count := 1
	current := rune(data[0])
	
	for i := 1; i < len(data); i++ {
		if rune(data[i]) == current {
			count++
		} else {
			result.WriteString(fmt.Sprintf("%d%c", count, current))
			current = rune(data[i])
			count = 1
		}
	}
	
	result.WriteString(fmt.Sprintf("%d%c", count, current))
	return result.String()
}

// RunLengthDecode decodes run-length encoded data
func (e *EncodingTools) RunLengthDecode(encoded string) (string, error) {
	var result strings.Builder
	i := 0
	
	for i < len(encoded) {
		// Read count
		countStr := ""
		for i < len(encoded) && encoded[i] >= '0' && encoded[i] <= '9' {
			countStr += string(encoded[i])
			i++
		}
		
		if countStr == "" || i >= len(encoded) {
			return "", fmt.Errorf("invalid run-length encoding")
		}
		
		count, err := strconv.Atoi(countStr)
		if err != nil {
			return "", err
		}
		
		// Read character
		char := encoded[i]
		i++
		
		// Append character count times
		for j := 0; j < count; j++ {
			result.WriteByte(char)
		}
	}
	
	return result.String(), nil
}

// HuffmanEncode applies simple Huffman encoding (simplified)
func (e *EncodingTools) HuffmanEncode(data string) string {
	// Simplified Huffman encoding
	codes := map[rune]string{
		'e': "0", 't': "10", 'a': "110", 'o': "1110",
		'i': "1111", 'n': "11110", 's': "111110",
	}
	
	var result strings.Builder
	for _, char := range strings.ToLower(data) {
		if code, ok := codes[char]; ok {
			result.WriteString(code)
		} else {
			result.WriteString(fmt.Sprintf("[%c]", char))
		}
	}
	
	return result.String()
}

// BinaryToHex converts binary string to hexadecimal
func (e *EncodingTools) BinaryToHex(binary string) (string, error) {
	// Remove spaces
	binary = strings.ReplaceAll(binary, " ", "")
	
	if len(binary)%8 != 0 {
		return "", fmt.Errorf("binary length must be multiple of 8")
	}
	
	var result strings.Builder
	for i := 0; i < len(binary); i += 8 {
		num, err := strconv.ParseInt(binary[i:i+8], 2, 64)
		if err != nil {
			return "", err
		}
		result.WriteString(fmt.Sprintf("%02x", num))
	}
	
	return result.String(), nil
}

// HexToBinary converts hexadecimal to binary string
func (e *EncodingTools) HexToBinary(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	
	var result strings.Builder
	for _, b := range bytes {
		result.WriteString(fmt.Sprintf("%08b ", b))
	}
	
	return strings.TrimSpace(result.String()), nil
}

// OctalEncode encodes string to octal
func (e *EncodingTools) OctalEncode(data string) string {
	var result strings.Builder
	for _, char := range data {
		result.WriteString(fmt.Sprintf("%03o ", char))
	}
	return strings.TrimSpace(result.String())
}

// OctalDecode decodes octal encoded string
func (e *EncodingTools) OctalDecode(octal string) (string, error) {
	parts := strings.Split(octal, " ")
	var result strings.Builder
	
	for _, part := range parts {
		if part == "" {
			continue
		}
		num, err := strconv.ParseInt(part, 8, 64)
		if err != nil {
			return "", err
		}
		result.WriteRune(rune(num))
	}
	
	return result.String(), nil
}

// ASCIIToHex converts ASCII string to hex
func (e *EncodingTools) ASCIIToHex(ascii string) string {
	return hex.EncodeToString([]byte(ascii))
}

// HexToASCII converts hex to ASCII string
func (e *EncodingTools) HexToASCII(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// UnicodeEscape escapes Unicode characters
func (e *EncodingTools) UnicodeEscape(text string) string {
	var result strings.Builder
	for _, char := range text {
		if char > 127 {
			result.WriteString(fmt.Sprintf("\\u%04x", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// UnicodeUnescape unescapes Unicode characters
func (e *EncodingTools) UnicodeUnescape(text string) string {
	// Simplified implementation
	return text // Would need proper Unicode escape parsing
}

// QuotedPrintableEncode encodes to quoted-printable
func (e *EncodingTools) QuotedPrintableEncode(data string) string {
	var result strings.Builder
	for _, char := range data {
		if char > 126 || char < 32 || char == '=' {
			result.WriteString(fmt.Sprintf("=%02X", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// PercentEncode applies percent encoding
func (e *EncodingTools) PercentEncode(data string, safe string) string {
	var result strings.Builder
	for _, char := range data {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || 
		   (char >= '0' && char <= '9') || strings.ContainsRune(safe, char) {
			result.WriteRune(char)
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", char))
		}
	}
	return result.String()
}

// PunycodeEncode encodes IDN to Punycode (simplified)
func (e *EncodingTools) PunycodeEncode(domain string) string {
	// Simplified - real implementation would use proper Punycode algorithm
	return "xn--" + domain
}

// ZLibCompress compresses data (simplified representation)
func (e *EncodingTools) ZLibCompress(data []byte) string {
	// Simplified - would use actual zlib compression
	return base64.StdEncoding.EncodeToString(data)
}

// SubstitutionCipher applies simple substitution cipher
func (e *EncodingTools) SubstitutionCipher(text, key string) string {
	if len(key) != 26 {
		return text
	}
	
	var result strings.Builder
	for _, char := range text {
		switch {
		case char >= 'a' && char <= 'z':
			result.WriteRune(rune(key[char-'a']))
		case char >= 'A' && char <= 'Z':
			result.WriteRune(rune(strings.ToUpper(key)[char-'A']))
		default:
			result.WriteRune(char)
		}
	}
	
	return result.String()
}

// TranspositionCipher applies columnar transposition
func (e *EncodingTools) TranspositionCipher(text string, key int) string {
	if key <= 1 {
		return text
	}
	
	var result strings.Builder
	for i := 0; i < key; i++ {
		for j := i; j < len(text); j += key {
			result.WriteByte(text[j])
		}
	}
	
	return result.String()
}

// RailFenceCipher applies rail fence cipher
func (e *EncodingTools) RailFenceCipher(text string, rails int) string {
	if rails <= 1 {
		return text
	}
	
	fence := make([][]rune, rails)
	rail := 0
	direction := 1
	
	for _, char := range text {
		fence[rail] = append(fence[rail], char)
		
		if rail == 0 {
			direction = 1
		} else if rail == rails-1 {
			direction = -1
		}
		
		rail += direction
	}
	
	var result strings.Builder
	for _, row := range fence {
		result.WriteString(string(row))
	}
	
	return result.String()
}
