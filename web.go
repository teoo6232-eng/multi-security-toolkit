package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WebTools provides web security utilities
type WebTools struct{}

// CheckSecurityHeaders analyzes HTTP security headers
func (w *WebTools) CheckSecurityHeaders(url string) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := make(map[string]interface{})
	result["url"] = url
	result["statusCode"] = resp.StatusCode

	securityHeaders := map[string]bool{
		"Strict-Transport-Security": false,
		"X-Frame-Options":           false,
		"X-Content-Type-Options":    false,
		"X-XSS-Protection":          false,
		"Content-Security-Policy":   false,
		"Referrer-Policy":           false,
		"Permissions-Policy":        false,
	}

	headers := make(map[string]string)
	for key := range securityHeaders {
		value := resp.Header.Get(key)
		if value != "" {
			securityHeaders[key] = true
			headers[key] = value
		}
	}

	result["securityHeaders"] = securityHeaders
	result["headers"] = headers

	score := 0
	for _, present := range securityHeaders {
		if present {
			score++
		}
	}
	result["score"] = fmt.Sprintf("%d/7", score)

	return result, nil
}

// ValidateEmail checks if email format is valid
func (w *WebTools) ValidateEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// ValidateURL checks if URL format is valid
func (w *WebTools) ValidateURL(url string) bool {
	pattern := `^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+$`
	matched, _ := regexp.MatchString(pattern, url)
	return matched
}

// SanitizeInput sanitizes user input to prevent XSS
func (w *WebTools) SanitizeInput(input string) string {
	// Remove script tags
	scriptPattern := regexp.MustCompile(`<script[^>]*>.*?</script>`)
	input = scriptPattern.ReplaceAllString(input, "")

	// Remove event handlers
	eventPattern := regexp.MustCompile(`on\w+\s*=\s*["'][^"']*["']`)
	input = eventPattern.ReplaceAllString(input, "")

	// Escape HTML special characters
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	)

	return replacer.Replace(input)
}

// CheckSQLInjection detects potential SQL injection patterns
func (w *WebTools) CheckSQLInjection(input string) (bool, []string) {
	patterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(drop\s+table)`,
		`(?i)(update\s+\w+\s+set)`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)('|\s+or\s+'[^']*'\s*=\s*')`,
		`(?i)(--\s*$)`,
		`(?i)(;.*drop)`,
	}

	var detected []string
	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// CheckXSS detects potential XSS attack patterns
func (w *WebTools) CheckXSS(input string) (bool, []string) {
	patterns := []string{
		`<script[^>]*>.*?</script>`,
		`javascript:`,
		`on\w+\s*=`,
		`<iframe`,
		`<object`,
		`<embed`,
		`<img[^>]+src\s*=\s*["']?javascript:`,
		`expression\s*\(`,
		`@import`,
		`<link[^>]+href\s*=\s*["']?javascript:`,
	}

	var detected []string
	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// GenerateCSRFToken generates a CSRF token
func (w *WebTools) GenerateCSRFToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", token), nil
}

// CheckCORS analyzes CORS configuration
func (w *WebTools) CheckCORS(url string) (map[string]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", "https://example.com")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	corsHeaders := make(map[string]string)
	corsHeaders["Access-Control-Allow-Origin"] = resp.Header.Get("Access-Control-Allow-Origin")
	corsHeaders["Access-Control-Allow-Methods"] = resp.Header.Get("Access-Control-Allow-Methods")
	corsHeaders["Access-Control-Allow-Headers"] = resp.Header.Get("Access-Control-Allow-Headers")
	corsHeaders["Access-Control-Max-Age"] = resp.Header.Get("Access-Control-Max-Age")

	return corsHeaders, nil
}

// ValidateContentType checks if Content-Type header is properly set
func (w *WebTools) ValidateContentType(url string) (string, bool, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	isValid := contentType != ""

	return contentType, isValid, nil
}

// DisplayWebTools shows available web security tools
func DisplayWebTools() {
	fmt.Println("\n=== Web Security Tools ===")
	fmt.Println("1. Security Headers Checker")
	fmt.Println("2. Input Sanitizer")
	fmt.Println("3. SQL Injection Detector")
	fmt.Println("4. XSS Detector")
}

// CheckHSTS checks HTTP Strict Transport Security
func (w *WebTools) CheckHSTS(url string) (bool, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return false, "HSTS header not set", nil
	}

	return true, hsts, nil
}

// CheckCSP checks Content Security Policy
func (w *WebTools) CheckCSP(url string) (bool, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		return false, "CSP header not set", nil
	}

	return true, csp, nil
}

// SanitizeSQL sanitizes SQL input
func (w *WebTools) SanitizeSQL(input string) string {
	// Remove dangerous SQL keywords and characters
	dangerous := []string{
		"'", "\"", ";", "--", "/*", "*/",
		"DROP", "DELETE", "INSERT", "UPDATE",
		"UNION", "SELECT", "EXEC", "EXECUTE",
	}

	result := input
	for _, d := range dangerous {
		result = strings.ReplaceAll(result, d, "")
		result = strings.ReplaceAll(result, strings.ToLower(d), "")
	}

	return result
}

// CheckPathTraversal detects path traversal attempts
func (w *WebTools) CheckPathTraversal(path string) (bool, []string) {
	patterns := []string{
		`\.\./`,
		`\.\.\\`,
		`%2e%2e/`,
		`%2e%2e\\`,
		`..;/`,
	}

	var detected []string
	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(path), strings.ToLower(pattern)) {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// CheckCommandInjection detects command injection patterns
func (w *WebTools) CheckCommandInjection(input string) (bool, []string) {
	patterns := []string{
		`\|`, `&`, `;`, `\$\(`, "`",
		`>`, `<`, `\n`, `\r`,
	}

	var detected []string
	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// CheckLDAPInjection detects LDAP injection patterns
func (w *WebTools) CheckLDAPInjection(input string) (bool, []string) {
	patterns := []string{
		`\*`, `\(`, `\)`, `\|`, `&`,
		`!`, `=`, `~`, `>`, `<`,
	}

	var detected []string
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// CheckXMLInjection detects XML injection patterns
func (w *WebTools) CheckXMLInjection(input string) (bool, []string) {
	patterns := []string{
		`<!ENTITY`,
		`<!DOCTYPE`,
		`<![CDATA[`,
		`<?xml`,
	}

	var detected []string
	for _, pattern := range patterns {
		if strings.Contains(strings.ToUpper(input), strings.ToUpper(pattern)) {
			detected = append(detected, pattern)
		}
	}

	return len(detected) > 0, detected
}

// SanitizeFilename sanitizes filename for safe usage
func (w *WebTools) SanitizeFilename(filename string) string {
	// Remove path separators
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

	// Remove dangerous characters
	dangerous := regexp.MustCompile(`[<>:"|?*\x00-\x1f]`)
	filename = dangerous.ReplaceAllString(filename, "_")

	// Trim spaces and dots
	filename = strings.Trim(filename, " .")

	return filename
}

// ValidateMimeType validates MIME type
func (w *WebTools) ValidateMimeType(mimeType string, allowed []string) bool {
	for _, a := range allowed {
		if mimeType == a {
			return true
		}
	}
	return false
}

// CheckCSRFVulnerability checks for CSRF vulnerability
func (w *WebTools) CheckCSRFVulnerability(formHTML string) bool {
	// Check if form has CSRF token
	hasToken := strings.Contains(formHTML, "csrf") ||
		strings.Contains(formHTML, "token") ||
		strings.Contains(formHTML, "_token")

	return !hasToken
}

// CheckInsecureCookie checks for insecure cookie settings
func (w *WebTools) CheckInsecureCookie(cookie string) []string {
	var issues []string

	if !strings.Contains(cookie, "Secure") {
		issues = append(issues, "Missing Secure flag")
	}

	if !strings.Contains(cookie, "HttpOnly") {
		issues = append(issues, "Missing HttpOnly flag")
	}

	if !strings.Contains(cookie, "SameSite") {
		issues = append(issues, "Missing SameSite attribute")
	}

	return issues
}

// CheckOpenRedirect checks for open redirect vulnerability
func (w *WebTools) CheckOpenRedirect(redirectURL string, allowedDomains []string) bool {
	if !strings.HasPrefix(redirectURL, "http://") &&
		!strings.HasPrefix(redirectURL, "https://") {
		return false
	}

	for _, domain := range allowedDomains {
		if strings.Contains(redirectURL, domain) {
			return true
		}
	}

	return false
}

// SanitizeHTML sanitizes HTML content
func (w *WebTools) SanitizeHTML(html string) string {
	// Remove script tags
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")

	// Remove event handlers
	eventRe := regexp.MustCompile(`(?i)on\w+\s*=\s*["'][^"']*["']`)
	html = eventRe.ReplaceAllString(html, "")

	// Remove dangerous tags
	dangerousTags := []string{"iframe", "object", "embed", "applet", "meta", "link"}
	for _, tag := range dangerousTags {
		re := regexp.MustCompile(fmt.Sprintf(`(?i)<%s[^>]*>.*?</%s>`, tag, tag))
		html = re.ReplaceAllString(html, "")
	}

	return html
}

// CheckRateLimiting checks if rate limiting headers are present
func (w *WebTools) CheckRateLimiting(url string) (map[string]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	headers["X-RateLimit-Limit"] = resp.Header.Get("X-RateLimit-Limit")
	headers["X-RateLimit-Remaining"] = resp.Header.Get("X-RateLimit-Remaining")
	headers["X-RateLimit-Reset"] = resp.Header.Get("X-RateLimit-Reset")
	headers["Retry-After"] = resp.Header.Get("Retry-After")

	return headers, nil
}

// CheckAPIKeys checks for exposed API keys in response
func (w *WebTools) CheckAPIKeys(content string) []string {
	patterns := map[string]string{
		"AWS Key":        `AKIA[0-9A-Z]{16}`,
		"GitHub Token":   `ghp_[0-9a-zA-Z]{36}`,
		"Google API":     `AIza[0-9A-Za-z-_]{35}`,
		"Slack Token":    `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}`,
	}

	var found []string
	for keyType, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(content) {
			found = append(found, keyType)
		}
	}

	return found
}

// GenerateNonce generates a cryptographic nonce for CSP
func (w *WebTools) GenerateNonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

// ValidateOrigin validates HTTP Origin header
func (w *WebTools) ValidateOrigin(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// CheckSubresourceIntegrity checks SRI attributes
func (w *WebTools) CheckSubresourceIntegrity(html string) bool {
	// Check if external scripts have integrity attributes
	scriptRe := regexp.MustCompile(`<script[^>]+src=["'][^"']+["'][^>]*>`)
	scripts := scriptRe.FindAllString(html, -1)

	for _, script := range scripts {
		if !strings.Contains(script, "integrity=") {
			return false
		}
	}

	return len(scripts) > 0
}

// CheckClickjacking checks for clickjacking protection
func (w *WebTools) CheckClickjacking(url string) (bool, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	xFrameOptions := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	if xFrameOptions != "" || strings.Contains(csp, "frame-ancestors") {
		return true, xFrameOptions, nil
	}

	return false, "", nil
}
