package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// AnalysisTools provides security analysis and scanning utilities
type AnalysisTools struct{}

// ScanForSecrets scans text for potential secrets
func (a *AnalysisTools) ScanForSecrets(text string) []map[string]string {
	var findings []map[string]string

	patterns := map[string]string{
		"AWS Access Key":      `AKIA[0-9A-Z]{16}`,
		"AWS Secret Key":      `[0-9a-zA-Z/+]{40}`,
		"GitHub Token":        `ghp_[0-9a-zA-Z]{36}`,
		"Generic API Key":     `api[_-]?key[_-]?[0-9a-zA-Z]{32,}`,
		"Generic Secret":      `secret[_-]?[0-9a-zA-Z]{16,}`,
		"Private Key":         `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`,
		"Password in URL":     `://[^:]+:[^@]+@`,
		"JWT Token":           `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`,
		"Slack Token":         `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}`,
		"Google API Key":      `AIza[0-9A-Za-z-_]{35}`,
		"Stripe API Key":      `sk_live_[0-9a-zA-Z]{24,}`,
		"Square Access Token": `sq0atp-[0-9A-Za-z\-_]{22}`,
	}

	for secretType, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(text, -1)
		for _, match := range matches {
			finding := map[string]string{
				"type":  secretType,
				"value": match,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// ScanForVulnerabilities scans code for common vulnerability patterns
func (a *AnalysisTools) ScanForVulnerabilities(code string) []map[string]string {
	var findings []map[string]string

	vulnerabilityPatterns := map[string]string{
		"SQL Injection":              `(SELECT|INSERT|UPDATE|DELETE).*FROM.*WHERE.*\+.*`,
		"Command Injection":          `(exec|system|shell_exec|passthru)\s*\(`,
		"Path Traversal":             `\.\./|\.\.\\`,
		"Hardcoded Password":         `password\s*=\s*["'][^"']{4,}["']`,
		"Insecure Random":            `Math\.random\(\)|rand\(\)`,
		"Weak Crypto":                `MD5|DES|RC4`,
		"Eval Usage":                 `eval\s*\(`,
		"Unsafe Deserialization":     `(pickle\.loads|yaml\.load|unserialize)\s*\(`,
		"SSRF":                       `(requests\.get|http\.Get|fetch)\s*\(\s*[^"']*\+`,
		"XXE":                        `XMLDecoder|DocumentBuilder`,
		"Insecure Cookie":            `document\.cookie`,
		"Hardcoded Secret":           `(api_key|apikey|secret|token)\s*=\s*["'][A-Za-z0-9]{16,}["']`,
	}

	for vulnType, pattern := range vulnerabilityPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := re.FindAllString(code, -1)
		for _, match := range matches {
			finding := map[string]string{
				"type":        vulnType,
				"pattern":     match,
				"description": getVulnerabilityDescription(vulnType),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// getVulnerabilityDescription returns description for vulnerability type
func getVulnerabilityDescription(vulnType string) string {
	descriptions := map[string]string{
		"SQL Injection":              "Potential SQL injection vulnerability detected",
		"Command Injection":          "Command injection risk found",
		"Path Traversal":             "Path traversal pattern detected",
		"Hardcoded Password":         "Hardcoded password found in code",
		"Insecure Random":            "Cryptographically insecure random function used",
		"Weak Crypto":                "Weak cryptographic algorithm detected",
		"Eval Usage":                 "Dangerous eval() usage detected",
		"Unsafe Deserialization":     "Unsafe deserialization detected",
		"SSRF":                       "Potential SSRF vulnerability",
		"XXE":                        "XML External Entity vulnerability risk",
		"Insecure Cookie":            "Insecure cookie handling detected",
		"Hardcoded Secret":           "Hardcoded secret/API key detected",
	}

	if desc, ok := descriptions[vulnType]; ok {
		return desc
	}
	return "Security issue detected"
}

// AnalyzeDependencies analyzes dependencies for known vulnerabilities
func (a *AnalysisTools) AnalyzeDependencies(dependencies []string) []map[string]interface{} {
	var findings []map[string]interface{}

	vulnerablePackages := map[string]string{
		"lodash":     "< 4.17.21",
		"jquery":     "< 3.5.0",
		"express":    "< 4.17.0",
		"axios":      "< 0.21.1",
		"moment":     "< 2.29.2",
		"minimist":   "< 1.2.6",
		"node-fetch": "< 2.6.7",
		"glob-parent": "< 5.1.2",
	}

	for _, dep := range dependencies {
		for pkg, vuln := range vulnerablePackages {
			if strings.Contains(strings.ToLower(dep), strings.ToLower(pkg)) {
				finding := map[string]interface{}{
					"package":         pkg,
					"vulnerable":      vuln,
					"found":           dep,
					"recommendation":  fmt.Sprintf("Update %s to latest version", pkg),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// CheckComplianceIssues checks for common compliance issues
func (a *AnalysisTools) CheckComplianceIssues(data map[string]interface{}) []string {
	var issues []string

	// Check for PII
	if email, ok := data["email"].(string); ok {
		if !strings.Contains(email, "@") {
			issues = append(issues, "Invalid email format for PII field")
		}
	}

	// Check for unencrypted sensitive data
	if password, ok := data["password"].(string); ok {
		if len(password) < 60 { // Bcrypt hashes are 60 chars
			issues = append(issues, "Password appears to be stored in plaintext")
		}
	}

	// Check for weak identifiers
	if id, ok := data["id"].(string); ok {
		if len(id) < 16 {
			issues = append(issues, "Identifier may be predictable or weak")
		}
	}

	// Check for missing encryption
	if _, ok := data["ssn"]; ok {
		issues = append(issues, "SSN field present - ensure proper encryption")
	}

	if _, ok := data["credit_card"]; ok {
		issues = append(issues, "Credit card field present - PCI-DSS compliance required")
	}

	return issues
}

// GenerateSecurityReport generates a security analysis report
func (a *AnalysisTools) GenerateSecurityReport(data map[string]interface{}) string {
	var report strings.Builder

	report.WriteString("=== Security Analysis Report ===\n\n")
	report.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString("\n")

	if secrets, ok := data["secrets"].([]map[string]string); ok && len(secrets) > 0 {
		report.WriteString(fmt.Sprintf("Secrets Found: %d\n", len(secrets)))
		for _, secret := range secrets {
			report.WriteString(fmt.Sprintf("  - %s\n", secret["type"]))
		}
		report.WriteString("\n")
	}

	if vulns, ok := data["vulnerabilities"].([]map[string]string); ok && len(vulns) > 0 {
		report.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n", len(vulns)))
		for _, vuln := range vulns {
			report.WriteString(fmt.Sprintf("  - %s: %s\n", vuln["type"], vuln["description"]))
		}
		report.WriteString("\n")
	}

	if issues, ok := data["compliance"].([]string); ok && len(issues) > 0 {
		report.WriteString(fmt.Sprintf("Compliance Issues: %d\n", len(issues)))
		for _, issue := range issues {
			report.WriteString(fmt.Sprintf("  - %s\n", issue))
		}
		report.WriteString("\n")
	}

	report.WriteString("=== End of Report ===\n")

	return report.String()
}

// DisplayAnalysisTools shows available analysis and scanning tools
func DisplayAnalysisTools() {
	fmt.Println("\n=== Analysis & Scanning Tools ===")
	fmt.Println("1. Secret Scanner")
	fmt.Println("2. Vulnerability Scanner")
	fmt.Println("3. Dependency Analyzer")
	fmt.Println("4. Compliance Checker")
}

// ScanForHardcodedCredentials scans for hardcoded credentials
func (a *AnalysisTools) ScanForHardcodedCredentials(code string) []map[string]string {
	var findings []map[string]string

	patterns := map[string]string{
		"Database URL":       `(mysql|postgres|mongodb):\/\/[^:]+:[^@]+@`,
		"Connection String":  `Server=.*Password=.*`,
		"API Endpoint":       `https?:\/\/[^\/]+\/api\/.*key=`,
		"FTP Credentials":    `ftp:\/\/[^:]+:[^@]+@`,
		"Basic Auth":         `Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`,
		"Private Key Header": `-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`,
	}

	for credType, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(code, -1)
		for _, match := range matches {
			finding := map[string]string{
				"type":  credType,
				"value": match,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// ScanForInsecureConfigs scans for insecure configurations
func (a *AnalysisTools) ScanForInsecureConfigs(config string) []map[string]string {
	var findings []map[string]string

	insecurePatterns := map[string]string{
		"Debug Mode Enabled":        `debug\s*[:=]\s*(true|1|on|yes)`,
		"SSL Verification Disabled": `ssl[_-]?verify\s*[:=]\s*(false|0|off|no)`,
		"Insecure Protocol":         `http:\/\/(?!localhost)`,
		"Weak Cipher":               `(DES|RC4|MD5)`,
		"Default Port":              `:(3306|5432|27017|6379|5984)`,
	}

	lowerConfig := strings.ToLower(config)
	for configType, pattern := range insecurePatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(lowerConfig) {
			finding := map[string]string{
				"type":        configType,
				"description": "Insecure configuration detected",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// AnalyzeCodeComplexity analyzes code complexity
func (a *AnalysisTools) AnalyzeCodeComplexity(code string) map[string]interface{} {
	analysis := make(map[string]interface{})

	// Count lines
	lines := strings.Split(code, "\n")
	analysis["totalLines"] = len(lines)

	// Count functions (simplified)
	funcPattern := regexp.MustCompile(`func\s+\w+`)
	functions := funcPattern.FindAllString(code, -1)
	analysis["functionCount"] = len(functions)

	// Count conditionals
	ifPattern := regexp.MustCompile(`\bif\b`)
	ifCount := len(ifPattern.FindAllString(code, -1))
	
	switchPattern := regexp.MustCompile(`\bswitch\b`)
	switchCount := len(switchPattern.FindAllString(code, -1))
	
	analysis["conditionals"] = ifCount + switchCount

	// Count loops
	forPattern := regexp.MustCompile(`\bfor\b`)
	loopCount := len(forPattern.FindAllString(code, -1))
	analysis["loops"] = loopCount

	// Calculate complexity score
	complexity := ifCount + switchCount*2 + loopCount
	analysis["complexityScore"] = complexity

	var rating string
	switch {
	case complexity < 10:
		rating = "Low"
	case complexity < 20:
		rating = "Medium"
	case complexity < 40:
		rating = "High"
	default:
		rating = "Very High"
	}
	analysis["complexityRating"] = rating

	return analysis
}

// ScanForInsecureRandomness scans for insecure random number generation
func (a *AnalysisTools) ScanForInsecureRandomness(code string) []map[string]string {
	var findings []map[string]string

	patterns := map[string]string{
		"Math.random()":     `Math\.random\(\)`,
		"rand() function":   `\brand\(\)`,
		"time-based seed":   `srand\(time\(`,
		"predictable seed":  `srand\(\d+\)`,
	}

	for randomType, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(code, -1)
		for _, match := range matches {
			finding := map[string]string{
				"type":        randomType,
				"pattern":     match,
				"description": "Insecure random number generation detected",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// ScanForRaceConditions scans for potential race conditions
func (a *AnalysisTools) ScanForRaceConditions(code string) []map[string]string {
	var findings []map[string]string

	patterns := map[string]string{
		"Shared Global Variable": `var\s+\w+\s*=`,
		"Unprotected Map Access": `map\[\w+\]\s*=`,
		"Missing Mutex":           `go\s+func\(.*\)\s*{`,
	}

	for raceType, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(code) {
			finding := map[string]string{
				"type":        raceType,
				"description": "Potential race condition detected",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// GenerateVulnerabilityReport generates a comprehensive vulnerability report
func (a *AnalysisTools) GenerateVulnerabilityReport(code string) string {
	var report strings.Builder

	report.WriteString("=== Vulnerability Scan Report ===\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	// Scan for vulnerabilities
	vulns := a.ScanForVulnerabilities(code)
	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", len(vulns)))

	if len(vulns) > 0 {
		report.WriteString("Vulnerabilities Found:\n")
		for i, vuln := range vulns {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, vuln["type"]))
			report.WriteString(fmt.Sprintf("   Description: %s\n", vuln["description"]))
			report.WriteString("\n")
		}
	}

	// Scan for secrets
	secrets := a.ScanForSecrets(code)
	report.WriteString(fmt.Sprintf("\nPotential Secrets: %d\n", len(secrets)))

	// Scan for insecure configs
	configs := a.ScanForInsecureConfigs(code)
	report.WriteString(fmt.Sprintf("Insecure Configurations: %d\n", len(configs)))

	// Analyze complexity
	complexity := a.AnalyzeCodeComplexity(code)
	report.WriteString(fmt.Sprintf("\nCode Complexity: %s\n", complexity["complexityRating"]))
	report.WriteString(fmt.Sprintf("Total Lines: %d\n", complexity["totalLines"]))
	report.WriteString(fmt.Sprintf("Functions: %d\n", complexity["functionCount"]))

	report.WriteString("\n=== End of Report ===\n")

	return report.String()
}

// CalculateSecurityScore calculates overall security score
func (a *AnalysisTools) CalculateSecurityScore(scanResults map[string]int) float64 {
	score := 100.0

	// Deduct points for issues
	score -= float64(scanResults["vulnerabilities"]) * 10
	score -= float64(scanResults["secrets"]) * 15
	score -= float64(scanResults["insecureConfigs"]) * 5
	score -= float64(scanResults["hardcodedCreds"]) * 20

	if score < 0 {
		score = 0
	}

	return score
}

// PrioritizeFindings prioritizes security findings by severity
func (a *AnalysisTools) PrioritizeFindings(findings []map[string]string) []map[string]string {
	// Sort by severity (simplified)
	priority := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}

	var prioritized []map[string]string

	for _, level := range priority {
		for _, finding := range findings {
			if finding["severity"] == level {
				prioritized = append(prioritized, finding)
			}
		}
	}

	// Add any remaining findings
	for _, finding := range findings {
		found := false
		for _, p := range prioritized {
			if p["type"] == finding["type"] {
				found = true
				break
			}
		}
		if !found {
			prioritized = append(prioritized, finding)
		}
	}

	return prioritized
}

// GenerateRemediationAdvice generates remediation advice for findings
func (a *AnalysisTools) GenerateRemediationAdvice(findingType string) string {
	advice := map[string]string{
		"SQL Injection":         "Use parameterized queries or prepared statements",
		"XSS":                   "Sanitize user input and use output encoding",
		"Command Injection":     "Avoid using shell commands or validate input strictly",
		"Path Traversal":        "Validate and sanitize file paths",
		"Hardcoded Password":    "Use environment variables or secure vaults",
		"Weak Crypto":           "Use modern cryptographic algorithms (AES-256, SHA-256)",
		"Insecure Random":       "Use cryptographically secure random generators",
		"Missing Authentication": "Implement proper authentication mechanisms",
	}

	if adv, ok := advice[findingType]; ok {
		return adv
	}

	return "Review code and apply security best practices"
}
