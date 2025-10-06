package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version information
const (
	Version = "1.0.0"
	AppName = "Multi Security Toolkit"
)

func main() {
	printBanner()
	
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Println("\n" + strings.Repeat("=", 60))
		fmt.Println("Select a category:")
		fmt.Println("1. Cryptography Tools")
		fmt.Println("2. Network Security Tools")
		fmt.Println("3. Password Security Tools")
		fmt.Println("4. Hash & Checksum Tools")
		fmt.Println("5. Encoding & Decoding Tools")
		fmt.Println("6. Certificate Management Tools")
		fmt.Println("7. File Security Tools")
		fmt.Println("8. Web Security Tools")
		fmt.Println("9. JWT & Token Tools")
		fmt.Println("10. Analysis & Scanning Tools")
		fmt.Println("11. Utility Tools")
		fmt.Println("12. About")
		fmt.Println("0. Exit")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			break
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			handleCryptoTools(scanner)
		case "2":
			handleNetworkTools(scanner)
		case "3":
			handlePasswordTools(scanner)
		case "4":
			handleHashTools(scanner)
		case "5":
			handleEncodingTools(scanner)
		case "6":
			handleCertificateTools(scanner)
		case "7":
			handleFileTools(scanner)
		case "8":
			handleWebTools(scanner)
		case "9":
			handleJWTTools(scanner)
		case "10":
			handleAnalysisTools(scanner)
		case "11":
			handleUtilityTools(scanner)
		case "12":
			showAbout()
		case "0":
			fmt.Println("\nThank you for using Multi Security Toolkit!")
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func printBanner() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(AppName)
	fmt.Println("Version:", Version)
	fmt.Println("A comprehensive security toolkit with 53 tools")
	fmt.Println(strings.Repeat("=", 60))
}

func showAbout() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("About Multi Security Toolkit")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Version:", Version)
	fmt.Println("Total Tools: 53")
	fmt.Println("Categories: 11")
	fmt.Println("\nThis toolkit provides comprehensive security utilities")
	fmt.Println("for cryptography, network security, password management,")
	fmt.Println("and much more.")
	fmt.Println(strings.Repeat("=", 60))
}

func handleCryptoTools(scanner *bufio.Scanner) {
	crypto := &CryptoTools{}
	
	for {
		DisplayCryptoTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter plaintext: ")
			scanner.Scan()
			plaintext := scanner.Text()
			
			key, _ := crypto.GenerateRandomKey(32)
			ciphertext, err := crypto.AESEncrypt([]byte(plaintext), key)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nEncrypted:", ciphertext)
				fmt.Printf("Key (hex): %x\n", key)
			}
			
		case "2":
			fmt.Println("\nGenerating RSA key pair (2048 bits)...")
			privateKey, publicKey, err := crypto.RSAGenerateKeyPair(2048)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nPrivate Key:")
				fmt.Println(privateKey[:100] + "...")
				fmt.Println("\nPublic Key:")
				fmt.Println(publicKey[:100] + "...")
				fmt.Println("\n(Keys truncated for display)")
			}
			
		case "3":
			key, _ := crypto.GenerateRandomKey(32)
			fmt.Printf("Generated 256-bit key: %x\n", key)
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleNetworkTools(scanner *bufio.Scanner) {
	network := &NetworkTools{}
	
	for {
		DisplayNetworkTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter hostname/IP: ")
			scanner.Scan()
			host := scanner.Text()
			
			fmt.Println("\nScanning ports 20-100...")
			openPorts, err := network.PortScan(host, 20, 100)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("Open ports:", openPorts)
			}
			
		case "2":
			fmt.Print("Enter hostname: ")
			scanner.Scan()
			hostname := scanner.Text()
			
			addrs, err := network.DNSLookup(hostname)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("IP addresses:", addrs)
			}
			
		case "3":
			localIP, err := network.GetLocalIP()
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("Local IP:", localIP)
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handlePasswordTools(scanner *bufio.Scanner) {
	password := &PasswordTools{}
	
	for {
		DisplayPasswordTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			pwd, err := password.GeneratePassword(16, true, true, true, true)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nGenerated password:", pwd)
			}
			
		case "2":
			fmt.Print("Enter password to check: ")
			scanner.Scan()
			pwd := scanner.Text()
			
			strength := password.CheckPasswordStrength(pwd)
			fmt.Println("\nPassword Analysis:")
			fmt.Printf("Length: %d\n", strength["length"])
			fmt.Printf("Strength: %s\n", strength["strength"])
			fmt.Printf("Score: %d/7\n", strength["score"])
			
		case "3":
			fmt.Print("Enter password to hash: ")
			scanner.Scan()
			pwd := scanner.Text()
			
			hash, err := password.HashPasswordBcrypt(pwd, 10)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nBcrypt hash:", hash)
			}
			
		case "5":
			passphrase := password.GeneratePassphrase(4, "-")
			fmt.Println("\nGenerated passphrase:", passphrase)
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleHashTools(scanner *bufio.Scanner) {
	hash := &HashTools{}
	
	for {
		DisplayHashTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter text to hash: ")
			scanner.Scan()
			text := scanner.Text()
			
			fmt.Println("\nMD5:", hash.MD5Hash([]byte(text)))
			
		case "2":
			fmt.Print("Enter text to hash: ")
			scanner.Scan()
			text := scanner.Text()
			
			fmt.Println("\nSHA-256:", hash.SHA256Hash([]byte(text)))
			
		case "3":
			fmt.Print("Enter text to hash: ")
			scanner.Scan()
			text := scanner.Text()
			
			fmt.Println("\nSHA-512:", hash.SHA512Hash([]byte(text)))
			
		case "5":
			fmt.Print("Enter text to hash: ")
			scanner.Scan()
			text := scanner.Text()
			
			hashes := hash.MultiHash([]byte(text))
			fmt.Println("\nAll hashes:")
			for algo, h := range hashes {
				fmt.Printf("%s: %s\n", strings.ToUpper(algo), h)
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleEncodingTools(scanner *bufio.Scanner) {
	encoding := &EncodingTools{}
	
	for {
		DisplayEncodingTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Println("\n1. Encode  2. Decode")
			fmt.Print("Choose: ")
			scanner.Scan()
			subChoice := scanner.Text()
			
			if subChoice == "1" {
				fmt.Print("Enter text to encode: ")
				scanner.Scan()
				text := scanner.Text()
				fmt.Println("\nBase64:", encoding.Base64Encode([]byte(text)))
			} else if subChoice == "2" {
				fmt.Print("Enter Base64 to decode: ")
				scanner.Scan()
				text := scanner.Text()
				decoded, err := encoding.Base64Decode(text)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("\nDecoded:", string(decoded))
				}
			}
			
		case "2":
			fmt.Println("\n1. Encode  2. Decode")
			fmt.Print("Choose: ")
			scanner.Scan()
			subChoice := scanner.Text()
			
			if subChoice == "1" {
				fmt.Print("Enter text to encode: ")
				scanner.Scan()
				text := scanner.Text()
				fmt.Println("\nHex:", encoding.HexEncode([]byte(text)))
			} else if subChoice == "2" {
				fmt.Print("Enter hex to decode: ")
				scanner.Scan()
				text := scanner.Text()
				decoded, err := encoding.HexDecode(text)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("\nDecoded:", string(decoded))
				}
			}
			
		case "3":
			fmt.Println("\n1. Encode  2. Decode")
			fmt.Print("Choose: ")
			scanner.Scan()
			subChoice := scanner.Text()
			
			if subChoice == "1" {
				fmt.Print("Enter text to encode: ")
				scanner.Scan()
				text := scanner.Text()
				fmt.Println("\nURL Encoded:", encoding.URLEncode(text))
			} else if subChoice == "2" {
				fmt.Print("Enter URL encoded text: ")
				scanner.Scan()
				text := scanner.Text()
				decoded, err := encoding.URLDecode(text)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("\nDecoded:", decoded)
				}
			}
			
		case "4":
			fmt.Print("Enter text: ")
			scanner.Scan()
			text := scanner.Text()
			fmt.Println("\nROT13:", encoding.ROT13(text))
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleCertificateTools(scanner *bufio.Scanner) {
	cert := &CertificateTools{}
	
	for {
		DisplayCertificateTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter Common Name: ")
			scanner.Scan()
			cn := scanner.Text()
			
			fmt.Print("Valid days (e.g., 365): ")
			scanner.Scan()
			daysStr := scanner.Text()
			days, _ := strconv.Atoi(daysStr)
			if days <= 0 {
				days = 365
			}
			
			certPEM, keyPEM, err := cert.GenerateSelfSignedCert(cn, days)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nCertificate generated successfully!")
				fmt.Println("Certificate (truncated):", certPEM[:100]+"...")
				fmt.Println("Private Key (truncated):", keyPEM[:100]+"...")
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleFileTools(scanner *bufio.Scanner) {
	file := &FileTools{}
	
	for {
		DisplayFileTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter input file path: ")
			scanner.Scan()
			input := scanner.Text()
			
			fmt.Print("Enter output file path: ")
			scanner.Scan()
			output := scanner.Text()
			
			key, _ := file.GenerateFileKey()
			keyBytes, _ := hexStringToBytes(key)
			
			err := file.EncryptFile(input, output, keyBytes)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nFile encrypted successfully!")
				fmt.Println("Key:", key)
				fmt.Println("Save this key to decrypt the file later.")
			}
			
		case "4":
			keyStr, _ := file.GenerateFileKey()
			fmt.Println("\nGenerated encryption key:", keyStr)
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleWebTools(scanner *bufio.Scanner) {
	web := &WebTools{}
	
	for {
		DisplayWebTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter URL (e.g., https://example.com): ")
			scanner.Scan()
			url := scanner.Text()
			
			fmt.Println("\nChecking security headers...")
			result, err := web.CheckSecurityHeaders(url)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nSecurity Score:", result["score"])
				headers := result["securityHeaders"].(map[string]bool)
				for header, present := range headers {
					status := "✗"
					if present {
						status = "✓"
					}
					fmt.Printf("%s %s\n", status, header)
				}
			}
			
		case "2":
			fmt.Print("Enter text to sanitize: ")
			scanner.Scan()
			text := scanner.Text()
			
			sanitized := web.SanitizeInput(text)
			fmt.Println("\nSanitized:", sanitized)
			
		case "3":
			fmt.Print("Enter input to check: ")
			scanner.Scan()
			input := scanner.Text()
			
			found, patterns := web.CheckSQLInjection(input)
			if found {
				fmt.Println("\n⚠ SQL Injection patterns detected!")
				fmt.Println("Patterns found:", len(patterns))
			} else {
				fmt.Println("\n✓ No SQL injection patterns detected")
			}
			
		case "4":
			fmt.Print("Enter input to check: ")
			scanner.Scan()
			input := scanner.Text()
			
			found, patterns := web.CheckXSS(input)
			if found {
				fmt.Println("\n⚠ XSS patterns detected!")
				fmt.Println("Patterns found:", len(patterns))
			} else {
				fmt.Println("\n✓ No XSS patterns detected")
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleJWTTools(scanner *bufio.Scanner) {
	jwt := &JWTTools{}
	
	for {
		DisplayJWTTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter subject: ")
			scanner.Scan()
			subject := scanner.Text()
			
			fmt.Print("Enter secret key: ")
			scanner.Scan()
			secret := scanner.Text()
			
			payload := map[string]interface{}{
				"sub": subject,
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(24 * time.Hour).Unix(),
			}
			
			token, err := jwt.CreateJWT(payload, secret)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nGenerated JWT:")
				fmt.Println(token)
			}
			
		case "3":
			fmt.Print("Enter JWT token: ")
			scanner.Scan()
			token := scanner.Text()
			
			header, payload, err := jwt.DecodeJWT(token)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nHeader:")
				for k, v := range header {
					fmt.Printf("  %s: %v\n", k, v)
				}
				fmt.Println("\nPayload:")
				for k, v := range payload {
					fmt.Printf("  %s: %v\n", k, v)
				}
			}
			
		case "4":
			fmt.Print("Enter key length (e.g., 32): ")
			scanner.Scan()
			lengthStr := scanner.Text()
			length, _ := strconv.Atoi(lengthStr)
			if length <= 0 {
				length = 32
			}
			
			apiKey, err := jwt.GenerateAPIKey(length)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nGenerated API Key:", apiKey)
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleAnalysisTools(scanner *bufio.Scanner) {
	analysis := &AnalysisTools{}
	
	for {
		DisplayAnalysisTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			fmt.Print("Enter text to scan: ")
			scanner.Scan()
			text := scanner.Text()
			
			secrets := analysis.ScanForSecrets(text)
			if len(secrets) > 0 {
				fmt.Printf("\n⚠ Found %d potential secret(s):\n", len(secrets))
				for _, secret := range secrets {
					fmt.Printf("  Type: %s\n", secret["type"])
					fmt.Printf("  Value: %s\n", secret["value"][:20]+"...")
				}
			} else {
				fmt.Println("\n✓ No secrets detected")
			}
			
		case "2":
			fmt.Print("Enter code to scan: ")
			scanner.Scan()
			code := scanner.Text()
			
			vulns := analysis.ScanForVulnerabilities(code)
			if len(vulns) > 0 {
				fmt.Printf("\n⚠ Found %d vulnerability pattern(s):\n", len(vulns))
				for _, vuln := range vulns {
					fmt.Printf("  Type: %s\n", vuln["type"])
					fmt.Printf("  Description: %s\n", vuln["description"])
				}
			} else {
				fmt.Println("\n✓ No vulnerabilities detected")
			}
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func handleUtilityTools(scanner *bufio.Scanner) {
	utils := &UtilityTools{}
	
	for {
		DisplayUtilityTools()
		fmt.Println("0. Back to main menu")
		fmt.Print("\nEnter your choice: ")
		
		if !scanner.Scan() {
			return
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			uuid := utils.GenerateUUID()
			fmt.Println("\nGenerated UUID:", uuid)
			
		case "2":
			fmt.Print("Enter JSON to format: ")
			scanner.Scan()
			jsonStr := scanner.Text()
			
			formatted, err := utils.FormatJSON(jsonStr)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("\nFormatted JSON:")
				fmt.Println(formatted)
			}
			
		case "3":
			fmt.Print("Enter timestamp (Unix or RFC3339): ")
			scanner.Scan()
			timestamp := scanner.Text()
			
			// Try to parse as Unix timestamp
			if unixTime, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
				result := utils.TimestampConverter(unixTime)
				fmt.Println("\nConverted timestamps:")
				for format, value := range result {
					fmt.Printf("%s: %s\n", format, value)
				}
			} else {
				// Try as string
				result := utils.TimestampConverter(timestamp)
				fmt.Println("\nConverted timestamps:")
				for format, value := range result {
					fmt.Printf("%s: %s\n", format, value)
				}
			}
			
		case "4":
			fmt.Print("Enter data to mask: ")
			scanner.Scan()
			data := scanner.Text()
			
			masked := utils.MaskSensitiveData(data)
			fmt.Println("\nMasked data:", masked)
			
		case "0":
			return
			
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

// Helper function to convert hex string to bytes
func hexStringToBytes(hexStr string) ([]byte, error) {
	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		b, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		bytes[i/2] = byte(b)
	}
	return bytes, nil
}