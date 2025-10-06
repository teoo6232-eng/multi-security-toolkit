# Multi Security Toolkit

A comprehensive security toolkit written in Go, providing 53+ security tools across 11 categories.

## Version
1.0.0

## Features

### 1. Cryptography Tools (8 tools)
- AES-256-GCM Encryption/Decryption
- DES Encryption/Decryption
- RSA Key Generation (2048/4096 bits)
- RSA Encryption/Decryption
- Blowfish Encryption
- Twofish Encryption
- ChaCha20-Poly1305 Encryption/Decryption
- Random Cryptographic Key Generation

### 2. Network Security Tools (6 tools)
- Port Scanner
- DNS Lookup
- Reverse DNS Lookup
- HTTP Security Headers Checker
- SSL/TLS Certificate Verification
- Traceroute

### 3. Password Security Tools (5 tools)
- Secure Password Generator
- Password Strength Analyzer
- Bcrypt Password Hashing
- Scrypt Password Hashing
- Passphrase Generator

### 4. Hash & Checksum Tools (5 tools)
- MD5 Hash
- SHA-256 Hash
- SHA-512 Hash
- File Checksum Verification
- Multiple Hash Calculator (MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2b, BLAKE2s)

### 5. Encoding & Decoding Tools (5 tools)
- Base64 Encode/Decode
- Hex Encode/Decode
- URL Encode/Decode
- ROT13 / Caesar Cipher
- XOR Encode/Decode

### 6. Certificate Management Tools (4 tools)
- Generate Self-Signed Certificates
- Parse Certificate Information
- Verify Certificate Validity
- Generate Certificate Signing Request (CSR)

### 7. File Security Tools (4 tools)
- File Encryption (AES-256-GCM)
- File Decryption
- Secure File Deletion
- File Integrity Checking

### 8. Web Security Tools (4 tools)
- Security Headers Analyzer
- Input Sanitizer (XSS Prevention)
- SQL Injection Detector
- XSS Pattern Detector

### 9. JWT & Token Tools (4 tools)
- Create JWT Tokens
- Verify JWT Tokens
- Decode JWT Tokens
- Generate API Keys

### 10. Analysis & Scanning Tools (4 tools)
- Secret Scanner (AWS Keys, GitHub Tokens, etc.)
- Vulnerability Scanner (SQL Injection, Command Injection, etc.)
- Dependency Analyzer
- Compliance Checker

### 11. Utility Tools (4 tools)
- UUID Generator
- JSON Formatter/Validator
- Timestamp Converter
- Sensitive Data Masking

## Installation

### Prerequisites
- Go 1.18 or higher

### Build from Source
```bash
git clone https://github.com/teoo6232-eng/multi-security-toolkit.git
cd multi-security-toolkit
go mod tidy
go build -o multi-security-toolkit
```

## Usage

Run the application:
```bash
./multi-security-toolkit
```

The interactive menu will guide you through the available tools.

## Examples

### Generate a Secure Password
1. Select option `3` (Password Security Tools)
2. Select option `1` (Password Generator)
3. A random secure password will be generated

### Encrypt a File
1. Select option `7` (File Security Tools)
2. Select option `1` (Encrypt File)
3. Provide input and output file paths
4. Save the generated encryption key

### Scan for Secrets
1. Select option `10` (Analysis & Scanning Tools)
2. Select option `1` (Secret Scanner)
3. Enter text to scan for potential secrets

### Generate JWT Token
1. Select option `9` (JWT & Token Tools)
2. Select option `1` (Create JWT)
3. Provide subject and secret key
4. JWT token will be generated

## Security Notes

- Always use strong, randomly generated keys for encryption
- Store encryption keys securely
- Use bcrypt or scrypt for password hashing
- Regularly update dependencies for security patches
- Test security configurations in a safe environment first

## Architecture

The toolkit is organized into 13 files:
- `main.go` - Main application and CLI interface
- `crypto.go` - Cryptography utilities
- `network.go` - Network security tools
- `password.go` - Password management
- `hash.go` - Hashing and checksums
- `encoding.go` - Encoding/decoding utilities
- `certificate.go` - Certificate management
- `file.go` - File security operations
- `web.go` - Web security tools
- `jwt.go` - JWT and token utilities
- `analysis.go` - Security analysis and scanning
- `utils.go` - General utility functions
- `go.mod` - Go module dependencies

## Dependencies

- `golang.org/x/crypto` - Advanced cryptographic functions

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices
- All tests pass
- Security features are properly implemented
- Documentation is updated

## License

MIT License

## Disclaimer

This toolkit is provided for educational and legitimate security testing purposes only. Always obtain proper authorization before testing security on systems you don't own.

## Support

For issues and feature requests, please use the GitHub issue tracker.

## Author

Multi Security Toolkit Team

## Changelog

### Version 1.0.0
- Initial release
- 53 security tools across 11 categories
- Interactive CLI interface
- Comprehensive cryptography support
- Network security analysis
- Web security testing utilities
- File encryption and protection
- Password security features
- JWT token management
- Security scanning and analysis
