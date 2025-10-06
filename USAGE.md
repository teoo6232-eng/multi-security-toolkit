# Multi Security Toolkit - Usage Guide

## Building

```bash
go build -o multi-security-toolkit
```

## Running

```bash
./multi-security-toolkit
```

## Quick Start Examples

### 1. Generate a Secure Password
- Select option `3` (Password Security Tools)
- Select option `1` (Password Generator)
- A random secure password will be generated with uppercase, lowercase, numbers, and special characters

### 2. Hash a String
- Select option `4` (Hash & Checksum Tools)
- Select option `2` (SHA-256 Hash)
- Enter your text
- SHA-256 hash will be displayed

### 3. Encode/Decode Base64
- Select option `5` (Encoding & Decoding Tools)
- Select option `1` (Base64 Encode/Decode)
- Choose encode (1) or decode (2)
- Enter your text
- Result will be displayed

### 4. Generate JWT Token
- Select option `9` (JWT & Token Tools)
- Select option `1` (Create JWT)
- Enter subject (e.g., user ID)
- Enter secret key
- JWT token will be generated

### 5. Scan for Secrets
- Select option `10` (Analysis & Scanning Tools)
- Select option `1` (Secret Scanner)
- Enter text to scan (can include API keys, tokens, etc.)
- Any detected secrets will be reported

### 6. Check Password Strength
- Select option `3` (Password Security Tools)
- Select option `2` (Password Strength Checker)
- Enter password to analyze
- Strength score and analysis will be displayed

## Tool Categories

1. **Cryptography Tools** - 8 tools for encryption/decryption
2. **Network Security Tools** - 6 tools for network analysis
3. **Password Security Tools** - 5 tools for password management
4. **Hash & Checksum Tools** - 5 tools for hashing operations
5. **Encoding & Decoding Tools** - 5 tools for encoding/decoding
6. **Certificate Management Tools** - 4 tools for certificate operations
7. **File Security Tools** - 4 tools for file operations
8. **Web Security Tools** - 4 tools for web security
9. **JWT & Token Tools** - 4 tools for token management
10. **Analysis & Scanning Tools** - 4 tools for security scanning
11. **Utility Tools** - 4 tools for general utilities

## Security Notes

⚠️ **Important Security Considerations:**

1. **Key Management**: Store encryption keys securely, never in code
2. **Password Hashing**: Always use bcrypt or scrypt for passwords
3. **Random Generation**: Use the toolkit's secure random generators
4. **Testing Only**: Test in safe environments only
5. **Authorization**: Obtain proper authorization before security testing

## Requirements

- Go 1.18 or higher
- No external dependencies except golang.org/x/crypto

## Support

For issues and feature requests, use the GitHub issue tracker.
