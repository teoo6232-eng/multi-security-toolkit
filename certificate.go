package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CertificateTools provides certificate management utilities
type CertificateTools struct{}

// GenerateSelfSignedCert generates a self-signed certificate
func (c *CertificateTools) GenerateSelfSignedCert(commonName string, validDays int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Multi Security Toolkit"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(certPEM), string(privateKeyPEM), nil
}

// ParseCertificate parses a PEM-encoded certificate
func (c *CertificateTools) ParseCertificate(certPEM string) (map[string]interface{}, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	info := make(map[string]interface{})
	info["subject"] = cert.Subject.String()
	info["issuer"] = cert.Issuer.String()
	info["serialNumber"] = cert.SerialNumber.String()
	info["notBefore"] = cert.NotBefore.Format(time.RFC3339)
	info["notAfter"] = cert.NotAfter.Format(time.RFC3339)
	info["isCA"] = cert.IsCA
	info["version"] = cert.Version
	
	var dnsNames []string
	for _, name := range cert.DNSNames {
		dnsNames = append(dnsNames, name)
	}
	info["dnsNames"] = dnsNames

	return info, nil
}

// VerifyCertificate verifies certificate validity
func (c *CertificateTools) VerifyCertificate(certPEM string) (bool, string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, "failed to parse certificate PEM"
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Sprintf("failed to parse certificate: %v", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, "certificate is not yet valid"
	}
	if now.After(cert.NotAfter) {
		return false, "certificate has expired"
	}

	return true, "certificate is valid"
}

// GenerateCSR generates a Certificate Signing Request
func (c *CertificateTools) GenerateCSR(commonName, organization, country string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{country},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(csrPEM), string(privateKeyPEM), nil
}

// CheckCertificateExpiry checks if certificate is expiring soon
func (c *CertificateTools) CheckCertificateExpiry(certPEM string, warningDays int) (bool, string, int) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, "failed to parse certificate PEM", 0
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Sprintf("failed to parse certificate: %v", err), 0
	}

	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	if daysUntilExpiry < 0 {
		return true, "certificate has expired", daysUntilExpiry
	}
	if daysUntilExpiry <= warningDays {
		return true, fmt.Sprintf("certificate expires in %d days", daysUntilExpiry), daysUntilExpiry
	}

	return false, "certificate is valid", daysUntilExpiry
}

// ExtractPublicKey extracts public key from certificate
func (c *CertificateTools) ExtractPublicKey(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// DisplayCertificateTools shows available certificate management tools
func DisplayCertificateTools() {
	fmt.Println("\n=== Certificate Management Tools ===")
	fmt.Println("1. Generate Self-Signed Certificate")
	fmt.Println("2. Parse Certificate Information")
	fmt.Println("3. Verify Certificate Validity")
	fmt.Println("4. Generate Certificate Signing Request (CSR)")
}
