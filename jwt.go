package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// JWTTools provides JWT and token utilities
type JWTTools struct{}

// JWTHeader represents the JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTPayload represents the JWT payload
type JWTPayload struct {
	Sub string `json:"sub,omitempty"`
	Iat int64  `json:"iat,omitempty"`
	Exp int64  `json:"exp,omitempty"`
	Iss string `json:"iss,omitempty"`
	Aud string `json:"aud,omitempty"`
}

// CreateJWT creates a JWT token
func (j *JWTTools) CreateJWT(payload map[string]interface{}, secret string) (string, error) {
	// Create header
	header := JWTHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	// Add standard claims if not present
	if _, ok := payload["iat"]; !ok {
		payload["iat"] = time.Now().Unix()
	}
	if _, ok := payload["exp"]; !ok {
		payload["exp"] = time.Now().Add(24 * time.Hour).Unix()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Encode header and payload
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	message := headerEncoded + "." + payloadEncoded
	signature := j.signHS256(message, secret)

	// Construct JWT
	token := message + "." + signature

	return token, nil
}

// VerifyJWT verifies and decodes a JWT token
func (j *JWTTools) VerifyJWT(token, secret string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	expectedSignature := j.signHS256(message, secret)
	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if exp, ok := payload["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token has expired")
		}
	}

	return payload, nil
}

// DecodeJWT decodes a JWT without verification
func (j *JWTTools) DecodeJWT(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}

	var header map[string]interface{}
	err = json.Unmarshal(headerJSON, &header)
	if err != nil {
		return nil, nil, err
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}

// signHS256 creates HMAC-SHA256 signature
func (j *JWTTools) signHS256(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// GenerateAPIKey generates a random API key
func (j *JWTTools) GenerateAPIKey(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateAccessToken generates a random access token
func (j *JWTTools) GenerateAccessToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// GenerateRefreshToken generates a random refresh token
func (j *JWTTools) GenerateRefreshToken() (string, error) {
	token := make([]byte, 48)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// ValidateTokenFormat checks if a token has valid format
func (j *JWTTools) ValidateTokenFormat(token string) (bool, string) {
	if token == "" {
		return false, "token is empty"
	}

	// Check JWT format
	if strings.Count(token, ".") == 2 {
		parts := strings.Split(token, ".")
		for _, part := range parts {
			if part == "" {
				return false, "invalid JWT format: empty part"
			}
		}
		return true, "valid JWT format"
	}

	// Check if it's a hex token
	if _, err := hex.DecodeString(token); err == nil && len(token)%2 == 0 {
		return true, "valid hex token"
	}

	// Check if it's a base64 token
	if _, err := base64.StdEncoding.DecodeString(token); err == nil {
		return true, "valid base64 token"
	}

	return false, "unknown token format"
}

// CreateOAuthToken creates an OAuth-style token structure
func (j *JWTTools) CreateOAuthToken(clientID string, scopes []string, expiresIn int64) (map[string]interface{}, error) {
	accessToken, err := j.GenerateAccessToken()
	if err != nil {
		return nil, err
	}

	refreshToken, err := j.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	token := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"scope":         strings.Join(scopes, " "),
		"client_id":     clientID,
		"created_at":    time.Now().Unix(),
	}

	return token, nil
}

// DisplayJWTTools shows available JWT and token tools
func DisplayJWTTools() {
	fmt.Println("\n=== JWT & Token Tools ===")
	fmt.Println("1. Create JWT")
	fmt.Println("2. Verify JWT")
	fmt.Println("3. Decode JWT")
	fmt.Println("4. Generate API Key")
}

// CreateJWTWithClaims creates JWT with custom claims
func (j *JWTTools) CreateJWTWithClaims(claims map[string]interface{}, secret string, expiresIn int64) (string, error) {
	// Add standard claims
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Unix() + expiresIn
	}
	if _, ok := claims["nbf"]; !ok {
		claims["nbf"] = time.Now().Unix()
	}

	return j.CreateJWT(claims, secret)
}

// RefreshJWT refreshes an existing JWT
func (j *JWTTools) RefreshJWT(token, secret string, expiresIn int64) (string, error) {
	// Verify and decode existing token
	payload, err := j.VerifyJWT(token, secret)
	if err != nil {
		// If expired, still decode it
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return "", fmt.Errorf("invalid token format")
		}

		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", err
		}

		err = json.Unmarshal(payloadJSON, &payload)
		if err != nil {
			return "", err
		}
	}

	// Update timestamps
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Unix() + expiresIn

	return j.CreateJWT(payload, secret)
}

// RevokeJWT adds JWT to revocation list (simplified)
func (j *JWTTools) RevokeJWT(token string, revocationList *[]string) {
	*revocationList = append(*revocationList, token)
}

// IsJWTRevoked checks if JWT is revoked
func (j *JWTTools) IsJWTRevoked(token string, revocationList []string) bool {
	for _, revokedToken := range revocationList {
		if token == revokedToken {
			return true
		}
	}
	return false
}

// ExtractJWTClaims extracts specific claims from JWT
func (j *JWTTools) ExtractJWTClaims(token string, claimNames []string) (map[string]interface{}, error) {
	_, payload, err := j.DecodeJWT(token)
	if err != nil {
		return nil, err
	}

	claims := make(map[string]interface{})
	for _, name := range claimNames {
		if value, ok := payload[name]; ok {
			claims[name] = value
		}
	}

	return claims, nil
}

// ValidateJWTExpiry checks if JWT is expired
func (j *JWTTools) ValidateJWTExpiry(token string) (bool, int64, error) {
	_, payload, err := j.DecodeJWT(token)
	if err != nil {
		return false, 0, err
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		return false, 0, fmt.Errorf("no expiry claim found")
	}

	now := time.Now().Unix()
	expiresAt := int64(exp)
	
	isValid := now < expiresAt
	remainingTime := expiresAt - now

	return isValid, remainingTime, nil
}

// CreateSessionToken creates a session token
func (j *JWTTools) CreateSessionToken(userID string, sessionData map[string]interface{}) (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	// Combine user ID, session data, and random bytes
	data := fmt.Sprintf("%s:%d:%s", userID, time.Now().Unix(), hex.EncodeToString(token))
	
	return base64.URLEncoding.EncodeToString([]byte(data)), nil
}

// ValidateSessionToken validates a session token
func (j *JWTTools) ValidateSessionToken(token string, maxAge int64) (bool, string, error) {
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false, "", err
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) < 3 {
		return false, "", fmt.Errorf("invalid token format")
	}

	userID := parts[0]
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false, "", err
	}

	age := time.Now().Unix() - timestamp
	isValid := age <= maxAge

	return isValid, userID, nil
}

// GenerateBearerToken generates a Bearer token
func (j *JWTTools) GenerateBearerToken(userID string, scopes []string) (string, error) {
	claims := map[string]interface{}{
		"sub":    userID,
		"scopes": scopes,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
	}

	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return j.CreateJWT(claims, hex.EncodeToString(secret))
}

// ParseBearerToken parses Bearer token from Authorization header
func (j *JWTTools) ParseBearerToken(authHeader string) (string, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	return strings.TrimSpace(token), nil
}

// GenerateMAC generates Message Authentication Code
func (j *JWTTools) GenerateMAC(message, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyMAC verifies Message Authentication Code
func (j *JWTTools) VerifyMAC(message, key, mac string) bool {
	expectedMAC := j.GenerateMAC(message, key)
	return hmac.Equal([]byte(mac), []byte(expectedMAC))
}

// CreateTemporaryToken creates a temporary single-use token
func (j *JWTTools) CreateTemporaryToken(purpose string, expiresIn int64) (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	data := map[string]interface{}{
		"token":   hex.EncodeToString(token),
		"purpose": purpose,
		"exp":     time.Now().Unix() + expiresIn,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(jsonData), nil
}

// ValidateTemporaryToken validates a temporary token
func (j *JWTTools) ValidateTemporaryToken(token, expectedPurpose string) (bool, error) {
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(decoded, &data)
	if err != nil {
		return false, err
	}

	purpose, ok := data["purpose"].(string)
	if !ok || purpose != expectedPurpose {
		return false, fmt.Errorf("invalid purpose")
	}

	exp, ok := data["exp"].(float64)
	if !ok {
		return false, fmt.Errorf("no expiry found")
	}

	if time.Now().Unix() > int64(exp) {
		return false, fmt.Errorf("token expired")
	}

	return true, nil
}

// CreateResetToken creates a password reset token
func (j *JWTTools) CreateResetToken(userID string) (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s:%d:%s", userID, time.Now().Unix(), hex.EncodeToString(token))
	h := sha256.New()
	h.Write([]byte(data))

	return hex.EncodeToString(h.Sum(nil)), nil
}

// CreateVerificationToken creates an email verification token
func (j *JWTTools) CreateVerificationToken(email string) (string, error) {
	token := make([]byte, 24)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s:%s", email, hex.EncodeToString(token))
	return base64.URLEncoding.EncodeToString([]byte(data)), nil
}

// GenerateTokenPair generates access and refresh token pair
func (j *JWTTools) GenerateTokenPair(userID string, secret string) (map[string]string, error) {
	// Access token (short-lived)
	accessClaims := map[string]interface{}{
		"sub":  userID,
		"type": "access",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
	}

	accessToken, err := j.CreateJWT(accessClaims, secret)
	if err != nil {
		return nil, err
	}

	// Refresh token (long-lived)
	refreshClaims := map[string]interface{}{
		"sub":  userID,
		"type": "refresh",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(7 * 24 * time.Hour).Unix(),
	}

	refreshToken, err := j.CreateJWT(refreshClaims, secret)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	}, nil
}

// ValidateRefreshToken validates a refresh token
func (j *JWTTools) ValidateRefreshToken(token, secret string) (string, error) {
	payload, err := j.VerifyJWT(token, secret)
	if err != nil {
		return "", err
	}

	tokenType, ok := payload["type"].(string)
	if !ok || tokenType != "refresh" {
		return "", fmt.Errorf("not a refresh token")
	}

	userID, ok := payload["sub"].(string)
	if !ok {
		return "", fmt.Errorf("invalid subject claim")
	}

	return userID, nil
}
