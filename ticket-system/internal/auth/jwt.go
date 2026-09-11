package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Sub string `json:"sub"` // user ID
	Exp int64  `json:"exp"` // unix seconds
	Iat int64  `json:"iat"` // unix seconds
}

func b64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// GenerateToken issues a signed HS256 JWT for the given user ID, valid for ttl.
func GenerateToken(userID string, secret []byte, ttl time.Duration) (string, error) {
	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwtClaims{
		Sub: userID,
		Iat: now.Unix(),
		Exp: now.Add(ttl).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := b64Encode(headerJSON) + "." + b64Encode(claimsJSON)
	sig := sign(signingInput, secret)
	return signingInput + "." + b64Encode(sig), nil
}

// ParseToken verifies the signature and expiry of tokenString and returns the user ID (sub claim).
func ParseToken(tokenString string, secret []byte) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := sign(signingInput, secret)

	actualSig, err := b64Decode(parts[2])
	if err != nil {
		return "", ErrInvalidToken
	}
	if subtle.ConstantTimeCompare(expectedSig, actualSig) != 1 {
		return "", ErrInvalidToken
	}

	claimsBytes, err := b64Decode(parts[1])
	if err != nil {
		return "", ErrInvalidToken
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", ErrInvalidToken
	}

	if time.Now().Unix() > claims.Exp {
		return "", ErrExpiredToken
	}
	if claims.Sub == "" {
		return "", ErrInvalidToken
	}
	return claims.Sub, nil
}

func sign(input string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

// EnsureSecretNotEmpty is a small guard used at startup so the server
// never silently runs with an empty signing secret.
func EnsureSecretNotEmpty(secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("JWT secret must not be empty")
	}
	return nil
}
