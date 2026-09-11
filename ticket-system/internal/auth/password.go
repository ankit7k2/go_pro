// Package auth handles password hashing and JWT issuing/verification.
//
// Password hashing uses PBKDF2-HMAC-SHA256 implemented directly against the
// Go standard library (crypto/hmac + crypto/sha256). This avoids pulling in
// an external module just for hashing, while still storing salted,
// iterated hashes instead of plaintext passwords.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Iterations = 100_000
	saltLengthBytes  = 16
	keyLengthBytes   = 32
)

// pbkdf2 derives a keyLen-byte key from password+salt using iter rounds of HMAC-SHA256.
// This is a direct implementation of RFC 2898 PBKDF2 with PRF = HMAC-SHA256.
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, 4)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)

		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// HashPassword returns an encoded string of the form:
//
//	pbkdf2$<iterations>$<saltHex>$<hashHex>
//
// This encoded form is safe to store in place of the plaintext password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLengthBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash := pbkdf2([]byte(password), salt, pbkdf2Iterations, keyLengthBytes)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

// CheckPassword reports whether password matches the previously encoded hash.
// Comparison is constant-time to avoid timing side-channels.
func CheckPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2([]byte(password), salt, iter, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
