// Package codes generates and verifies single-use enrollment codes.
//
// A code is 20 base32 characters (100 bits of entropy) displayed in groups
// of four: ABCD-EFGH-IJKL-MNOP-QRST. Only the SHA-256 of the normalized
// form is stored (PLAN §5, §16).
package codes

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	// Length in base32 characters.
	Length = 20
	// TTL is how long a code stays valid after issue (PLAN §5).
	TTL = 14 * 24 * time.Hour
	// MaxAttempts wrong guesses invalidate the code (PLAN §7.5).
	MaxAttempts = 3
)

// Crockford-style alphabet without the ambiguous I, L, O, U.
var enc = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// New returns a fresh code in display form.
func New() (string, error) {
	// 13 random bytes → 20.8 base32 chars; take the first 20 (100 bits).
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := enc.EncodeToString(b)[:Length]
	return Format(raw), nil
}

// Format inserts dashes every four characters.
func Format(raw string) string {
	var sb strings.Builder
	for i, r := range raw {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// Normalize strips separators/whitespace, upper-cases, and maps the
// ambiguous glyphs to their canonical letters so hand-typed codes still match.
func Normalize(s string) (string, error) {
	s = strings.ToUpper(s)
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r == 'I' || r == 'L':
			sb.WriteByte('1')
		case r == 'O':
			sb.WriteByte('0')
		case r == 'U':
			sb.WriteByte('V')
		case strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", r):
			sb.WriteRune(r)
		default:
			return "", errors.New("code contains an invalid character")
		}
	}
	if sb.Len() != Length {
		return "", errors.New("code must be 20 characters")
	}
	return sb.String(), nil
}

// Hash returns the stored form of a normalized code.
func Hash(normalized string) string {
	h := sha256.Sum256([]byte("tprm-enroll-code-v1:" + normalized))
	return hex.EncodeToString(h[:])
}

// Match compares a candidate (any form) against a stored hash in constant time.
func Match(candidate, storedHash string) bool {
	n, err := Normalize(candidate)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(Hash(n)), []byte(storedHash)) == 1
}
