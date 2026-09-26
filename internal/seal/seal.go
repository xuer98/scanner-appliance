// Package seal encrypts result chunks to the control plane's public key so
// the spool on the appliance is unreadable without the control plane
// (PLAN §9, G6). It is an age-style construction from the standard library
// only: ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM, with the job id
// and sequence number as associated data. The appliance holds only the
// public key and cannot decrypt what it wrote.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const version = 1

// Envelope is the sealed wire/disk format.
type Envelope struct {
	V     int    `json:"v"`
	KID   string `json:"kid"`   // recipient key id
	EPK   string `json:"epk"`   // ephemeral public key, X9.63 uncompressed, base64
	Nonce string `json:"nonce"` // 12 bytes, base64
	CT    string `json:"ct"`    // AES-256-GCM ciphertext+tag, base64
}

// GenerateKey creates a recipient key.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// EncodePublic renders a public key for the enroll response.
func EncodePublic(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ParsePublic reverses EncodePublic.
func ParsePublic(s string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(b)
}

// KID is a short stable identifier of a public key.
func KID(pub *ecdh.PublicKey) string {
	h := sha256.Sum256(pub.Bytes())
	return hex.EncodeToString(h[:8])
}

// SavePrivate writes a PKCS#8 PEM (0600).
func SavePrivate(path string, k *ecdh.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// LoadPrivate reads a PKCS#8 PEM.
func LoadPrivate(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("spool key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch kk := k.(type) {
	case *ecdh.PrivateKey:
		return kk, nil
	default:
		// ecdsa keys parse as *ecdsa.PrivateKey; convert.
		type ecdher interface {
			ECDH() (*ecdh.PrivateKey, error)
		}
		if e, ok := k.(ecdher); ok {
			return e.ECDH()
		}
		return nil, fmt.Errorf("spool key: unsupported type %T", k)
	}
}

func deriveKey(shared []byte, epk, rpk []byte) ([]byte, error) {
	info := append(append([]byte("tprm-spool-v1|"), epk...), rpk...)
	return hkdf.Key(sha256.New, shared, nil, string(info), 32)
}

// Seal encrypts plaintext to pub.
func Seal(pub *ecdh.PublicKey, plaintext, aad []byte) (*Envelope, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, eph.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return &Envelope{
		V: version, KID: KID(pub),
		EPK:   base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts an envelope with the recipient private key.
func Open(priv *ecdh.PrivateKey, env *Envelope, aad []byte) ([]byte, error) {
	if env == nil || env.V != version {
		return nil, errors.New("seal: unsupported envelope version")
	}
	if env.KID != KID(priv.PublicKey()) {
		return nil, fmt.Errorf("seal: envelope is for key %s, have %s", env.KID, KID(priv.PublicKey()))
	}
	epkB, err := base64.StdEncoding.DecodeString(env.EPK)
	if err != nil {
		return nil, err
	}
	epk, err := ecdh.P256().NewPublicKey(epkB)
	if err != nil {
		return nil, fmt.Errorf("seal: bad ephemeral key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(epk)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, epk.Bytes(), priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("seal: bad nonce length")
	}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("seal: authentication failed")
	}
	return pt, nil
}

// SealJSON marshals v and seals it; returns the envelope's JSON bytes.
func SealJSON(pub *ecdh.PublicKey, v any, aad []byte) ([]byte, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	env, err := Seal(pub, pt, aad)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// OpenJSON parses an envelope's JSON bytes and decrypts into v.
func OpenJSON(priv *ecdh.PrivateKey, b []byte, aad []byte, v any) error {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("seal: bad envelope: %w", err)
	}
	pt, err := Open(priv, &env, aad)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, v)
}

// AAD builds the associated data for a result chunk.
func AAD(jobID string, seq int) []byte {
	return []byte(fmt.Sprintf("tprm-result|%s|%d", jobID, seq))
}
