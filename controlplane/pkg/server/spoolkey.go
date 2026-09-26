package server

import (
	"crypto/ecdh"

	"github.com/tprm/scanner-appliance/internal/seal"
)

// sealKey wraps the control plane's spool private key so results.go can
// stay decoupled from the concrete type in tests.
type sealKey interface {
	Public() interface{}
	priv() *ecdh.PrivateKey
}

// SpoolKey is the recipient key results are sealed to (PLAN §9).
type SpoolKey struct{ Key *ecdh.PrivateKey }

func (k *SpoolKey) Public() interface{}    { return k.Key.PublicKey() }
func (k *SpoolKey) priv() *ecdh.PrivateKey { return k.Key }

// PublicString / KID render the key for the enroll response.
func (k *SpoolKey) PublicString() string { return seal.EncodePublic(k.Key.PublicKey()) }
func (k *SpoolKey) KID() string          { return seal.KID(k.Key.PublicKey()) }
