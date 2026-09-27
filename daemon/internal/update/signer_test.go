package update

import (
	"crypto/ecdsa"
	"testing"

	"github.com/tprm/scanner-appliance/internal/bundle"
)

type signer struct{ key *ecdsa.PrivateKey }

func newSigner(t *testing.T) signer {
	t.Helper()
	k, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: k}
}

func (s signer) pubs() []*ecdsa.PublicKey { return []*ecdsa.PublicKey{&s.key.PublicKey} }
