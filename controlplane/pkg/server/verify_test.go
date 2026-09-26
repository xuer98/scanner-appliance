package server

import (
	"crypto/ecdsa"
	"encoding/base64"

	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
)

func verifyWith(c *ca.CA, digest []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	pub, ok := c.Intermediate.PublicKey.(*ecdsa.PublicKey)
	return ok && ecdsa.VerifyASN1(pub, digest, sig)
}
