// Package pki holds the control-plane root CA that applianced pins.
//
// roots.pem is embedded at build time (ci/build.sh copies the production
// root there). For development the file may be empty; then the daemon
// also reads /etc/appliance/root-ca.pem and $APPLIANCE_ROOT_CA.
package pki

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"os"
)

//go:embed roots.pem
var embeddedRoots []byte

// RuntimeRootPath is the on-disk fallback (used by the OVA in dev/staging).
const RuntimeRootPath = "/etc/appliance/root-ca.pem"

// Pool returns the pinned root pool. Sources are additive so a staging
// root can coexist with the embedded production root.
func Pool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	n := 0
	if pool.AppendCertsFromPEM(embeddedRoots) {
		n++
	}
	for _, p := range []string{os.Getenv("APPLIANCE_ROOT_CA"), RuntimeRootPath} {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && pool.AppendCertsFromPEM(b) {
			n++
		}
	}
	if n == 0 {
		return nil, errors.New("no control-plane root CA available (embedded roots.pem empty and no APPLIANCE_ROOT_CA / /etc/appliance/root-ca.pem)")
	}
	return pool, nil
}

// Embedded reports whether a root was compiled in.
func Embedded() bool { return len(embeddedRoots) > 0 }
