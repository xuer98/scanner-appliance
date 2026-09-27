package pki

import (
	"crypto/ecdsa"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/tprm/scanner-appliance/daemon/internal/platform"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// release-pub.pem holds the public key(s) that signature bundles and daemon
// releases must be signed with (PLAN §13, §14). ci/build.sh copies the
// production key there; for development it may be empty and the daemon
// also reads $APPLIANCE_RELEASE_KEY and <conf>/release-pub.pem.
//
//go:embed release-pub.pem
var embeddedReleaseKeys []byte

// ReleaseKeyPath is the on-disk fallback next to root-ca.pem.
var ReleaseKeyPath = filepath.Join(platform.ConfDir(), "release-pub.pem")

// ReleaseKeys returns every configured release key (sources are additive
// so a rotation can ship both keys). Empty means updates are refused.
func ReleaseKeys() []*ecdsa.PublicKey {
	keys := bundle.ParsePublicKeys(embeddedReleaseKeys)
	for _, p := range []string{os.Getenv("APPLIANCE_RELEASE_KEY"), ReleaseKeyPath} {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			keys = append(keys, bundle.ParsePublicKeys(b)...)
		}
	}
	return keys
}

// RootsPEM returns the PEM of every pinned root (embedded plus the
// runtime overrides), for tools that need a CA file such as apt.
func RootsPEM() []byte {
	out := append([]byte{}, embeddedRoots...)
	for _, p := range []string{os.Getenv("APPLIANCE_ROOT_CA"), RuntimeRootPath} {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			if len(out) > 0 && out[len(out)-1] != '\n' {
				out = append(out, '\n')
			}
			out = append(out, b...)
		}
	}
	return out
}
