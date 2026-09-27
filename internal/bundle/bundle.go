// Package bundle implements the signature bundle of PLAN §13: a
// content-addressed manifest {version, feed_version, files:[{path, sha256,
// size}]} over a directory tree, signed with an ECDSA P-256 key in the same
// format cosign uses for blobs (base64 of the DER signature over the SHA-256
// of the manifest bytes), so `cosign sign-blob` / `cosign verify-blob` and
// this package are interchangeable.
//
// Layout inside a bundle (all optional):
//
//	nasl/...               VT feed tree; applianced installs it into the
//	                       openvas plugins directory and waits for ospd to
//	                       reload (PLAN §13 "reload_vts")
//	configs/<name>.json    openvas scan configs (internal/scanconfig)
//	nuclei-templates/...   filtered nuclei templates for the web add-on
//	fragile-ports.json     default fragile-device ports ([]int)
//
// The daemon diffs a new manifest against the installed one and fetches only
// changed or new files by sha256; deleted files are removed.
package bundle

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Manifest describes one bundle version.
type Manifest struct {
	Version     string    `json:"version"`
	FeedVersion string    `json:"feed_version,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Files       []File    `json:"files"`
}

// File is one entry; Path uses forward slashes and is relative to the
// bundle root.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Well-known paths.
const (
	FeedDir      = "nasl"
	ConfigsDir   = "configs"
	TemplatesDir = "nuclei-templates"
	FragileFile  = "fragile-ports.json"
	FeedInfoFile = "plugin_feed_info.inc"
)

// Bytes returns the total size.
func (m *Manifest) Bytes() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Size
	}
	return n
}

// Index maps path → file.
func (m *Manifest) Index() map[string]File {
	out := make(map[string]File, len(m.Files))
	for _, f := range m.Files {
		out[f.Path] = f
	}
	return out
}

// Validate checks the shape: clean relative paths, hex digests, no dupes.
func (m *Manifest) Validate() error {
	if m.Version == "" {
		return errors.New("bundle: empty version")
	}
	if !ValidVersion(m.Version) {
		return fmt.Errorf("bundle: bad version %q", m.Version)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if err := CheckPath(f.Path); err != nil {
			return err
		}
		if seen[f.Path] {
			return fmt.Errorf("bundle: duplicate path %s", f.Path)
		}
		seen[f.Path] = true
		if !isHex64(f.SHA256) {
			return fmt.Errorf("bundle: %s: bad sha256", f.Path)
		}
		if f.Size < 0 {
			return fmt.Errorf("bundle: %s: negative size", f.Path)
		}
	}
	return nil
}

// CheckPath rejects anything that could escape the target directory.
func CheckPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
		return fmt.Errorf("bundle: bad path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("bundle: bad path %q", p)
		}
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Build walks root and produces the manifest (files sorted by path).
// FeedVersion is read from nasl/plugin_feed_info.inc when present.
func Build(root, version string, now time.Time) (*Manifest, error) {
	m := &Manifest{Version: version, CreatedAt: now.UTC().Truncate(time.Second), Files: []File{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, ".") {
			return nil
		}
		sum, n, err := HashFile(p)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, File{Path: rel, SHA256: sum, Size: n})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	if f, err := os.Open(filepath.Join(root, FeedDir, FeedInfoFile)); err == nil {
		m.FeedVersion = ParseFeedVersion(f)
		_ = f.Close()
	}
	return m, m.Validate()
}

var pluginSetRe = regexp.MustCompile(`^\s*PLUGIN_SET\s*=\s*"([0-9]+)"`)

// ParseFeedVersion extracts PLUGIN_SET from plugin_feed_info.inc.
func ParseFeedVersion(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if m := pluginSetRe.FindStringSubmatch(sc.Text()); m != nil {
			return m[1]
		}
	}
	return ""
}

// HashFile returns the hex sha256 and size of a file.
func HashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Diff returns the files to fetch (new or changed) and the paths to remove
// when moving from installed to next. installed may be nil (first install).
func Diff(installed, next *Manifest) (fetch []File, remove []string) {
	have := map[string]File{}
	if installed != nil {
		have = installed.Index()
	}
	want := next.Index()
	for _, f := range next.Files {
		if h, ok := have[f.Path]; !ok || h.SHA256 != f.SHA256 || h.Size != f.Size {
			fetch = append(fetch, f)
		}
	}
	for p := range have {
		if _, ok := want[p]; !ok {
			remove = append(remove, p)
		}
	}
	sort.Strings(remove)
	return fetch, remove
}

// ---- signing (cosign blob compatible) ----

// GenerateKey makes a P-256 signing key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Sign returns base64(DER-ECDSA(SHA-256(b))), the format `cosign
// sign-blob` writes for a key-based signature.
func Sign(b []byte, key *ecdsa.PrivateKey) (string, error) {
	h := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks a Sign signature against any of the public keys.
func Verify(b []byte, sigB64 string, pubs []*ecdsa.PublicKey) error {
	h := sha256.Sum256(b)
	return VerifyDigest(h[:], sigB64, pubs)
}

// VerifyDigest is Verify for a caller that hashed the payload while
// streaming it (release artifacts).
func VerifyDigest(digest []byte, sigB64 string, pubs []*ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("bundle: signature is not base64: %w", err)
	}
	for _, pub := range pubs {
		if pub != nil && ecdsa.VerifyASN1(pub, digest, sig) {
			return nil
		}
	}
	if len(pubs) == 0 {
		return errors.New("bundle: no release signing key available")
	}
	return errors.New("bundle: signature does not verify against any release key")
}

// ValidVersion accepts the characters a bundle/release version may carry
// (it ends up in paths and in a shell-sourced file on the appliance).
func ValidVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}

// SHA256Hex of bytes.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// EncodeManifest renders the canonical bytes that get signed and served:
// compact JSON, so the manifest survives being embedded as a
// json.RawMessage (which encoding/json compacts) byte for byte.
func EncodeManifest(m *Manifest) ([]byte, error) {
	return json.Marshal(m)
}

// DecodeManifest parses and validates.
func DecodeManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("bundle: manifest: %w", err)
	}
	if m.Files == nil {
		m.Files = []File{}
	}
	return &m, m.Validate()
}

// ---- key files ----

// SavePrivate writes an EC private key PEM (0600).
func SavePrivate(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// SavePublic writes a PKIX public key PEM, the format cosign expects.
func SavePublic(path string, pub *ecdsa.PublicKey) error {
	return os.WriteFile(path, EncodePublic(pub), 0o644)
}

// EncodePublic returns the PKIX PEM.
func EncodePublic(pub *ecdsa.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// LoadPrivate reads an EC (SEC1) or PKCS#8 private key PEM.
func LoadPrivate(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivate(b)
}

// ParsePrivate parses an EC (SEC1) or PKCS#8 private key PEM.
func ParsePrivate(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bundle: no PEM block in private key")
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: private key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("bundle: private key is not ECDSA")
	}
	return ek, nil
}

// ParsePublicKeys parses every PUBLIC KEY block in the PEM (rotation: an old
// and a new key may coexist). Non-ECDSA blocks are skipped.
func ParsePublicKeys(b []byte) []*ecdsa.PublicKey {
	var out []*ecdsa.PublicKey
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		if blk.Type != "PUBLIC KEY" {
			continue
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			continue
		}
		if ek, ok := k.(*ecdsa.PublicKey); ok {
			out = append(out, ek)
		}
	}
}

// LoadPublicKeys reads a PEM file of public keys.
func LoadPublicKeys(path string) ([]*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := ParsePublicKeys(b)
	if len(keys) == 0 {
		return nil, fmt.Errorf("bundle: no ECDSA public key in %s", path)
	}
	return keys, nil
}
