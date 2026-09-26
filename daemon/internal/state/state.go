// Package state persists the appliance's durable configuration under
// /var/lib/appliance and publishes runtime status under /run/appliance.
//
//	/var/lib/appliance/key.pem     ECDSA P-256 private key (0600), never leaves the box
//	/var/lib/appliance/cert.pem    leaf + chain PEM
//	/var/lib/appliance/state.json  everything else
//	/run/appliance/status.json     live status written by the daemon, read by the TTY
package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

const (
	DefaultDir    = "/var/lib/appliance"
	DefaultRunDir = "/run/appliance"
)

// NIC is a per-interface network setting written to systemd-networkd.
type NIC struct {
	Mode string   `json:"mode" yaml:"mode"` // dhcp | static
	CIDR string   `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	GW   string   `json:"gw,omitempty" yaml:"gw,omitempty"`
	DNS  []string `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// Network holds both NICs' settings.
type Network struct {
	WAN0 *NIC `json:"wan0,omitempty" yaml:"wan0,omitempty"`
	LAN0 *NIC `json:"lan0,omitempty" yaml:"lan0,omitempty"`
}

// State is the durable configuration.
type State struct {
	// Enrollment
	ApplianceID   string        `json:"appliance_id,omitempty"`
	CPURL         string        `json:"cp_url,omitempty"`
	EnrollURL     string        `json:"enroll_url,omitempty"`
	PollIntervalS int           `json:"poll_interval_s,omitempty"`
	Site          v1.SiteConfig `json:"site"`
	EnrolledAt    *time.Time    `json:"enrolled_at,omitempty"`
	CertNotAfter  *time.Time    `json:"cert_not_after,omitempty"`

	// Pending code (only present between seed read and successful enrollment;
	// zeroed on success per PLAN §5).
	PendingCode string `json:"pending_code,omitempty"`

	// Local configuration
	Proxy   string  `json:"proxy,omitempty"` // host:port or user:pass@host:port
	Split   bool    `json:"split"`
	Network Network `json:"network"`

	// Control-channel state
	IntervalOverrideS int    `json:"interval_override_s,omitempty"`
	StopAll           bool   `json:"stop_all"`
	SeedConsumed      bool   `json:"seed_consumed"`
	BundleVersion     string `json:"bundle_version,omitempty"`

	// Spool key: results are sealed to this control-plane key before they
	// touch disk (PLAN §9). Refreshed at enrollment and renewal.
	SpoolPubKey string `json:"spool_pubkey,omitempty"`
	SpoolKID    string `json:"spool_kid,omitempty"`
}

// Store reads and writes state files with atomic replace.
type Store struct {
	Dir    string
	RunDir string
}

func New(dir, runDir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	if runDir == "" {
		runDir = DefaultRunDir
	}
	return &Store{Dir: dir, RunDir: runDir}
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Load returns the state, or an empty state if none exists yet.
func (s *Store) Load() (*State, error) {
	st := &State{}
	b, err := os.ReadFile(s.path("state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("state.json corrupt: %w", err)
	}
	return st, nil
}

// Save writes state atomically.
func (s *Store) Save(st *State) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path("state.json"), b, 0o600)
}

// Enrolled reports whether a usable certificate exists.
func (s *Store) Enrolled() bool {
	st, err := s.Load()
	if err != nil || st.ApplianceID == "" {
		return false
	}
	_, err = s.Certificate()
	return err == nil
}

// Key returns the appliance private key, generating it on first call.
func (s *Store) Key() (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(s.path("key.pem"))
	if err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("key.pem: no PEM block")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(s.path("key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// CSR builds a PEM certificate request for the appliance key. Subject is
// empty on purpose: the control plane sets CN and SANs.
func (s *Store) CSR() (string, error) {
	key, err := s.Key()
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// SaveCertificate stores leaf + chain.
func (s *Store) SaveCertificate(certPEM, chainPEM string) error {
	return atomicWrite(s.path("cert.pem"), []byte(certPEM+chainPEM), 0o600)
}

// Certificate loads the TLS client certificate.
func (s *Store) Certificate() (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(s.path("cert.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(s.path("key.pem"))
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil && len(c.Certificate) > 0 {
		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	return &c, nil
}

// Wipe destroys all state (PLAN §6, §9): overwrite then unlink every file.
func (s *Store) Wipe() error {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var first error
	for _, e := range entries {
		p := filepath.Join(s.Dir, e.Name())
		if e.IsDir() {
			if err := os.RemoveAll(p); err != nil && first == nil {
				first = err
			}
			continue
		}
		if err := shred(p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func shred(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for pass := 0; pass < 3; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			break
		}
		remaining := fi.Size()
		for remaining > 0 {
			n := int64(len(buf))
			if remaining < n {
				n = remaining
			}
			_, _ = rand.Read(buf[:n])
			if _, err := f.Write(buf[:n]); err != nil {
				break
			}
			remaining -= n
		}
		_ = f.Sync()
	}
	_ = f.Close()
	return os.Remove(path)
}

// Status is the live view published for the TTY (never contains secrets).
type Status struct {
	UpdatedAt     time.Time       `json:"updated_at"`
	Version       string          `json:"version"`
	BundleVersion string          `json:"bundle_version"`
	State         string          `json:"state"`
	ApplianceID   string          `json:"appliance_id"`
	CPURL         string          `json:"cp_url"`
	Reachable     bool            `json:"reachable"`
	LastError     string          `json:"last_error,omitempty"`
	LastHeartbeat *time.Time      `json:"last_heartbeat,omitempty"`
	SkewS         int64           `json:"skew_s"`
	IntervalS     int             `json:"interval_s"`
	Ifaces        []v1.Iface      `json:"ifaces"`
	CurrentJob    *v1.JobProgress `json:"current_job,omitempty"`
	StopAll       bool            `json:"stop_all"`
	CertNotAfter  *time.Time      `json:"cert_not_after,omitempty"`
	// Phase 2: engine health, feed version and spool backlog for the console.
	Engine         v1.EngineHealth `json:"engine"`
	FeedVersion    string          `json:"feed_version,omitempty"`
	PendingResults int             `json:"pending_results"`
}

func (s *Store) WriteStatus(st *Status) error {
	if err := os.MkdirAll(s.RunDir, 0o755); err != nil {
		return err
	}
	st.UpdatedAt = time.Now()
	b, _ := json.MarshalIndent(st, "", "  ")
	return atomicWrite(filepath.Join(s.RunDir, "status.json"), b, 0o644)
}

func (s *Store) ReadStatus() (*Status, error) {
	b, err := os.ReadFile(filepath.Join(s.RunDir, "status.json"))
	if err != nil {
		return nil, err
	}
	st := &Status{}
	return st, json.Unmarshal(b, st)
}

// Touch signals the daemon that state.json changed (TTY → daemon IPC via files).
func (s *Store) Touch(name string) error {
	if err := os.MkdirAll(s.RunDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.RunDir, name), []byte(time.Now().Format(time.RFC3339)), 0o644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
