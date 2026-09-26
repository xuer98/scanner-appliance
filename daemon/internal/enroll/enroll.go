// Package enroll performs first-boot enrollment and certificate renewal (PLAN §7).
package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/cpclient"
	"github.com/tprm/scanner-appliance/daemon/internal/fingerprint"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// Options for Enroll.
type Options struct {
	EnrollURL string // base URL of the no-client-cert listener
	Code      string
	Proxy     string
	Version   string
	Roots     *x509.CertPool
}

// ValidateCode is the console-side check before we hit the network.
func ValidateCode(code string) error {
	n := 0
	for _, r := range strings.ToUpper(code) {
		switch {
		case r == '-' || r == ' ':
		case (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z'):
			n++
		default:
			return fmt.Errorf("code contains an invalid character %q", r)
		}
	}
	if n != 20 {
		return fmt.Errorf("code must have 20 characters (got %d)", n)
	}
	return nil
}

// Enroll generates the key on first use, sends the CSR, and persists the
// result. On success the pending code is zeroed from state (PLAN §5).
func Enroll(ctx context.Context, st *state.Store, o Options) (*v1.EnrollResponse, error) {
	if err := ValidateCode(o.Code); err != nil {
		return nil, err
	}
	if o.EnrollURL == "" {
		return nil, errors.New("no control plane URL configured")
	}
	csr, err := st.CSR()
	if err != nil {
		return nil, fmt.Errorf("key/csr: %w", err)
	}
	cl, err := cpclient.New(cpclient.Options{Roots: o.Roots, Proxy: o.Proxy, Timeout: 45 * time.Second})
	if err != nil {
		return nil, err
	}
	resp, err := cl.Enroll(ctx, o.EnrollURL, v1.EnrollRequest{
		Code: strings.TrimSpace(o.Code), CSRPEM: csr, Version: o.Version, Fingerprint: fingerprint.Collect(),
	})
	if err != nil {
		return nil, err
	}
	if err := persist(st, resp, o.EnrollURL, true); err != nil {
		return nil, err
	}
	return resp, nil
}

// Renew replaces the certificate over mTLS using the existing key.
func Renew(ctx context.Context, st *state.Store, roots *x509.CertPool, version string) error {
	s, err := st.Load()
	if err != nil {
		return err
	}
	cert, err := st.Certificate()
	if err != nil {
		return err
	}
	csr, err := st.CSR()
	if err != nil {
		return err
	}
	cl, err := cpclient.New(cpclient.Options{Roots: roots, Proxy: s.Proxy, ClientCert: cert})
	if err != nil {
		return err
	}
	resp, err := cl.Renew(ctx, s.CPURL, v1.RenewRequest{CSRPEM: csr, Version: version})
	if err != nil {
		return err
	}
	return persist(st, resp, "", false)
}

func persist(st *state.Store, resp *v1.EnrollResponse, enrollURL string, first bool) error {
	if err := st.SaveCertificate(resp.CertPEM, resp.ChainPEM); err != nil {
		return fmt.Errorf("store cert: %w", err)
	}
	cert, err := st.Certificate()
	if err != nil {
		return fmt.Errorf("issued cert unusable: %w", err)
	}
	s, err := st.Load()
	if err != nil {
		return err
	}
	now := time.Now()
	s.ApplianceID = resp.ApplianceID
	if resp.CPURL != "" {
		s.CPURL = resp.CPURL
	}
	if enrollURL != "" {
		s.EnrollURL = enrollURL
	}
	s.PollIntervalS = resp.PollIntervalS
	s.Site = resp.Site
	if resp.SpoolPubKey != "" {
		s.SpoolPubKey, s.SpoolKID = resp.SpoolPubKey, resp.SpoolKID
	}
	na := cert.Leaf.NotAfter
	s.CertNotAfter = &na
	if first {
		s.EnrolledAt = &now
		s.PendingCode = ""
		s.SeedConsumed = true
	}
	if err := st.Save(s); err != nil {
		return err
	}
	writeTimeSourceHint(s.CPURL, s.Proxy)
	return nil
}

// Paths harden.sh wires up for htpdate (PLAN §8.3): a .path unit restarts
// htpdate when either file changes.
var (
	CPFQDNPath      = "/etc/appliance/cp-fqdn"
	HTPDateConfPath = "/etc/htpdate.conf"
)

// writeTimeSourceHint points htpdate at the control plane. Best effort: on a
// container or dev box /etc/appliance does not exist and nothing happens.
func writeTimeSourceHint(cpURL, proxy string) {
	if cpURL == "" {
		return
	}
	u, err := url.Parse(cpURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	if _, err := os.Stat(filepath.Dir(CPFQDNPath)); err != nil {
		return
	}
	_ = os.WriteFile(CPFQDNPath, []byte(u.Hostname()+"\n"), 0o644)
	hp := ""
	if pu, err := cpclient.ProxyURL(proxy); err == nil && pu != nil {
		hp = pu.Host // htpdate -P takes host:port; credentials are not supported there
	}
	conf := "# written by applianced after enrollment\nHTP_PROXY=\"" + hp + "\"\nHTP_OPTIONS=\"-s -l\"\n"
	if _, err := os.Stat(HTPDateConfPath); err == nil {
		_ = os.WriteFile(HTPDateConfPath, []byte(conf), 0o644)
	}
}

// NeedsRenewal is true past two thirds of the certificate lifetime (PLAN §7.3).
func NeedsRenewal(leaf *x509.Certificate, now time.Time) bool {
	if leaf == nil {
		return false
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return now.After(leaf.NotBefore.Add(life * 2 / 3))
}
