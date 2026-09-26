// Package jobs polls for dispatched jobs, enforces the appliance-side
// guardrails (PLAN §11), runs the engine, spools results and reports
// status. Nothing here is reachable from the network: the control plane
// only ever answers polls.
package jobs

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// VerifySpec checks the job signature against the issuing CA chain the
// appliance received at enrollment (every chain certificate must itself
// chain to the pinned root) and the issued_at freshness (PLAN §11, §16).
func VerifySpec(spec v1.JobSpec, chain []*x509.Certificate, roots *x509.CertPool, now time.Time, fresh time.Duration) error {
	if spec.Sig == "" {
		return errors.New("job is unsigned")
	}
	if spec.IssuedAt == 0 {
		return errors.New("job has no issued_at")
	}
	if d := now.Sub(time.Unix(spec.IssuedAt, 0)); d > fresh || d < -fresh {
		return fmt.Errorf("job issued_at is stale by %s", d.Round(time.Second))
	}
	sig, err := base64.StdEncoding.DecodeString(spec.Sig)
	if err != nil {
		return fmt.Errorf("job signature is not base64: %w", err)
	}
	body, err := spec.SigningBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	if len(chain) == 0 {
		return errors.New("no issuing CA chain stored; re-enroll")
	}
	var last error
	for _, c := range chain {
		if !c.IsCA {
			continue
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			last = fmt.Errorf("chain certificate %q does not verify against the pinned root: %w", c.Subject.CommonName, err)
			continue
		}
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			last = errors.New("issuing CA key is not ECDSA")
			continue
		}
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil
		}
		last = errors.New("job signature does not verify")
	}
	return last
}
