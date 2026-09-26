// Package ca is the internal certificate authority for appliances.
//
// Layout on disk (pki-dir):
//
//	root.pem              root CA certificate (public; embedded in applianced)
//	root-key.pem          root private key — only present where `ca init` ran;
//	                      in production the root is offline and this file is absent
//	intermediate.pem      appliance-issuing intermediate certificate
//	intermediate-key.pem  intermediate private key (online, used by cp-api)
//
// This is the "~200-line Go issuer" option from PLAN §7.1.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	rootValidity         = 20 * 365 * 24 * time.Hour
	intermediateValidity = 5 * 365 * 24 * time.Hour
	// ApplianceValidity is the lifetime of an appliance certificate (PLAN §7.1).
	ApplianceValidity = 365 * 24 * time.Hour
	serverValidity    = 2 * 365 * 24 * time.Hour
)

// CA is an online issuer backed by the intermediate.
type CA struct {
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	key          *ecdsa.PrivateKey
	chainPEM     []byte // intermediate PEM (what appliances send as chain)
}

// Init creates a fresh root + intermediate under dir. It refuses to overwrite.
func Init(dir, orgName string) error {
	if _, err := os.Stat(filepath.Join(dir, "root.pem")); err == nil {
		return fmt.Errorf("%s already contains root.pem; refusing to overwrite", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{Organization: []string{orgName}, CommonName: orgName + " Appliance Root CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(rootValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{Organization: []string{orgName}, CommonName: orgName + " Appliance Issuing CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(intermediateValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "root.pem"), "CERTIFICATE", rootDER, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "root-key.pem"), rootKey); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "intermediate.pem"), "CERTIFICATE", intDER, 0o644); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, "intermediate-key.pem"), intKey)
}

// Load opens the intermediate (and root, for chain verification) from dir.
func Load(dir string) (*CA, error) {
	root, err := readCert(filepath.Join(dir, "root.pem"))
	if err != nil {
		return nil, err
	}
	inter, err := readCert(filepath.Join(dir, "intermediate.pem"))
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(dir, "intermediate-key.pem"))
	if err != nil {
		return nil, err
	}
	// Sanity: the intermediate must chain to the root.
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := inter.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("intermediate does not chain to root: %w", err)
	}
	return &CA{
		Root: root, Intermediate: inter, key: key,
		chainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}),
	}, nil
}

// ChainPEM is the intermediate certificate in PEM, sent to appliances.
func (c *CA) ChainPEM() string { return string(c.chainPEM) }

// ClientPool is the pool used by the mTLS listener to verify appliance certs.
// It contains only the intermediate: the root is not needed and keeping it
// out means a cert signed directly by the root is not accepted for mTLS.
func (c *CA) ClientPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Intermediate)
	return p
}

// Issued is the result of signing an appliance CSR.
type Issued struct {
	CertPEM  string
	Serial   string // hex, lowercase, no leading zeros
	NotAfter time.Time
}

// IssueAppliance signs a CSR for the given appliance. The CSR's subject and
// SANs are ignored: CN and URI SAN are set from the control plane's record.
func (c *CA) IssueAppliance(csrPEM, applianceID, vendorID, siteID string) (*Issued, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("csr public key must be ECDSA P-256")
	}
	uri, _ := url.Parse(fmt.Sprintf("urn:tprm:appliance:%s:%s:%s", vendorID, siteID, applianceID))
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: applianceID, Organization: c.Intermediate.Subject.Organization},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(ApplianceValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Intermediate, pub, c.key)
	if err != nil {
		return nil, err
	}
	return &Issued{
		CertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Serial:   SerialHex(tmpl.SerialNumber),
		NotAfter: tmpl.NotAfter,
	}, nil
}

// IssueServer creates a server TLS certificate signed by the intermediate.
// Used in --dev so the appliance can trust the control plane via the pinned
// root; production uses a cert from whatever fronts the LB.
func (c *CA) IssueServer(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: hosts[0], Organization: c.Intermediate.Subject.Organization},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Intermediate, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.chainPEM...)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	return certPEM, keyPEM, nil
}

// ParseCSR decodes and signature-checks a PEM CSR.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	return csr, nil
}

// SerialHex renders a serial the way it is stored in the revoked set.
func SerialHex(n *big.Int) string { return n.Text(16) }

// SPKIFingerprint is the SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

func newSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func writeKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "EC PRIVATE KEY", der, 0o600)
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// SignJob signs a job spec's canonical bytes with the issuing key. The
// appliance verifies against the intermediate certificate it received as
// the chain at enrollment (PLAN §11, §16). The intermediate already carries
// KeyUsageDigitalSignature.
func (c *CA) SignJob(signingBytes []byte) (string, error) {
	digest := sha256.Sum256(signingBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
