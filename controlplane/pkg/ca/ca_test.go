package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestInitLoadIssue(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "TestOrg"); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "TestOrg"); err == nil {
		t.Fatal("expected refusal to overwrite")
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	iss, err := c.IssueAppliance(csrPEM, "apl_1", "vnd_1", "site_1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(iss.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.CommonName != "apl_1" || len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:tprm:appliance:vnd_1:site_1:apl_1" {
		t.Fatalf("bad subject/SAN: %v %v", cert.Subject, cert.URIs)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: c.ClientPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify against intermediate pool: %v", err)
	}
	// P-384 keys are rejected for appliances.
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k384)
	if _, err := c.IssueAppliance(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der384})), "a", "v", "s"); err == nil {
		t.Fatal("expected P-384 rejection")
	}
	certPEM, keyPEM, err := c.IssueServer([]string{"localhost", "127.0.0.1"})
	if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("server cert: %v", err)
	}
}
