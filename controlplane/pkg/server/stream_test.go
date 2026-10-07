package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/internal/bundle"
)

// The mTLS listener ends a response WriteTimeout after the request was
// read. A download has to outlive that for as long as it keeps moving: the
// manifest of the full feed is 16 MB and takes over two minutes on a
// 1 Mbit/s link. The appliance speaks HTTP/2 to the control plane; both
// protocols are covered.
func TestDownloadOutlivesWriteTimeout(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	h.enrolled(t)

	// Far larger than the socket buffers and the HTTP/2 flow-control
	// windows, so the server is still writing when the timeout passes.
	blob := bytes.Repeat([]byte("0123456789abcdef"), 4<<20)
	sum := sha256.Sum256(blob)
	sha := hex.EncodeToString(sum[:])
	if st, body, _ := h.rawAdmin(t, "PUT", "/admin/bundles/files/"+sha, blob, nil); st != 201 {
		t.Fatalf("put file: %d %s", st, body)
	}
	certPEM, keyPEM, err := h.ca.IssueServer([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	const writeTimeout = 300 * time.Millisecond
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		ts := httptest.NewUnstartedServer(h.srv.MTLSHandler())
		ts.TLS = TLSConfigMTLS(serverCert, h.ca)
		ts.EnableHTTP2 = proto == "HTTP/2.0"
		ts.Config.WriteTimeout = writeTimeout
		ts.StartTLS()
		cl := &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: h.rootPool, Certificates: []tls.Certificate{h.applCert}},
			ForceAttemptHTTP2: proto == "HTTP/2.0",
		}}
		resp, err := cl.Get(ts.URL + "/v1/bundles/20261006T000000Z/files/" + sha)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if resp.Proto != proto {
			t.Fatalf("negotiated %s, want %s", resp.Proto, proto)
		}
		// Read a little, then stay away for longer than the write timeout.
		got := sha256.New()
		if _, err := io.CopyN(got, resp.Body, 1<<20); err != nil {
			t.Fatalf("%s: first megabyte: %v", proto, err)
		}
		time.Sleep(4 * writeTimeout)
		n, err := io.Copy(got, resp.Body)
		_ = resp.Body.Close()
		if err != nil || n+1<<20 != int64(len(blob)) {
			t.Fatalf("%s: download cut after %d of %d bytes: %v", proto, n+1<<20, len(blob), err)
		}
		if hex.EncodeToString(got.Sum(nil)) != sha {
			t.Fatalf("%s: content differs", proto)
		}
		ts.Close()
	}
}
