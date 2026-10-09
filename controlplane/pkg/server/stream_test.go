package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/internal/bundle"
)

// slowBody hands out half of b, waits, then hands out the rest.
type slowBody struct {
	b     []byte
	pause time.Duration
	off   int
	slept bool
}

func (s *slowBody) Read(p []byte) (int, error) {
	if s.off >= len(s.b) {
		return 0, io.EOF
	}
	end := len(s.b)
	if !s.slept {
		if s.off >= len(s.b)/2 {
			time.Sleep(s.pause)
			s.slept = true
		} else {
			end = len(s.b) / 2
		}
	}
	n := copy(p, s.b[s.off:end])
	s.off += n
	return n, nil
}

// The same deadline starts when a request's header is read, so an upload
// that takes longer than it was answered too late: the reply was cut and
// the client saw a TLS error for a request the server had carried out. In
// the lab that was the publish of the 16 MB manifest over a 1 Mbit/s link:
// "bad record MAC" after two minutes, with the bundle published.
func TestSlowUploadIsAnswered(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	certPEM, keyPEM, err := h.ca.IssueServer([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	const writeTimeout = 300 * time.Millisecond
	for i, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		ts := httptest.NewUnstartedServer(h.srv.MTLSHandler())
		ts.TLS = TLSConfigMTLS(serverCert, h.ca)
		ts.EnableHTTP2 = proto == "HTTP/2.0"
		ts.Config.WriteTimeout = writeTimeout
		ts.StartTLS()
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.rootPool}, ForceAttemptHTTP2: proto == "HTTP/2.0"}}
		blob := bytes.Repeat([]byte{byte('a' + i)}, 256<<10)
		sum := sha256.Sum256(blob)
		sha := hex.EncodeToString(sum[:])
		req, _ := http.NewRequest("PUT", ts.URL+"/admin/bundles/files/"+sha, &slowBody{b: blob, pause: 4 * writeTimeout})
		req.ContentLength = int64(len(blob))
		req.Header.Set("Authorization", "Bearer "+h.adminTok)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s: an upload slower than the write timeout got no answer: %v", proto, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var ack struct {
			SHA256 string `json:"sha256"`
			Size   int    `json:"size"`
		}
		if err != nil || resp.StatusCode != 201 || json.Unmarshal(body, &ack) != nil || ack.SHA256 != sha || ack.Size != len(blob) {
			t.Fatalf("%s: answer to a slow upload: %d %q %v", proto, resp.StatusCode, body, err)
		}
		if resp.Proto != proto {
			t.Fatalf("negotiated %s, want %s", resp.Proto, proto)
		}
		ts.Close()
	}
}

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
	h.srv.cfg.AptDir = t.TempDir()
	h.enrolled(t)

	// Far larger than the socket buffers and the HTTP/2 flow-control
	// windows, so the server is still writing when the timeout passes.
	blob := bytes.Repeat([]byte("0123456789abcdef"), 4<<20)
	sum := sha256.Sum256(blob)
	sha := hex.EncodeToString(sum[:])
	if st, body, _ := h.rawAdmin(t, "PUT", "/admin/bundles/files/"+sha, blob, nil); st != 201 {
		t.Fatalf("put file: %d %s", st, body)
	}
	// The same bytes as a package on the apt mirror, which the appliance's
	// unattended upgrades fetch over the same listener.
	if err := os.WriteFile(filepath.Join(h.srv.cfg.AptDir, "linux-image.deb"), blob, 0o644); err != nil {
		t.Fatal(err)
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
		for _, path := range []string{"/v1/bundles/20261006T000000Z/files/" + sha, "/apt/linux-image.deb"} {
			resp, err := cl.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("%s %s: %v", proto, path, err)
			}
			if resp.Proto != proto || resp.StatusCode != 200 {
				t.Fatalf("%s: negotiated %s, status %d", path, resp.Proto, resp.StatusCode)
			}
			// Read a little, then stay away for longer than the write timeout.
			got := sha256.New()
			if _, err := io.CopyN(got, resp.Body, 1<<20); err != nil {
				t.Fatalf("%s %s: first megabyte: %v", proto, path, err)
			}
			time.Sleep(4 * writeTimeout)
			n, err := io.Copy(got, resp.Body)
			_ = resp.Body.Close()
			if err != nil || n+1<<20 != int64(len(blob)) {
				t.Fatalf("%s %s: download cut after %d of %d bytes: %v", proto, path, n+1<<20, len(blob), err)
			}
			if hex.EncodeToString(got.Sum(nil)) != sha {
				t.Fatalf("%s %s: content differs", proto, path)
			}
		}
		ts.Close()
	}
}

// A request that takes the server longer than the write timeout to carry
// out is answered all the same. In the lab that was a publish whose check
// of 105,000 digests ran against a database behind a slow link. This is
// HTTP/1.1, which the admin client speaks: HTTP/2 resets the stream when
// the deadline passes, whatever the handler is doing.
func TestSlowRequestIsAnswered(t *testing.T) {
	h := newHarness(t)
	certPEM, keyPEM, err := h.ca.IssueServer([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	const writeTimeout = 300 * time.Millisecond
	slow := http.NewServeMux()
	slow.HandleFunc("GET /answer", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(4 * writeTimeout)
		writeJSON(w, http.StatusCreated, map[string]string{"published": "20261007T233000Z"})
	})
	slow.HandleFunc("GET /nothing", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(4 * writeTimeout)
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewUnstartedServer(logging(h.srv.log, h.srv.stall(), slow))
	ts.TLS = TLSConfigEnroll(serverCert)
	ts.Config.WriteTimeout = writeTimeout
	ts.StartTLS()
	defer ts.Close()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.rootPool}}}
	resp, err := cl.Get(ts.URL + "/answer")
	if err != nil {
		t.Fatalf("a request slower than the write timeout got no answer: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 201 || !bytes.Contains(body, []byte("20261007T233000Z")) || resp.Proto != "HTTP/1.1" {
		t.Fatalf("answer: %d %q %v (%s)", resp.StatusCode, body, err, resp.Proto)
	}
	resp, err = cl.Get(ts.URL + "/nothing")
	if err != nil {
		t.Fatalf("a slow request without a body in its answer got none: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d, want 204", resp.StatusCode)
	}
}

// The stall time is the only limit on a download: one that takes several
// times as long but keeps moving arrives whole, and one that stops moving
// is ended, so a reader that went away does not hold the connection.
func TestDownloadLastsWhileItMoves(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	// A second: short enough to try, long enough that a busy CI runner
	// pausing either side does not look like a stalled reader.
	const stall = time.Second
	h.srv.cfg.StreamStall = stall
	h.enrolled(t)
	// Far larger than the socket buffers and the HTTP/2 flow-control
	// windows: the server cannot hand it all to the kernel and be done.
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
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		ts := httptest.NewUnstartedServer(h.srv.MTLSHandler())
		ts.TLS = TLSConfigMTLS(serverCert, h.ca)
		ts.EnableHTTP2 = proto == "HTTP/2.0"
		ts.Config.WriteTimeout = stall
		ts.StartTLS()
		cl := &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: h.rootPool, Certificates: []tls.Certificate{h.applCert}},
			ForceAttemptHTTP2: proto == "HTTP/2.0",
		}}
		url := ts.URL + "/v1/bundles/20261006T000000Z/files/" + sha

		// A megabyte every 35 ms: over two seconds for the whole of it,
		// more than twice the stall time, and never a pause near it.
		resp, err := cl.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		start := time.Now()
		got := sha256.New()
		var n int64
		for {
			m, err := io.CopyN(got, resp.Body, 1<<20)
			n += m
			if err != nil {
				break
			}
			time.Sleep(35 * time.Millisecond)
		}
		_ = resp.Body.Close()
		if n != int64(len(blob)) || hex.EncodeToString(got.Sum(nil)) != sha {
			t.Fatalf("%s: a download that kept moving was cut after %d of %d bytes and %s", proto, n, len(blob), time.Since(start).Round(time.Millisecond))
		}
		if took := time.Since(start); took < 2*stall {
			t.Fatalf("%s: the download took %s, not long enough to outlast the stall time of %s", proto, took.Round(time.Millisecond), stall)
		}

		// The reader goes away for twice the stall time.
		resp, err = cl.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if _, err := io.CopyN(io.Discard, resp.Body, 1<<20); err != nil {
			t.Fatalf("%s: first megabyte: %v", proto, err)
		}
		time.Sleep(2 * stall)
		rest, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err == nil && rest+1<<20 == int64(len(blob)) {
			t.Fatalf("%s: a download that stood still for %s was kept open", proto, 2*stall)
		}
		ts.Close()
	}
}
