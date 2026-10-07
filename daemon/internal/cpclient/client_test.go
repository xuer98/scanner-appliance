package cpclient

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func downloadClient(t *testing.T, srv *httptest.Server, stall time.Duration) *Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	// The control-call timeout is far shorter than the transfers below: a
	// download must not be bound by it.
	c, err := New(Options{Roots: roots, Timeout: 100 * time.Millisecond, StallTimeout: stall})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A bundle manifest for the full feed is 16 MB. On a 1 Mbit/s link it
// takes over two minutes, and in the lab the 60 s limit that used to cover
// the whole request failed every such download. Slow is fine as long as
// bytes keep arriving.
func TestDownloadSlowButSteady(t *testing.T) {
	chunk := bytes.Repeat([]byte("x"), 1024)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 12; i++ {
			_, _ = w.Write(chunk)
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	c := downloadClient(t, srv, 2*time.Second)
	var buf bytes.Buffer
	start := time.Now()
	_, n, err := c.Download(t.Context(), srv.URL, "/v1/bundles/x/manifest", &buf, 1<<20)
	if err != nil {
		t.Fatalf("a slow download that keeps moving failed after %s: %v", time.Since(start), err)
	}
	if n != 12*1024 || buf.Len() != 12*1024 {
		t.Fatalf("got %d bytes", n)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("the transfer was not slower than the control-call timeout; the test proves nothing")
	}
}

func TestDownloadGivesUpOnAStall(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"body stops": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("start"))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		},
		"headers never come": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		},
	} {
		srv := httptest.NewTLSServer(handler)
		c := downloadClient(t, srv, 300*time.Millisecond)
		var buf bytes.Buffer
		start := time.Now()
		_, _, err := c.Download(t.Context(), srv.URL, "/v1/bundles/x/manifest", &buf, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "made no progress for 300ms") {
			t.Fatalf("%s: err = %v", name, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("%s: gave up only after %s", name, d)
		}
		srv.Close()
	}
}

func TestProxyURL(t *testing.T) {
	for in, want := range map[string]string{
		"proxy:3128":                      "http://proxy:3128",
		"user:pw@proxy.vendor.local:3128": "http://user:pw@proxy.vendor.local:3128",
		"http://p:8080":                   "http://p:8080",
		"":                                "",
	} {
		u, err := ProxyURL(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != want {
			t.Fatalf("%q → %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"proxy", "socks5://p:1080", "::"} {
		if _, err := ProxyURL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
