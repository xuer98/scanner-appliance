package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

func TestBundleExcludesSecrets(t *testing.T) {
	st := state.New(t.TempDir(), t.TempDir())
	if _, err := st.Key(); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Load()
	s.PendingCode = "SECRET-CODE"
	s.Proxy = "user:hunter2@proxy:3128"
	_ = st.Save(s)
	var buf bytes.Buffer
	if err := Build(context.Background(), &buf, st, "test"); err != nil {
		t.Fatal(err)
	}
	gz, _ := gzip.NewReader(&buf)
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		b, _ := io.ReadAll(tr)
		if strings.Contains(string(b), "SECRET-CODE") || strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatalf("%s leaks a secret", h.Name)
		}
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "key.pem") || !strings.Contains(joined, "support/state.json") || !strings.Contains(joined, "support/meta.json") {
		t.Fatalf("entries: %v", names)
	}
}
