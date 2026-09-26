package seal

import (
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "spool-key.pem")
	if err := SavePrivate(p, k); err != nil {
		t.Fatal(err)
	}
	k2, err := LoadPrivate(p)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic(EncodePublic(k.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	type doc struct {
		A string
		N int
	}
	b, err := SealJSON(pub, doc{"hello", 7}, AAD("job_1", 3))
	if err != nil {
		t.Fatal(err)
	}
	var out doc
	if err := OpenJSON(k2, b, AAD("job_1", 3), &out); err != nil || out.A != "hello" || out.N != 7 {
		t.Fatalf("open: %v %+v", err, out)
	}
	if err := OpenJSON(k2, b, AAD("job_1", 4), &out); err == nil {
		t.Fatal("wrong aad accepted")
	}
	other, _ := GenerateKey()
	if err := OpenJSON(other, b, AAD("job_1", 3), &out); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Tamper.
	b[len(b)-10] ^= 0x01
	if err := OpenJSON(k2, b, AAD("job_1", 3), &out); err == nil {
		t.Fatal("tampered envelope accepted")
	}
}
