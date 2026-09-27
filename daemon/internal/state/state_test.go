package state

import (
	"os"
	"runtime"
	"testing"
)

func TestKeyCSRStateWipe(t *testing.T) {
	s := New(t.TempDir(), t.TempDir())
	k1, err := s.Key()
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := s.Key()
	if !k1.Equal(k2) {
		t.Fatal("key not stable across loads")
	}
	fi, _ := os.Stat(s.path("key.pem"))
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // NTFS has no POSIX mode bits
		t.Fatalf("key perms %o", fi.Mode().Perm())
	}
	csr, err := s.CSR()
	if err != nil || len(csr) == 0 {
		t.Fatal(err)
	}
	st, _ := s.Load()
	st.PendingCode = "X"
	st.Proxy = "proxy:3128"
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	st2, _ := s.Load()
	if st2.Proxy != "proxy:3128" || st2.PendingCode != "X" {
		t.Fatalf("roundtrip: %+v", st2)
	}
	if s.Enrolled() {
		t.Fatal("should not be enrolled")
	}
	if err := s.Wipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path("key.pem")); !os.IsNotExist(err) {
		t.Fatal("key survived wipe")
	}
	st3, _ := s.Load()
	if st3.Proxy != "" {
		t.Fatal("state survived wipe")
	}
}
