package tty

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

func run(t *testing.T, st *state.Store, input string) string {
	t.Helper()
	var out bytes.Buffer
	c := &Console{In: strings.NewReader(input), Out: &out, Store: st, Version: "test", Idle: time.Second,
		ApplyNetwork: func(context.Context, state.Network) error { return nil },
		PowerOff:     func() error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Run(ctx); err != io.EOF {
		t.Fatalf("run: %v", err)
	}
	return out.String()
}

func TestMenuGrammar(t *testing.T) {
	st := state.New(t.TempDir(), t.TempDir())
	out := run(t, st, "9\n\n2\n1\n2\nnot-an-ip\n10.20.0.50/24\n10.20.0.1\n10.20.0.10 10.20.0.11\n\n0\n3\nbadproxy\n\n1\n")
	for _, want := range []string{"=== Scanner Appliance test — Status ===", "Unknown option \"9\"", "=== Scanner Appliance test — Network ===",
		"enter an IPv4 address with prefix length", "Applied to wan0", "proxy needs a port"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	s, _ := st.Load()
	if s.Network.WAN0 == nil || s.Network.WAN0.CIDR != "10.20.0.50/24" || len(s.Network.WAN0.DNS) != 2 {
		t.Fatalf("network not saved: %+v", s.Network.WAN0)
	}
}

func TestWipeRequiresID(t *testing.T) {
	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.ApplianceID = "apl_TEST"
	_ = st.Save(s)
	_, _ = st.Key()
	out := run(t, st, "6\nwrong\n\n")
	if !strings.Contains(out, "Did not match") {
		t.Fatalf("%s", out)
	}
	if k, _ := st.Load(); k.ApplianceID != "apl_TEST" {
		t.Fatal("state wiped without confirmation")
	}
	out = run(t, st, "6\napl_TEST\n")
	if !strings.Contains(out, "Powering off") {
		t.Fatalf("%s", out)
	}
	if st.Enrolled() {
		t.Fatal("still enrolled after wipe")
	}
}

func TestIdleReturnsToStatus(t *testing.T) {
	st := state.New(t.TempDir(), t.TempDir())
	pr, pw := io.Pipe()
	var out bytes.Buffer
	c := &Console{In: pr, Out: &out, Store: st, Version: "test", Idle: 200 * time.Millisecond, PowerOff: func() error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	_, _ = pw.Write([]byte("2\n"))
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done
	_ = pw.Close()
	if !strings.Contains(out.String(), "(idle)") || strings.Count(out.String(), "— Status ===") < 2 {
		t.Fatalf("idle handling:\n%s", out.String())
	}
}

func TestSupportBundleIsReviewedBeforeUpload(t *testing.T) {
	st := state.New(t.TempDir(), t.TempDir())
	out := run(t, st, "5\nn\n")
	for _, want := range []string{"Never included: the private key", "Contents:", "state.json", "meta.json", "Not uploaded."} {
		if !strings.Contains(out, want) {
			t.Fatalf("support screen missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Uploading") {
		t.Fatalf("uploaded without confirmation:\n%s", out)
	}
}
