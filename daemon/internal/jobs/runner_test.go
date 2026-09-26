package jobs

import (
	"context"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/internal/seal"
)

type fakeControl struct {
	mu       sync.Mutex
	next     *v1.JobsResponse
	statuses []v1.JobStatusRequest
	uploads  int
}

func (f *fakeControl) Jobs(context.Context, string, string) (*v1.JobsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.next
	f.next = nil
	return r, nil
}

func (f *fakeControl) JobStatus(_ context.Context, _, _ string, st v1.JobStatusRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, st)
	return nil
}

func (f *fakeControl) UploadResults(context.Context, string, string, int, bool, string, []byte) (*v1.ResultAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads++
	return &v1.ResultAck{}, nil
}

func (f *fakeControl) last() v1.JobStatusRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) == 0 {
		return v1.JobStatusRequest{}
	}
	return f.statuses[len(f.statuses)-1]
}

func TestPollRejectsAndRuns(t *testing.T) {
	pkiDir := t.TempDir()
	if err := ca.Init(pkiDir, "T"); err != nil {
		t.Fatal(err)
	}
	issuer, _ := ca.Load(pkiDir)
	roots := x509.NewCertPool()
	rootPEM, _ := os.ReadFile(filepath.Join(pkiDir, "root.pem"))
	roots.AppendCertsFromPEM(rootPEM)
	spoolKey, _ := seal.GenerateKey()

	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.ApplianceID, s.CPURL, s.SpoolPubKey = "apl_1", "https://cp.test", seal.EncodePublic(spoolKey.PublicKey())
	_ = st.Save(s)
	csr, _ := st.CSR()
	issued, err := issuer.IssueAppliance(csr, "apl_1", "vnd_1", "site_1")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SaveCertificate(issued.CertPEM, issuer.ChainPEM())

	naabu := filepath.Join(t.TempDir(), "naabu")
	_ = os.WriteFile(naabu, []byte("#!/bin/sh\nprintf '%s\\n' 10.30.5.20\n"), 0o755)
	now := time.Now
	r := &Runner{Store: st, Roots: roots, Log: slog.Default(), Now: now, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")},
		Engine: &engine.Engine{NaabuPath: naabu, Log: slog.Default(), PollInterval: 10 * time.Millisecond}}
	site := v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}, MaxPPS: 300, MaxConcurrency: 16, TZ: "UTC"}
	sign := func(spec v1.JobSpec) v1.JobSpec {
		spec.Sig = ""
		b, _ := spec.SigningBytes()
		spec.Sig, _ = issuer.SignJob(b)
		return spec
	}
	base := func(mode string) v1.JobSpec {
		spec := v1.JobSpec{JobID: "job_" + mode, SiteID: "site_1", ApplianceID: "apl_1", Targets: []string{"10.30.5.0/24"}, SafeChecks: true, IssuedAt: now().Unix()}
		spec.DefaultsFor(mode)
		return spec
	}
	ready := v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}
	ctx := context.Background()

	cases := []struct {
		name  string
		spec  v1.JobSpec
		site  v1.SiteConfig
		eng   v1.EngineHealth
		stop  bool
		check string
	}{
		{name: "unsigned", spec: func() v1.JobSpec { s := base("discovery"); s.Sig = ""; return s }(), site: site, eng: ready, check: CheckSignature},
		{name: "tampered", spec: func() v1.JobSpec { s := sign(base("discovery")); s.Targets = []string{"10.30.9.0/24"}; return s }(), site: site, eng: ready, check: CheckSignature},
		{name: "stale", spec: func() v1.JobSpec {
			s := base("discovery")
			s.IssuedAt = now().Add(-3 * time.Hour).Unix()
			return sign(s)
		}(), site: site, eng: ready, check: CheckSignature},
		{name: "other appliance", spec: func() v1.JobSpec { s := base("discovery"); s.ApplianceID = "apl_2"; return sign(s) }(), site: site, eng: ready, check: CheckAppliance},
		{name: "out of scope", spec: sign(base("discovery")), site: v1.SiteConfig{AllowedCIDRs: []string{"10.31.0.0/16"}}, eng: ready, check: "scope"},
		{name: "engine down", spec: sign(base("inventory")), site: site, eng: v1.EngineHealth{}, check: CheckEngine},
		{name: "stop_all", spec: sign(base("discovery")), site: site, eng: ready, stop: true, check: CheckStopAll},
	}
	for _, c := range cases {
		fc := &fakeControl{next: &v1.JobsResponse{Job: c.spec, Site: c.site}}
		s, _ := st.Load()
		s.StopAll = c.stop
		_ = st.Save(s)
		r.Poll(ctx, fc, s, c.eng)
		r.Wait()
		last := fc.last()
		if last.Status != v1.JobRejected || last.Check != c.check {
			t.Fatalf("%s: got %+v want rejected/%s", c.name, last, c.check)
		}
	}

	// A valid discovery job runs, spools and uploads, then reports done.
	s, _ = st.Load()
	s.StopAll = false
	_ = st.Save(s)
	fc := &fakeControl{next: &v1.JobsResponse{Job: sign(base("discovery")), Site: site}}
	r.Poll(ctx, fc, s, ready)
	if r.Idle() {
		t.Fatal("job did not start")
	}
	if p := r.Progress(); p == nil || p.ID != "job_discovery" {
		t.Fatalf("progress: %+v", p)
	}
	r.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fc.last().Status != v1.JobDone {
		time.Sleep(20 * time.Millisecond)
	}
	if fc.last().Status != v1.JobDone || fc.uploads == 0 || r.Pending() != 0 || len(r.Spool.Jobs()) != 0 {
		t.Fatalf("run: last=%+v uploads=%d pending=%d jobs=%v", fc.last(), fc.uploads, r.Pending(), r.Spool.Jobs())
	}
	if !strings.Contains(strings.Join(statusNames(fc), ","), "running") {
		t.Fatalf("no running report: %+v", fc.statuses)
	}
}

func statusNames(fc *fakeControl) []string {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var out []string
	for _, s := range fc.statuses {
		out = append(out, s.Status)
	}
	return out
}
