// Package e2e drives the real daemon loop against the real control-plane
// server in-process: the Phase 1 definition of done (PLAN §20) minus the
// hypervisor.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/server"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/support"
	"github.com/tprm/scanner-appliance/daemon/internal/tty"
)

func TestPhase1(t *testing.T) {
	pkiDir := t.TempDir()
	if err := ca.Init(pkiDir, "E2E"); err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.Load(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := issuer.IssueServer([]string{"127.0.0.1"})
	serverCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	roots := x509.NewCertPool()
	rootPEM, _ := os.ReadFile(pkiDir + "/root.pem")
	roots.AppendCertsFromPEM(rootPEM)

	mem := store.NewMemory()
	mtls := httptest.NewUnstartedServer(nil)
	mtls.TLS = server.TLSConfigMTLS(serverCert, issuer)
	srv := server.New(server.Config{Store: mem, CA: issuer, PublicURL: "", AdminToken: "tok", Logger: slog.Default()})
	mtls.Config.Handler = srv.MTLSHandler()
	mtls.StartTLS()
	defer mtls.Close()
	// PublicURL must be the real listener address; rebuild the server with it.
	srv = server.New(server.Config{Store: mem, CA: issuer, PublicURL: mtls.URL, AdminToken: "tok", Logger: slog.Default()})
	mtls.Config.Handler = srv.MTLSHandler()
	enrollSrv := httptest.NewUnstartedServer(srv.EnrollHandler())
	enrollSrv.TLS = server.TLSConfigEnroll(serverCert)
	enrollSrv.StartTLS()
	defer enrollSrv.Close()

	admin := func(method, path string, body, out any) int {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, mtls.URL+path, &buf)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}

	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Reno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}

	// Daemon side: seed with the code (as the OVF/volume/env path would), then run the loop.
	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.EnrollURL = enrollSrv.URL
	s.PendingCode = created.Code
	s.IntervalOverrideS = 1 // enrollment overwrites PollIntervalS with the server default (60 s)
	_ = st.Save(s)
	loop := &heartbeat.Loop{Store: st, Roots: roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go loop.Run(ctx)

	// DoD: enrolled + online.
	var view v1.AdminApplianceView
	waitFor(t, 20*time.Second, func() bool {
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
		return view.Status == v1.StatusEnrolled && view.Online
	}, "appliance online")
	if view.LastHeartbeat == nil || view.LastHeartbeat.State != heartbeat.StateIdle || view.Fingerprint == nil {
		t.Fatalf("heartbeat content: %+v", view)
	}
	local, _ := st.Load()
	if local.PendingCode != "" || !local.SeedConsumed || local.CPURL != mtls.URL || len(local.Site.AllowedCIDRs) != 1 {
		t.Fatalf("local state after enroll: %+v", local)
	}
	if _, err := st.Certificate(); err != nil {
		t.Fatal(err)
	}

	// DoD: stop_all and set_interval acked on the next heartbeat.
	var d1, d2 v1.AdminDirectiveView
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "set_interval", Payload: map[string]any{"s": 10.0}}, &d1)
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "stop_all"}, &d2)
	waitFor(t, 45*time.Second, func() bool {
		var list []v1.AdminDirectiveView
		admin("GET", "/admin/appliances/"+created.ApplianceID+"/directives", nil, &list)
		acked := 0
		for _, d := range list {
			if d.AckedAt != nil {
				acked++
			}
		}
		return acked == 2
	}, "directives acked")
	local, _ = st.Load()
	if !local.StopAll || local.IntervalOverrideS != 10 {
		t.Fatalf("directives not applied locally: %+v", local)
	}
	live, _ := st.ReadStatus()
	if live == nil || !live.StopAll || live.IntervalS != 10 || !live.Reachable {
		t.Fatalf("status.json: %+v", live)
	}

	// DoD: support bundle uploads over mTLS.
	ack, err := support.Upload(ctx, st, roots, "e2e")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ack.ObjectKey, "support/"+created.ApplianceID+"/") || ack.Bytes == 0 {
		t.Fatalf("support ack: %+v", ack)
	}

	// Console status screen reflects the live daemon.
	var out bytes.Buffer
	c := &tty.Console{In: strings.NewReader("1\n"), Out: &out, Store: st, Roots: roots, Version: "e2e", Idle: time.Second, PowerOff: func() error { return nil }}
	_ = c.Run(ctx)
	if !strings.Contains(out.String(), "Enrolled:        yes ("+created.ApplianceID+")") || !strings.Contains(out.String(), "STOP_ALL:        active") {
		t.Fatalf("console:\n%s", out.String())
	}

	// Wipe directive with the right token: control plane marks wiped + revokes; local state gone.
	var poweredOff atomic.Bool
	loop.PowerOff = func() error { poweredOff.Store(true); return nil }
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "wipe", Payload: map[string]any{"confirm_token": created.ApplianceID}}, nil)
	waitFor(t, 30*time.Second, func() bool {
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
		return view.Status == v1.StatusWiped
	}, "wiped on control plane")
	waitFor(t, 10*time.Second, func() bool { return poweredOff.Load() && !st.Enrolled() }, "local wipe + poweroff")
	if rev, _ := mem.IsRevoked(ctx, view.CertSerial); !rev {
		t.Fatal("serial not revoked after wipe")
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
