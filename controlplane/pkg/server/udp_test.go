package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

func TestUDPModuleJobs(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	target := []string{"10.30.5.0/24"}
	modules := func(req v1.AdminJobRequest) (string, int) {
		var job v1.AdminJobView
		st := h.admin("POST", "/admin/jobs", req, &job)
		return strings.Join(job.Spec.Modules, ","), st
	}

	// Off unless asked for; the shortcut appends it to the mode's defaults.
	if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: target}); st != 201 || strings.Contains(m, v1.ModuleUDP) {
		t.Fatalf("default full job: %d %q", st, m)
	}
	if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: target, UDP: true}); st != 201 || m != "discovery,portscan,openvas,web,udp" {
		t.Fatalf("full job with udp: %d %q", st, m)
	}
	if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: target, Modules: []string{"discovery", "portscan", "openvas", "udp"}, UDP: true}); st != 201 || m != "discovery,portscan,openvas,udp" {
		t.Fatalf("udp listed and flagged: %d %q", st, m)
	}
	// It belongs to the openvas phase: refused without it.
	if _, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeDiscovery, Targets: target, UDP: true}); st != 400 {
		t.Fatalf("discovery job with udp accepted: %d", st)
	}
	if _, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: target, Modules: []string{"discovery", "portscan", "udp"}}); st != 400 {
		t.Fatalf("udp without openvas accepted: %d", st)
	}
	// A schedule opts in through its module list.
	var sched v1.AdminScheduleView
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: created.ApplianceID, Name: "monthly udp", Mode: v1.ModeInventory, Targets: target,
		Cron: "0 22 1 * *", Modules: []string{"discovery", "portscan", "openvas", "udp"}}, &sched); st != 201 || strings.Join(sched.Modules, ",") != "discovery,portscan,openvas,udp" {
		t.Fatalf("schedule with udp: %d %+v", st, sched.Modules)
	}

	// Which findings a finished job may resolve.
	scopes := func(mode string, mods ...string) string {
		j := &store.Job{Spec: v1.JobSpec{Modules: mods}}
		j.Spec.DefaultsFor(mode)
		return strings.Join(jobScopes(j), ",")
	}
	if got := scopes(v1.ModeInventory); got != "inventory" {
		t.Fatalf("inventory scopes: %q", got)
	}
	if got := scopes(v1.ModeInventory, "discovery", "portscan", "openvas", "udp"); got != "inventory,inventory+udp" {
		t.Fatalf("inventory+udp scopes: %q", got)
	}
	if got := scopes(v1.ModeFull, "discovery", "portscan", "openvas", "web", "udp"); got != "inventory,full,inventory+udp,full+udp,web" {
		t.Fatalf("full+udp scopes: %q", got)
	}
}

func TestUDPFindingLifecycle(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	pub := h.srv.cfg.SpoolKey.PublicString()
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, VTCount: 10}})

	const ip = "10.30.5.40"
	tcp := v1.Port{Port: 53, Proto: "tcp", Service: "dns", Source: "naabu"}
	udp := v1.Port{Port: 161, Proto: "udp", Service: "snmp", Source: "openvas:find_service"}
	snmp := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.9002", Name: "SNMP finding", Family: "SNMP", Severity: "high", CVSS: 7.5, QoD: 99, Port: 161, Proto: "udp", CVE: []string{}}
	// run creates a job, lets the appliance take it and upload one final chunk.
	run := func(withUDP bool, host v1.Host) {
		t.Helper()
		var job v1.AdminJobView
		if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, UDP: withUDP}, &job); st != 201 {
			t.Fatalf("create job: %d", st)
		}
		if jr, st := h.pollJobs(t); st != 200 || jr.Job.JobID != job.ID || jr.Job.HasModule(v1.ModuleUDP) != withUDP {
			t.Fatalf("dispatch: %d", st)
		}
		batch := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "f1", StartedAt: 1, FinishedAt: 2, Seq: 1, Final: true,
			Stats: &v1.ScanStats{HostsAlive: 1, HostsScanned: 1, Findings: len(host.Findings), Rejected: []string{}}, Hosts: []v1.Host{host}}
		if st, ack, raw := h.upload(t, job.ID, batch, pub); st != 200 || !ack.Complete {
			t.Fatalf("upload: %d %s", st, raw)
		}
		h.now = h.now.Add(time.Hour)
	}
	state := func() (ports string, f *v1.AdminFindingView) {
		t.Helper()
		var hosts []v1.AdminHostView
		h.admin("GET", "/admin/sites/"+created.SiteID+"/hosts", nil, &hosts)
		for _, hv := range hosts {
			if hv.IP == ip {
				for _, p := range hv.Ports {
					ports += fmt.Sprintf("%d/%s ", p.Port, p.Proto)
				}
			}
		}
		var fs []v1.AdminFindingView
		h.admin("GET", "/admin/sites/"+created.SiteID+"/findings", nil, &fs)
		for i := range fs {
			if fs[i].Name == snmp.Name {
				f = &fs[i]
			}
		}
		return strings.TrimSpace(ports), f
	}

	// A job with the udp module finds SNMP on a UDP port.
	run(true, v1.Host{IP: ip, Notes: []string{v1.NoteUDPTested}, Ports: []v1.Port{tcp, udp}, Findings: []v1.Finding{snmp}})
	if ports, f := state(); ports != "53/tcp 161/udp" || f == nil || f.Scope != v1.UDPScope(v1.ScopeInventory) || f.Status != v1.FindingOpen {
		t.Fatalf("after the udp job: ports=%q finding=%+v", ports, f)
	}
	// The weekly job without it tested no UDP port: nothing changes.
	run(false, v1.Host{IP: ip, Ports: []v1.Port{tcp}, Findings: []v1.Finding{}})
	if ports, f := state(); ports != "53/tcp 161/udp" || f == nil || f.Status != v1.FindingOpen {
		t.Fatalf("a job without udp changed udp results: ports=%q finding=%+v", ports, f)
	}
	// The next udp job finds SNMP gone: the port goes and the finding is fixed.
	run(true, v1.Host{IP: ip, Notes: []string{v1.NoteUDPTested}, Ports: []v1.Port{tcp}, Findings: []v1.Finding{}})
	if ports, f := state(); ports != "53/tcp" || f == nil || f.Status != v1.FindingFixed {
		t.Fatalf("after the second udp job: ports=%q finding=%+v", ports, f)
	}
}
