package engine

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// webFakes writes shell scripts standing in for naabu (one host with an
// HTTP port), httpx (one live URL) and nuclei (two matches, one below the
// severity floor) and logs their arguments.
func webFakes(t *testing.T, logDir string) (naabu, httpx, nuclei string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fakes are POSIX shell scripts")
	}
	write := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	naabu = write("naabu", `#!/bin/sh
case " $* " in
  *" -sn "*) printf '%s\n' 10.30.5.20 ;;
  *) printf '%s\n' '{"ip":"10.30.5.20","port":8080,"protocol":"tcp"}' '{"ip":"10.30.5.20","port":3389,"protocol":"tcp"}' ;;
esac
`)
	httpx = write("httpx", `#!/bin/sh
echo "$@" >> "`+logDir+`/httpx.args"
list=""
while [ $# -gt 0 ]; do [ "$1" = "-l" ] && list="$2"; shift; done
cat "$list" >> "`+logDir+`/httpx.in"
printf '%s\n' '{"url":"http://10.30.5.20:8080","input":"10.30.5.20:8080","host":"10.30.5.20","port":"8080","scheme":"http","status_code":200,"title":"Warehouse WMS","webserver":"Apache/2.4.57","tech":["Apache HTTP Server:2.4.57","PHP"]}'
printf '%s\n' '{"url":"https://10.30.5.20:8080","input":"10.30.5.20:8080","host":"10.30.5.20","port":"8080","failed":true}'
`)
	nuclei = write("nuclei", `#!/bin/sh
echo "$@" >> "`+logDir+`/nuclei.args"
printf '%s\n' '{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 path traversal","severity":"critical","tags":["cve","apache","rce"],"classification":{"cve-id":["CVE-2021-41773"],"cvss-score":9.8},"remediation":"Upgrade Apache"},"type":"http","host":"http://10.30.5.20:8080","port":"8080","matched-at":"http://10.30.5.20:8080/cgi-bin/.%2e/etc/passwd","matcher-name":"passwd"}'
printf '%s\n' '{"template-id":"tech-detect","info":{"name":"Wappalyzer","severity":"info","tags":"tech"},"type":"http","host":"http://10.30.5.20:8080","matched-at":"http://10.30.5.20:8080"}'
printf '%s\n' '{"template-id":"CVE-2021-41773","info":{"name":"dupe","severity":"critical"},"type":"http","host":"http://10.30.5.20:8080","matched-at":"http://10.30.5.20:8080/other"}'
`)
	return naabu, httpx, nuclei
}

type webSink struct{ batches []v1.ResultBatch }

func (s *webSink) Emit(_ context.Context, b v1.ResultBatch) error {
	s.batches = append(s.batches, b)
	return nil
}
func (s *webSink) Progress(Progress) {}

func TestWebAddon(t *testing.T) {
	logDir := t.TempDir()
	naabu, httpx, nuclei := webFakes(t, logDir)
	bundleDir := t.TempDir()
	tpl := filepath.Join(bundleDir, "nuclei-templates", "http", "cves")
	_ = os.MkdirAll(tpl, 0o755)
	_ = os.WriteFile(filepath.Join(tpl, "x.yaml"), []byte("id: x\n"), 0o644)
	e := &Engine{NaabuPath: naabu, HTTPXPath: httpx, NucleiPath: nuclei, BundleDir: bundleDir, Log: slog.Default(),
		Now: time.Now, PollInterval: 10 * time.Millisecond, IfaceExists: func(string) bool { return false }}
	spec := v1.JobSpec{JobID: "job_web", SiteID: "site_1", ApplianceID: "apl_1", Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"},
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleWeb}, Ports: "standard", Rate: v1.Rate{PPS: 300, PerHostParallel: 2},
		Web: &v1.WebParams{MinSeverity: v1.SeverityMedium, ExcludeTags: []string{"dos"}}}
	sink := &webSink{}
	stats, err := e.Run(t.Context(), spec, v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Warnings) != 0 {
		t.Fatalf("warnings: %v", stats.Warnings)
	}
	final := sink.batches[len(sink.batches)-1]
	if !final.Final || len(final.Hosts) != 1 {
		t.Fatalf("final batch: %+v", final)
	}
	h := final.Hosts[0]
	var web *v1.Port
	for i := range h.Ports {
		if h.Ports[i].Port == 8080 {
			web = &h.Ports[i]
		}
	}
	if web == nil || web.Web == nil || web.Web.Title != "Warehouse WMS" || web.Web.Status != 200 || web.Service != "http" || web.Product != "Apache/2.4.57" || len(web.Web.Tech) != 2 {
		t.Fatalf("httpx fingerprint not attached: %+v", web)
	}
	if len(h.Findings) != 1 {
		t.Fatalf("findings (want the critical one, not info, not the dupe): %+v", h.Findings)
	}
	f := h.Findings[0]
	if f.Source != "nuclei" || f.ID != "CVE-2021-41773" || f.Severity != v1.SeverityCritical || f.CVSS != 9.8 || f.Port != 8080 || f.QoD != QoDWeb ||
		len(f.CVE) != 1 || f.CVE[0] != "CVE-2021-41773" || f.Solution != "Upgrade Apache" || !strings.Contains(f.Evidence, "/etc/passwd") || !strings.Contains(f.Evidence, "tags=cve,apache,rce") {
		t.Fatalf("finding: %+v", f)
	}
	if stats.Findings != 1 || stats.PhaseDurationS[PhaseWeb] < 0 {
		t.Fatalf("stats: %+v", stats)
	}
	// httpx only saw the HTTP-looking port; nuclei got the safety flags and the bundle templates.
	if in := read(t, filepath.Join(logDir, "httpx.in")); in != "10.30.5.20:8080\n" {
		t.Fatalf("httpx input: %q", in)
	}
	nargs := read(t, filepath.Join(logDir, "nuclei.args"))
	for _, want := range []string{"-no-interactsh", "-disable-update-check", "-exclude-tags dos,fuzz,intrusive", "-severity medium,high,critical", "-templates " + filepath.Join(bundleDir, "nuclei-templates")} {
		if !strings.Contains(nargs, want) {
			t.Fatalf("nuclei args missing %q: %s", want, nargs)
		}
	}
}

func TestWebAddonSkipsGracefully(t *testing.T) {
	logDir := t.TempDir()
	naabu, httpx, nuclei := webFakes(t, logDir)
	spec := v1.JobSpec{JobID: "job_web2", SiteID: "site_1", ApplianceID: "apl_1", Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"},
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleWeb}, Ports: "standard", Rate: v1.Rate{PPS: 300, PerHostParallel: 2}}
	// No tools: a warning, not a failure.
	e := &Engine{NaabuPath: naabu, Log: slog.Default(), IfaceExists: func(string) bool { return false }}
	stats, err := e.Run(t.Context(), spec, v1.SiteConfig{}, &webSink{})
	if err != nil || len(stats.Warnings) != 1 || !strings.Contains(stats.Warnings[0], "not installed") {
		t.Fatalf("no tools: %v %v", err, stats.Warnings)
	}
	// Tools but no bundled templates.
	e = &Engine{NaabuPath: naabu, HTTPXPath: httpx, NucleiPath: nuclei, BundleDir: t.TempDir(), Log: slog.Default(), IfaceExists: func(string) bool { return false }}
	stats, err = e.Run(t.Context(), spec, v1.SiteConfig{}, &webSink{})
	if err != nil || len(stats.Warnings) != 1 || !strings.Contains(stats.Warnings[0], "templates") {
		t.Fatalf("no templates: %v %v", err, stats.Warnings)
	}
	if _, err := os.Stat(filepath.Join(logDir, "httpx.args")); err == nil {
		t.Fatal("httpx ran without templates")
	}
}

func TestIsWebPortAndHostPort(t *testing.T) {
	for _, p := range []v1.Port{{Port: 8080, Proto: "tcp"}, {Port: 12345, Proto: "tcp", Service: "www"}, {Port: 12345, Proto: "tcp", Product: "Jetty HTTP server"}} {
		if !isWebPort(&p) {
			t.Fatalf("%+v not web", p)
		}
	}
	for _, p := range []v1.Port{{Port: 80, Proto: "udp"}, {Port: 3389, Proto: "tcp", Service: "ms-wbt-server"}} {
		if isWebPort(&p) {
			t.Fatalf("%+v web", p)
		}
	}
	h, p := hostPortOf(nucleiLine{Host: "https://10.30.5.21", MatchedAt: "https://10.30.5.21/login"})
	if h != "10.30.5.21" || p != 443 {
		t.Fatalf("%s %d", h, p)
	}
	h, p = hostPortOf(nucleiLine{Host: "http://10.30.5.21:8443", Port: "8443", MatchedAt: "http://10.30.5.21:8443/x?y=1"})
	if h != "10.30.5.21" || p != 8443 {
		t.Fatalf("%s %d", h, p)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestSetConfKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "openvas.conf")
	_ = os.WriteFile(p, []byte("plugins_folder = /var/lib/openvas/plugins\nsource_iface = eth0\n"), 0o644)
	if err := setConfKey(p, "source_iface", "lan0"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p); got != "plugins_folder = /var/lib/openvas/plugins\nsource_iface = lan0\n" {
		t.Fatalf("%q", got)
	}
	if err := setConfKey(p, "max_hosts", "4"); err != nil || !strings.HasSuffix(read(t, p), "max_hosts = 4\n") {
		t.Fatalf("append: %v %q", err, read(t, p))
	}
	missing := filepath.Join(t.TempDir(), "new.conf")
	if err := setConfKey(missing, "source_iface", "lan0"); err != nil || read(t, missing) != "source_iface = lan0\n" {
		t.Fatalf("create: %v %q", err, read(t, missing))
	}
}
