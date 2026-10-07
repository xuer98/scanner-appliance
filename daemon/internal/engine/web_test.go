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
	// Like the real one it reports what it loaded on stderr; a file named
	// nuclei.broken in the log directory makes it report that many templates
	// as not loaded.
	nuclei = write("nuclei", `#!/bin/sh
echo "$@" >> "`+logDir+`/nuclei.args"
if [ -f "`+logDir+`/nuclei.broken" ]; then
  echo "[WRN] Found $(cat "`+logDir+`/nuclei.broken") templates with runtime error (use -validate flag for further examination)" >&2
fi
echo "[INF] Templates loaded for current scan: 5861" >&2
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
	// The bundle's templates are also named as nuclei's own template
	// directory: only below that does it open the helper files they use.
	nargs := read(t, filepath.Join(logDir, "nuclei.args"))
	tplDir := filepath.Join(bundleDir, "nuclei-templates")
	for _, want := range []string{"-no-interactsh", "-disable-update-check", "-exclude-tags dos,fuzz,intrusive,default-login ", "-severity medium,high,critical",
		"-templates " + tplDir + " ", "-update-template-dir " + tplDir + " "} {
		if !strings.Contains(nargs, want) {
			t.Fatalf("nuclei args missing %q: %s", want, nargs)
		}
	}
	// -silent would hide what nuclei says about templates it cannot load.
	if strings.Contains(" "+nargs, " -silent ") {
		t.Fatalf("nuclei ran silent: %s", nargs)
	}
}

// A template that does not load is a check that did not run. nuclei says so
// in one line on stderr and goes on, so the job has to carry it. It is a
// note and not a "web:" warning, which would tell the control plane that
// the phase did not look and that no web finding may be resolved.
func TestTemplatesThatDoNotLoadAreReported(t *testing.T) {
	logDir := t.TempDir()
	naabu, httpx, nuclei := webFakes(t, logDir)
	bundleDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(bundleDir, "nuclei-templates", "http"), 0o755)
	if err := os.WriteFile(filepath.Join(logDir, "nuclei.broken"), []byte("244"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Engine{NaabuPath: naabu, HTTPXPath: httpx, NucleiPath: nuclei, BundleDir: bundleDir, Log: slog.Default(),
		Now: time.Now, PollInterval: 10 * time.Millisecond, IfaceExists: func(string) bool { return false }}
	spec := v1.JobSpec{JobID: "job_web3", SiteID: "site_1", ApplianceID: "apl_1", Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"},
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleWeb}, Ports: "standard", Rate: v1.Rate{PPS: 300, PerHostParallel: 2}}
	sink := &webSink{}
	stats, err := e.Run(t.Context(), spec, v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Warnings) != 1 || stats.Warnings[0] != "nuclei: 244 templates did not load" {
		t.Fatalf("warnings: %q", stats.Warnings)
	}
	// What the other templates found is still reported.
	if stats.Findings != 1 {
		t.Fatalf("findings: %d", stats.Findings)
	}

	// The lines as nuclei v3.4.10 prints them, banner and all.
	const diag = `
                     __     _
   ____  __  _______/ /__  (_)
[ERR] Could not read nuclei-ignore file: open /var/lib/appliance/.config/nuclei/.nuclei-ignore: no such file or directory
[WRN] Found 237 templates with runtime error (use -validate flag for further examination)
[WRN] Found 1 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v3.4.10 (unknown) - remove '-duc' flag to enable update checks
[INF] Templates loaded for current scan: 3
[INF] Executing 3 signed templates from projectdiscovery/nuclei-templates
[INF] Scan completed in 460.733292ms. No results found.
`
	if loaded, broken := nucleiLoad([]byte(diag)); loaded != 3 || broken != 238 {
		t.Fatalf("loaded=%d broken=%d, want 3 and 238", loaded, broken)
	}
	if loaded, broken := nucleiLoad([]byte("[INF] Templates loaded for current scan: 5861\n")); loaded != 5861 || broken != 0 {
		t.Fatalf("clean run: loaded=%d broken=%d", loaded, broken)
	}
}

// Checks that sign in with a vendor's default password are left out unless
// the job carries the default_logins module, and what they find is filed
// under its own family, which is how the control plane knows that only
// such a job can see it again.
func TestDefaultLoginsAreOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fakes are POSIX shell scripts")
	}
	logDir := t.TempDir()
	naabu, httpx, _ := webFakes(t, logDir)
	// A nuclei that honors -exclude-tags for the one tag that matters here.
	nuclei := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(nuclei, []byte(`#!/bin/sh
echo "$@" >> "`+logDir+`/nuclei.args"
excl=""
while [ $# -gt 0 ]; do [ "$1" = "-exclude-tags" ] && excl="$2"; shift; done
printf '%s\n' '{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 path traversal","severity":"critical","tags":["cve","apache"]},"type":"http","host":"http://10.30.5.20:8080","port":"8080","matched-at":"http://10.30.5.20:8080/x"}'
case ",$excl," in
  *,default-login,*) ;;
  *) printf '%s\n' '{"template-id":"tomcat-default-login","info":{"name":"Apache Tomcat Manager Default Login","severity":"high","tags":"tomcat,apache,default-login"},"type":"http","host":"http://10.30.5.20:8080","port":"8080","matched-at":"http://10.30.5.20:8080/manager/html","extracted-results":["tomcat:tomcat"]}' ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	bundleDir := t.TempDir()
	tpl := filepath.Join(bundleDir, "nuclei-templates", "http", "default-logins")
	_ = os.MkdirAll(tpl, 0o755)
	_ = os.WriteFile(filepath.Join(tpl, "x.yaml"), []byte("id: x\n"), 0o644)
	run := func(modules []string, exclude []string) (map[string]string, string) {
		t.Helper()
		_ = os.Remove(filepath.Join(logDir, "nuclei.args"))
		e := &Engine{NaabuPath: naabu, HTTPXPath: httpx, NucleiPath: nuclei, BundleDir: bundleDir, Log: slog.Default(),
			Now: time.Now, PollInterval: 10 * time.Millisecond, IfaceExists: func(string) bool { return false }}
		spec := v1.JobSpec{JobID: "job_dl", SiteID: "site_1", ApplianceID: "apl_1", Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"},
			Modules: modules, Ports: "standard", Rate: v1.Rate{PPS: 300, PerHostParallel: 2},
			Web: &v1.WebParams{MinSeverity: v1.SeverityMedium, ExcludeTags: exclude}}
		if err := spec.ValidateShape(); err != nil {
			t.Fatalf("spec: %v", err)
		}
		sink := &webSink{}
		if _, err := e.Run(t.Context(), spec, v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}}, sink); err != nil {
			t.Fatal(err)
		}
		families := map[string]string{}
		for _, f := range sink.batches[len(sink.batches)-1].Hosts[0].Findings {
			families[f.ID] = f.Family
		}
		return families, read(t, filepath.Join(logDir, "nuclei.args"))
	}
	plain := []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleWeb}
	withLogins := append(append([]string{}, plain...), v1.ModuleDefaultLogins)

	fam, args := run(plain, []string{"dos", "fuzz", "intrusive"})
	if !strings.Contains(args, "-exclude-tags dos,fuzz,intrusive,default-login ") {
		t.Fatalf("a job without the module must exclude the tag: %s", args)
	}
	if len(fam) != 1 || fam["CVE-2021-41773"] != v1.FamilyWeb {
		t.Fatalf("without the module: %v", fam)
	}

	fam, args = run(withLogins, []string{"dos", "fuzz", "intrusive"})
	if strings.Contains(args, "default-login") {
		t.Fatalf("a job with the module must not exclude the tag: %s", args)
	}
	if len(fam) != 2 || fam["tomcat-default-login"] != v1.FamilyWebDefaultLogin || fam["CVE-2021-41773"] != v1.FamilyWeb {
		t.Fatalf("with the module: %v", fam)
	}

	// The job's own exclusions still hold: the module lifts the appliance's
	// floor, it does not force the checks on.
	fam, args = run(withLogins, []string{"default-login"})
	if !strings.Contains(args, "-exclude-tags default-login,dos,fuzz,intrusive ") || len(fam) != 1 {
		t.Fatalf("job-level exclusion ignored: %v / %s", fam, args)
	}

	// The module needs the web phase.
	bad := v1.JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Ports: "standard",
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleDefaultLogins}, Rate: v1.Rate{PPS: 300, PerHostParallel: 2}}
	if err := bad.ValidateShape(); err == nil || !strings.Contains(err.Error(), "needs the web module") {
		t.Fatalf("default_logins without web: %v", err)
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
