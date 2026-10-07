package server

import (
	"context"
	_ "embed"
	"html/template"
	"net/http"
	"sort"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/scanconfig"
)

// The transparency page (PLAN §17.4, §22): what the appliance does, with
// which tools, what it collects and never collects, and the open-source
// notices. Served without authentication on both listeners so a vendor can
// read it before deploying.

//go:embed oss-notices.txt
var ossNotices string

// engineVersions are the pinned third-party components. Keep in sync with
// packer/scripts/install-openvas.sh, ci/build-engine.sh and docker/Dockerfile.
var engineVersions = []struct{ Name, Version, License, Role string }{
	{"openvas-scanner", "v23.50.24", "GPL-2.0-or-later", "vulnerability tests (network checks only, safe_checks on)"},
	{"ospd-openvas", "v22.10.5", "AGPL-3.0-or-later", "scanner control over a local socket"},
	{"gvm-libs", "v23.11.0", "GPL-2.0-or-later", "scanner library"},
	{"Greenbone Community Feed", "daily signed bundle", "ODbL 1.0", "the vulnerability tests themselves"},
	{"naabu", "v2.3.6", "MIT", "host discovery and port scan"},
	{"httpx", "v1.7.1", "MIT", "HTTP service fingerprint (web add-on)"},
	{"nuclei", "v3.4.10", "MIT", "HTTP template checks, dos/fuzz/intrusive templates removed (web add-on)"},
}

// nmapVersion is the Debian 12 package the image and container install
// when built with the fingerprint pass (WITH_NMAP=1 / packer with_nmap).
const nmapVersion = "7.93 (Debian 12 package)"

// nmapRole describes the pass with its sign-off state (PLAN §21: NPSL,
// shipped and run only after legal review).
func nmapRole(rec *signoffRecord) string {
	if rec == nil {
		return "service/version and OS fingerprint pass (-sV/-O, no scripts): NOT enabled; requires a recorded legal sign-off and is not shipped until then"
	}
	return "service/version and OS fingerprint pass (-sV/-O, no scripts): enabled since " + rec.At.UTC().Format("2006-01-02") + " under review " + rec.Reference
}

type transparencyData struct {
	Product    string
	Version    string
	Contact    string
	Phases     []string
	Tools      []struct{ Name, Version, License, Role string }
	Configs    []configSummary
	NeverFam   []string
	Guardrails []string
	Collected  []string
	Never      []string
	Updates    []string
	Retention  string
	Directives []string
	OSSNotices string
	JSONPath   string
}

type configSummary struct {
	Name     string
	Families []string
}

func (s *Server) transparencyData(ctx context.Context) transparencyData {
	product := s.cfg.Product
	if product == "" {
		product = "TPRM scanner appliance"
	}
	nmapRec, err := s.signoff(ctx, v1.SignoffNmap)
	if err != nil {
		s.log.Warn("transparency: signoff lookup", "err", err)
	}
	tools := append([]struct{ Name, Version, License, Role string }{}, engineVersions...)
	tools = append(tools, struct{ Name, Version, License, Role string }{"nmap", nmapVersion, "NPSL-0.95", nmapRole(nmapRec)})
	fingerprintPhase := "fingerprint pass (not enabled): nmap service/version and OS detection would run on the open ports of live hosts, never with scripts, only after a recorded legal sign-off"
	if nmapRec != nil {
		fingerprintPhase = "fingerprint pass (full scans by default, opt-in otherwise): nmap service/version and OS detection on the open ports of live hosts, no scripts; hosts under the fragile-device policy are skipped"
	}
	var cfgs []configSummary
	d := scanconfig.Defaults()
	names := make([]string, 0, len(d))
	for n := range d {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c, _ := scanconfig.Lookup(n, nil)
		cfgs = append(cfgs, configSummary{Name: n, Families: c.Families})
	}
	never := make([]string, 0, len(scanconfig.ExcludedFamilies))
	for f := range scanconfig.ExcludedFamilies {
		never = append(never, f)
	}
	sort.Strings(never)
	never = append(never, "every \"* Local Security Checks\" family (the appliance holds no credentials)")
	return transparencyData{
		Product: product, Version: s.cfg.Version, Contact: s.cfg.Contact, Tools: tools, Configs: cfgs, NeverFam: never,
		Phases: []string{
			"discovery: ARP / ICMP / TCP-SYN probes to 3 ports on the attested ranges (naabu)",
			"port scan: TCP SYN scan of the top ~1000 ports plus warehouse/OT ports on live hosts (naabu); a job may ask for all 65535 ports, which is only accepted when it fits the agreed window at the agreed packet rate",
			"detection: openvas re-checks the ports the port scan found with its own SYN scan, then runs service and product detection plus the vulnerability-test families of the selected scan config on those ports; the Default Accounts family among them signs in with the known default password of specific products, which in our lab was 5 sign-in attempts per scan against an nginx server and about 120 refused requests against a Tomcat management page that asks for a password",
			"UDP tests (only in jobs that ask for them, never by default): openvas has no UDP port scan to pin a list from, so each of its UDP tests probes its own well-known port on every host in scope, including hosts with no open TCP port; in our lab that was about 90 UDP ports and 1,300 datagrams per host, most of them SNMP requests that try about 170 common community names",
			fingerprintPhase,
			"web add-on (full scans only): httpx fingerprint of HTTP services, then nuclei HTTP templates at medium severity and above, without its default-login templates; in our lab that was about 9,660 requests per web server; of those sent to an nginx server, 35 carried a built-in account, where the flaw a check tests is such an account or sits behind a sign-in",
			"default-login templates of the web add-on (only in jobs that ask for them, never by default): they sign in with lists of default user names and passwords, several pairs per product; in our lab that added about 610 requests per web server",
		},
		Guardrails: []string{
			"targets must lie inside the CIDRs the vendor owner attested; a change of scope needs the vendor owner's approval",
			"public IP ranges are never scanned unless the site attests ownership",
			"scan windows and a maximum duration per job; a job outside its window is rejected",
			"packet-rate and per-host concurrency caps per site; safe_checks is always on for Tier 1 vendors",
			"hosts with a fragile-device port open (printers, PLCs, SNMP) are kept away from vulnerability tests until a human clears them",
			"the vendor can stop everything at any time (stop_all) and wipe the appliance from its console",
			"no remote command execution, file fetch or custom test upload exists in the control channel",
		},
		Collected: []string{
			"IP and MAC addresses, hostnames and an operating-system guess of hosts in the attested ranges",
			"open TCP/UDP ports with the service, product and version the detection tests report",
			"vulnerability findings: test name, CVE ids, severity, quality of detection and a short evidence excerpt of the response that triggered the test",
			"appliance health: version, feed version, uptime, load, free disk and memory, interface addresses, clock skew",
			"support bundles only when the vendor triggers them from the console, after reviewing their contents: daemon logs, network configuration and state without the private key",
		},
		Never: []string{
			"credentials of any kind: the appliance runs unauthenticated checks only",
			"file contents, documents, e-mail, user data or packet captures",
			"traffic from segments outside the attested ranges",
			"anything from the appliance's own private key or the enrollment code",
		},
		Updates: []string{
			"vulnerability tests and scan configurations arrive as signed bundles; the appliance fetches only changed files and reverts if the engine cannot load them",
			"the daemon updates itself from signed releases, confirms with a heartbeat and reverts on failure; releases go to lab appliances first",
			"Debian security updates come from our mirror; a required reboot happens between 03:00 and 04:00 local time when the appliance is idle",
		},
		Retention:  "results are kept for the duration of the engagement plus the retention period in the contract addendum; heartbeat logs for 30 days; support bundles until the case is closed",
		Directives: []string{"noop", "set_interval", "stop_all", "run_job_now", "update_bundle", "update_daemon", "reload_vts", "renew_cert", "wipe"},
		OSSNotices: strings.TrimSpace(ossNotices), JSONPath: "/transparency.json",
	}
}

var transparencyTmpl = template.Must(template.New("t").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Product}}: what this appliance does</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#222}h1,h2{line-height:1.2}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.3rem .6rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap;background:#f6f6f6;padding:1rem;font-size:13px}code{background:#f6f6f6;padding:0 .2rem}</style></head>
<body>
<h1>{{.Product}}: what this appliance does</h1>
<p>Version {{.Version}}. Machine-readable copy: <a href="{{.JSONPath}}">{{.JSONPath}}</a>.{{if .Contact}} Questions: {{.Contact}}.{{end}}</p>
<h2>How a scan runs</h2><ol>{{range .Phases}}<li>{{.}}</li>{{end}}</ol>
<h2>Tools on the appliance</h2><table><tr><th>Component</th><th>Version</th><th>License</th><th>Role</th></tr>{{range .Tools}}<tr><td>{{.Name}}</td><td>{{.Version}}</td><td>{{.License}}</td><td>{{.Role}}</td></tr>{{end}}</table>
<h2>Scan configurations</h2>{{range .Configs}}<p><strong>{{.Name}}</strong>: {{range $i, $f := .Families}}{{if $i}}, {{end}}{{$f}}{{end}}</p>{{end}}
<p>Never selectable: {{range $i, $f := .NeverFam}}{{if $i}}; {{end}}{{$f}}{{end}}.</p>
<h2>Guardrails</h2><ul>{{range .Guardrails}}<li>{{.}}</li>{{end}}</ul>
<h2>Data collected</h2><ul>{{range .Collected}}<li>{{.}}</li>{{end}}</ul>
<h2>Never collected</h2><ul>{{range .Never}}<li>{{.}}</li>{{end}}</ul>
<h2>Updates</h2><ul>{{range .Updates}}<li>{{.}}</li>{{end}}</ul>
<h2>Retention</h2><p>{{.Retention}}</p>
<h2>Control channel</h2><p>The appliance only ever connects out, to one address on TCP 443, with a client certificate. The complete set of instructions it accepts is: {{range $i, $d := .Directives}}{{if $i}}, {{end}}<code>{{$d}}</code>{{end}}. Every one of them is listed in the software's source; there is no shell, remote command or file fetch.</p>
<h2>Open-source notices</h2><pre>{{.OSSNotices}}</pre>
</body></html>
`))

func (s *Server) handleTransparency(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := transparencyTmpl.Execute(w, s.transparencyData(r.Context())); err != nil {
		s.log.Warn("transparency page", "err", err)
	}
}

func (s *Server) handleTransparencyJSON(w http.ResponseWriter, r *http.Request) {
	d := s.transparencyData(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"product": d.Product, "version": d.Version, "contact": d.Contact, "phases": d.Phases, "tools": d.Tools, "scan_configs": d.Configs,
		"never_selectable_families": d.NeverFam, "guardrails": d.Guardrails, "data_collected": d.Collected, "never_collected": d.Never,
		"updates": d.Updates, "retention": d.Retention, "directives": d.Directives, "oss_notices": d.OSSNotices,
	})
}
