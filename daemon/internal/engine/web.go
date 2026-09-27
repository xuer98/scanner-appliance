package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// Web add-on (PLAN §10.2, Phase 3): httpx fingerprints every open port
// that looks like HTTP(S), then nuclei runs the bundled HTTP templates
// against the live URLs with the job's severity floor and tag exclusions.
// Both tools are optional: when they or the templates are missing the
// phase is skipped and the job carries a warning instead of failing.
//
// Safety: nuclei runs without interactsh (no out-of-band callbacks leave
// the site), without template auto-update, and only with the templates
// shipped in the signed bundle.

// httpPorts are probed even when no service was detected on them.
var httpPorts = map[int]bool{80: true, 81: true, 443: true, 591: true, 3000: true, 5000: true, 7080: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8088: true, 8443: true, 8888: true, 9000: true, 9080: true, 9090: true, 9443: true, 10000: true}

// QoDWeb is the quality of a nuclei match: a request that produced the
// expected response, below an authenticated check but above a banner.
const QoDWeb = 80

// maxWebTargets bounds one job's HTTP probe list.
const maxWebTargets = 5000

func isWebPort(p *v1.Port) bool {
	if p.Proto != "tcp" {
		return false
	}
	if httpPorts[p.Port] {
		return true
	}
	svc := strings.ToLower(p.Service)
	return svc == "www" || svc == "http" || svc == "https" || strings.HasPrefix(svc, "http-") || strings.Contains(strings.ToLower(p.Product), "http")
}

func (r *run) webWarn(msg string) {
	r.stats.Warnings = append(r.stats.Warnings, "web: "+msg)
	r.log.Warn("web add-on skipped", "reason", msg)
}

// web runs the add-on for the whole job.
func (r *run) web(ctx context.Context) error {
	if r.e.HTTPXPath == "" || r.e.NucleiPath == "" {
		r.webWarn("httpx/nuclei not installed")
		return nil
	}
	templates := ""
	if r.e.BundleDir != "" {
		templates = filepath.Join(r.e.BundleDir, bundle.TemplatesDir)
	}
	if fi, err := os.Stat(templates); templates == "" || err != nil || !fi.IsDir() {
		r.webWarn("no nuclei templates in the installed bundle")
		return nil
	}
	var targets []string
	byInput := map[string]*hostAgg{}
	for _, ip := range r.order {
		h := r.hosts[ip]
		if r.excluded(ip) {
			continue
		}
		for _, p := range h.ports {
			if isWebPort(p) {
				in := net.JoinHostPort(ip, strconv.Itoa(p.Port))
				targets = append(targets, in)
				byInput[in] = h
			}
		}
	}
	if len(targets) == 0 {
		r.log.Info("web add-on: no HTTP ports to probe")
		return nil
	}
	if len(targets) > maxWebTargets {
		r.webWarn(fmt.Sprintf("%d HTTP targets, probing the first %d", len(targets), maxWebTargets))
		targets = targets[:maxWebTargets]
	}
	sort.Strings(targets)
	work, err := os.MkdirTemp("", "web-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	urls, err := r.httpx(ctx, work, targets, byInput)
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		r.log.Info("web add-on: nothing answered HTTP")
		return nil
	}
	r.progress(PhaseWeb, 50)
	return r.nuclei(ctx, work, templates, urls)
}

// httpxLine is the subset of httpx -json we use.
type httpxLine struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Scheme     string   `json:"scheme"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	Failed     bool     `json:"failed"`
}

func (r *run) httpx(ctx context.Context, work string, targets []string, byInput map[string]*hostAgg) ([]string, error) {
	list := filepath.Join(work, "targets.txt")
	if err := os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}
	args := []string{"-l", list, "-silent", "-json", "-no-color", "-disable-update-check", "-status-code", "-title", "-server", "-tech-detect",
		"-timeout", "10", "-retries", "1", "-threads", strconv.Itoa(clamp(r.spec.Rate.PerHostParallel*10, 10, 50)), "-rate-limit", strconv.Itoa(clamp(r.spec.Rate.PPS, 10, 1000)),
		"-no-fallback"}
	out, err := r.e.runTool(ctx, r.e.HTTPXPath, "httpx", args)
	if err != nil {
		return nil, err
	}
	var urls []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var l httpxLine
		if json.Unmarshal(line, &l) != nil || l.Failed || l.URL == "" {
			continue
		}
		h := byInput[l.Input]
		if h == nil {
			if hp, ok := byInput[net.JoinHostPort(l.Host, l.Port)]; ok {
				h = hp
			}
		}
		if h == nil {
			continue
		}
		port, _ := strconv.Atoi(l.Port)
		if port == 0 {
			continue
		}
		p := h.addPort(port, "tcp", "httpx")
		p.Web = &v1.WebInfo{URL: l.URL, Status: l.StatusCode, Title: strings.TrimSpace(l.Title), Server: strings.TrimSpace(l.WebServer), Tech: l.Tech}
		if p.Service == "" {
			p.Service = "http"
			if l.Scheme == "https" || strings.HasPrefix(l.URL, "https://") {
				p.Service = "https"
			}
		}
		if p.Product == "" && l.WebServer != "" {
			p.Product = strings.TrimSpace(l.WebServer)
		}
		urls = append(urls, l.URL)
	}
	sort.Strings(urls)
	r.log.Info("httpx", "targets", len(targets), "live_urls", len(urls))
	return urls, nil
}

// nucleiLine is the subset of nuclei -jsonl we use.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Tags           any    `json:"tags"`
		Remediation    string `json:"remediation"`
		Classification struct {
			CVEID     any     `json:"cve-id"`
			CVSSScore float64 `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
}

func anyStrings(v any) []string {
	switch t := v.(type) {
	case string:
		var out []string
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func (r *run) nuclei(ctx context.Context, work, templates string, urls []string) error {
	list := filepath.Join(work, "urls.txt")
	if err := os.WriteFile(list, []byte(strings.Join(urls, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	web := r.spec.Web
	if web == nil {
		web = v1.DefaultWebParams()
	}
	minRank := v1.SeverityRank(web.MinSeverity)
	if minRank < 0 {
		minRank = v1.SeverityRank(v1.SeverityMedium)
	}
	var sevs []string
	for _, s := range []string{v1.SeverityInfo, v1.SeverityLow, v1.SeverityMedium, v1.SeverityHigh, v1.SeverityCritical} {
		if v1.SeverityRank(s) >= minRank {
			sevs = append(sevs, s)
		}
	}
	excl := append([]string{}, web.ExcludeTags...)
	for _, must := range []string{"dos", "fuzz", "intrusive"} { // never negotiable (PLAN §10.2)
		found := false
		for _, e := range excl {
			if e == must {
				found = true
			}
		}
		if !found {
			excl = append(excl, must)
		}
	}
	args := []string{"-l", list, "-silent", "-jsonl", "-no-color", "-disable-update-check", "-no-interactsh",
		"-templates", templates, "-severity", strings.Join(sevs, ","), "-exclude-tags", strings.Join(excl, ","),
		"-timeout", "10", "-retries", "1", "-concurrency", strconv.Itoa(clamp(r.spec.Rate.PerHostParallel*5, 5, 25)),
		"-bulk-size", strconv.Itoa(clamp(r.spec.Rate.PerHostParallel*5, 5, 25)), "-rate-limit", strconv.Itoa(clamp(r.spec.Rate.PPS/2, 10, 500))}
	out, err := r.e.runTool(ctx, r.e.NucleiPath, "nuclei", args)
	if err != nil {
		return err
	}
	byIP := map[string]*hostAgg{}
	for ip, h := range r.hosts {
		byIP[ip] = h
	}
	seen := map[string]bool{}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var l nucleiLine
		if json.Unmarshal(line, &l) != nil || l.TemplateID == "" {
			continue
		}
		sev := strings.ToLower(l.Info.Severity)
		if !v1.KnownSeverities[sev] {
			sev = v1.SeverityInfo
		}
		if v1.SeverityRank(sev) < minRank {
			continue
		}
		host, port := hostPortOf(l)
		h := byIP[host]
		if h == nil {
			continue
		}
		key := l.TemplateID + "|" + host + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		f := v1.Finding{Source: "nuclei", ID: l.TemplateID, Name: strings.TrimSpace(l.Info.Name), Family: "Web application (nuclei)",
			Severity: sev, CVSS: l.Info.Classification.CVSSScore, CVE: []string{}, QoD: QoDWeb, Port: port, Proto: "tcp",
			Solution: strings.TrimSpace(l.Info.Remediation)}
		for _, c := range anyStrings(l.Info.Classification.CVEID) {
			f.CVE = append(f.CVE, strings.ToUpper(c))
		}
		if f.Name == "" {
			f.Name = l.TemplateID
		}
		ev := l.MatchedAt
		if l.MatcherName != "" {
			ev += " matcher=" + l.MatcherName
		}
		if len(l.ExtractedResults) > 0 {
			ev += " extracted=" + strings.Join(l.ExtractedResults, ",")
		}
		if tags := anyStrings(l.Info.Tags); len(tags) > 0 {
			ev += " tags=" + strings.Join(tags, ",")
		}
		if len(ev) > maxEvidence {
			ev = ev[:maxEvidence] + "…"
		}
		f.Evidence = ev
		h.findings = append(h.findings, f)
		n++
	}
	r.log.Info("nuclei", "urls", len(urls), "findings", n, "min_severity", web.MinSeverity)
	return nil
}

// hostPortOf extracts the target IP and port from a nuclei result.
func hostPortOf(l nucleiLine) (string, int) {
	host := l.Host
	port := 0
	if l.Port != "" {
		port, _ = strconv.Atoi(l.Port)
	}
	for _, u := range []string{l.MatchedAt, l.Host} {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		rest := u
		scheme := ""
		if i := strings.Index(u, "://"); i > 0 {
			scheme, rest = u[:i], u[i+3:]
		}
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		if h, p, err := net.SplitHostPort(rest); err == nil {
			host = h
			if port == 0 {
				port, _ = strconv.Atoi(p)
			}
		} else if rest != "" {
			host = rest
		}
		if port == 0 {
			switch scheme {
			case "https":
				port = 443
			case "http":
				port = 80
			}
		}
		if net.ParseIP(host) != nil {
			break
		}
	}
	return host, port
}

// runTool executes an engine helper with a bounded output size.
func (e *Engine) runTool(ctx context.Context, path, name string, args []string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(), "HOME=/var/lib/appliance", "NO_COLOR=1", "DISABLE_UPDATE_CHECK=1")
	e.Log.Info(name+" start", "args", strings.Join(args, " "))
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.Len() > 64<<20 {
		return nil, errors.New(name + ": output too large")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("%s failed: %v: %s", name, err, msg)
		}
		e.Log.Warn(name+" exited non-zero but produced output", "err", err, "stderr", msg)
	}
	return stdout.Bytes(), nil
}
