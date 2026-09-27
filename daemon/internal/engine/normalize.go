package engine

import (
	"encoding/xml"
	"regexp"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

const maxEvidence = 4096

// hostAgg accumulates everything learned about one host across phases.
type hostAgg struct {
	ip       string
	hostname string
	mac      string
	osCPE    string
	osTxt    string
	ports    map[string]*v1.Port // "80/tcp"
	alarms   []osp.Result
	logs     []osp.Result
	notes    []string
	scanned  bool // reached openvas
	findings []v1.Finding
	errors   int
}

func newHostAgg(ip string) *hostAgg { return &hostAgg{ip: ip, ports: map[string]*v1.Port{}} }

func portKey(p int, proto string) string { return strings.ToLower(proto) + ":" + itoa(p) }

func itoa(i int) string { return strconv.Itoa(i) }

func (h *hostAgg) addPort(p int, proto, source string) *v1.Port {
	if proto == "" {
		proto = "tcp"
	}
	k := portKey(p, proto)
	if e, ok := h.ports[k]; ok {
		return e
	}
	e := &v1.Port{Port: p, Proto: strings.ToLower(proto), Source: source}
	h.ports[k] = e
	return e
}

// absorb files one OSP result under the host.
func (h *hostAgg) absorb(r osp.Result) {
	if r.Hostname != "" && h.hostname == "" && r.Hostname != r.Host {
		h.hostname = strings.TrimSpace(r.Hostname)
	}
	switch r.Type {
	case "Alarm":
		h.alarms = append(h.alarms, r)
	case "Log Message":
		h.logs = append(h.logs, r)
	case "Host Detail":
		h.absorbDetail(r)
	case "Error Message":
		h.errors++
	}
}

// hostDetail is the <host><detail>…</detail></host> document openvas puts
// in the text of a Host Detail result.
type hostDetail struct {
	XMLName xml.Name `xml:"host"`
	Details []struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"detail"`
}

func (h *hostAgg) absorbDetail(r osp.Result) {
	apply := func(name, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		switch strings.ToLower(name) {
		case "mac":
			if h.mac == "" {
				h.mac = strings.ToLower(value)
			}
		case "best_os_cpe":
			h.osCPE = value
		case "best_os_txt", "os":
			if h.osTxt == "" {
				h.osTxt = value
			}
		case "hostname":
			if h.hostname == "" {
				h.hostname = value
			}
		}
	}
	text := strings.TrimSpace(r.Text)
	if strings.HasPrefix(text, "<host>") {
		var d hostDetail
		if err := xml.Unmarshal([]byte(text), &d); err == nil {
			for _, x := range d.Details {
				apply(x.Name, x.Value)
			}
			return
		}
	}
	apply(r.Name, text)
}

var (
	cpeRe     = regexp.MustCompile(`cpe:/[aoh]:[A-Za-z0-9._~%-]+(?::[A-Za-z0-9._~%-]*)*`)
	svcRe     = regexp.MustCompile(`(?i)\b(?:an?|the)\s+([A-Za-z0-9 ./()-]+?)\s+(?:server|service|daemon)\b`)
	versionRe = regexp.MustCompile(`(?i)version:?\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)
	detectRe  = regexp.MustCompile(`(?i)detected\s+(.+?)\s+version`)
)

// serviceKeywords map phrases in detection output to service labels;
// order matters (first hit wins).
var serviceKeywords = []struct{ kw, svc string }{
	{"remote desktop", "rdp"}, {"rdp", "rdp"}, {"web server", "http"}, {"http", "http"}, {"ssh", "ssh"},
	{"ftp", "ftp"}, {"smtp", "smtp"}, {"imap", "imap"}, {"pop3", "pop3"}, {"dns", "dns"}, {"vnc", "vnc"},
	{"smb", "smb"}, {"cifs", "smb"}, {"netbios", "netbios"}, {"telnet", "telnet"}, {"ldap", "ldap"},
	{"mysql", "mysql"}, {"mariadb", "mysql"}, {"postgresql", "postgresql"}, {"microsoft sql", "mssql"},
	{"mssql", "mssql"}, {"oracle", "oracle"}, {"snmp", "snmp"}, {"ntp", "ntp"}, {"tls", "tls"}, {"ssl", "tls"},
	{"jetdirect", "jetdirect"}, {"printer", "printer"}, {"ipp", "ipp"}, {"modbus", "modbus"}, {"mqtt", "mqtt"},
	{"redis", "redis"}, {"mongodb", "mongodb"}, {"memcache", "memcached"}, {"rpc", "rpc"}, {"nfs", "nfs"},
	{"kerberos", "kerberos"}, {"winrm", "winrm"}, {"sip", "sip"}, {"ipmi", "ipmi"}, {"elasticsearch", "elasticsearch"},
}

func serviceFromText(text string) string {
	lower := strings.ToLower(text)
	for _, k := range serviceKeywords {
		if strings.Contains(lower, k.kw) {
			return k.svc
		}
	}
	if m := svcRe.FindStringSubmatch(text); len(m) == 2 {
		return strings.ToLower(strings.TrimSpace(m[1]))
	}
	return ""
}

// osFamily derives the family from an OS CPE or free text.
func osFamily(cpe, txt string) string {
	s := strings.ToLower(cpe + " " + txt)
	switch {
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "linux"), strings.Contains(s, "debian"), strings.Contains(s, "ubuntu"), strings.Contains(s, "redhat"),
		strings.Contains(s, "red_hat"), strings.Contains(s, "centos"), strings.Contains(s, "fedora"), strings.Contains(s, "suse"), strings.Contains(s, "android"):
		return "linux"
	case strings.Contains(s, "mac_os"), strings.Contains(s, "macos"), strings.Contains(s, "darwin"), strings.Contains(s, "ios"):
		return "apple"
	case strings.Contains(s, "freebsd"), strings.Contains(s, "openbsd"), strings.Contains(s, "netbsd"):
		return "bsd"
	case strings.Contains(s, "cisco"), strings.Contains(s, "juniper"), strings.Contains(s, "arista"), strings.Contains(s, "fortinet"), strings.Contains(s, "palo"):
		return "network"
	case strings.Contains(s, "printer"), strings.Contains(s, "jetdirect"), strings.Contains(s, "hp:"), strings.Contains(s, "zebra"), strings.Contains(s, "embedded"), strings.Contains(s, "vxworks"):
		return "embedded"
	case s == " ":
		return ""
	}
	return "other"
}

// finalize turns the aggregate into the wire host using NVT metadata.
func (h *hostAgg) finalize(meta map[string]*nvt.Meta) v1.Host {
	out := v1.Host{IP: h.ip, MAC: h.mac, Hostname: h.hostname, Notes: h.notes}
	// Service / product detection from log results.
	for _, r := range h.logs {
		p, proto := r.PortNumber()
		if p == 0 {
			continue
		}
		port := h.addPort(p, proto, "openvas:find_service")
		fam := ""
		if m := meta[r.TestID]; m != nil {
			fam = m.Family
		}
		text := r.Text
		if cpes := cpeRe.FindAllString(text, -1); len(cpes) > 0 {
			for _, c := range cpes {
				if strings.HasPrefix(c, "cpe:/a:") && port.CPE == "" {
					port.CPE = c
					port.Source = "openvas:product_detection"
				}
			}
		}
		if m := detectRe.FindStringSubmatch(text); len(m) == 2 && port.Product == "" {
			port.Product = strings.TrimSpace(m[1])
			if v := versionRe.FindStringSubmatch(text); len(v) == 2 {
				port.Version = v[1]
			}
		}
		if port.Service == "" && (fam == "Service detection" || fam == "" || fam == "Product detection" || fam == "General") {
			if svc := serviceFromText(text); svc != "" {
				port.Service = svc
			}
		}
	}
	// Findings from alarms; one per (oid, port).
	seen := map[string]bool{}
	for _, r := range h.alarms {
		p, proto := r.PortNumber()
		key := r.TestID + "|" + proto + ":" + itoa(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		score := r.SeverityScore()
		f := v1.Finding{Source: "openvas", NVTOID: r.TestID, Name: strings.TrimSpace(r.Name), CVSS: score, QoD: r.QoDValue(), Port: p, Proto: proto, CVE: []string{}}
		if m := meta[r.TestID]; m != nil && !m.Missing {
			f.Family, f.Solution = m.Family, m.Solution
			if len(m.CVEs) > 0 {
				f.CVE = append([]string{}, m.CVEs...)
			}
			if f.Name == "" {
				f.Name = m.Name
			}
			if f.CVSS == 0 {
				f.CVSS = m.CVSS
			}
			if f.QoD == 0 {
				f.QoD = m.QoD
			}
		}
		f.Severity = v1.SeverityFor(f.CVSS)
		f.Evidence = strings.TrimSpace(r.Text)
		if len(f.Evidence) > maxEvidence {
			f.Evidence = f.Evidence[:maxEvidence] + "…"
		}
		if f.Severity == v1.SeverityInfo {
			continue // an Alarm without a score is a log line in disguise
		}
		out.Findings = append(out.Findings, f)
	}
	out.Findings = append(out.Findings, h.findings...)
	if h.osCPE != "" || h.osTxt != "" {
		out.OSGuess = &v1.OSGuess{Family: osFamily(h.osCPE, h.osTxt), Name: h.osTxt, CPE: h.osCPE, Source: "openvas:os_detection", Confidence: 0.5}
		if h.osCPE != "" {
			out.OSGuess.Confidence = 0.7
		}
	}
	for _, p := range h.ports {
		out.Ports = append(out.Ports, *p)
	}
	sort.Slice(out.Ports, func(i, j int) bool {
		if out.Ports[i].Proto != out.Ports[j].Proto {
			return out.Ports[i].Proto < out.Ports[j].Proto
		}
		return out.Ports[i].Port < out.Ports[j].Port
	})
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].CVSS != out.Findings[j].CVSS {
			return out.Findings[i].CVSS > out.Findings[j].CVSS
		}
		return out.Findings[i].NVTOID < out.Findings[j].NVTOID
	})
	if out.Ports == nil {
		out.Ports = []v1.Port{}
	}
	if out.Findings == nil {
		out.Findings = []v1.Finding{}
	}
	return out
}
