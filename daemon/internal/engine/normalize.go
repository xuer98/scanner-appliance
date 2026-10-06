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
	services map[string]string   // portKey → name from "Services" host details
	alarms   []osp.Result
	logs     []osp.Result
	notes    []string
	scanned  bool // reached openvas
	// enginePorts: openvas reported on a real port of the host or listed
	// its open ports, so its port scanner test worked there.
	enginePorts bool
	findings    []v1.Finding
	errors      int
	// nmapOS is the fingerprint pass's OS match (Phase 5); it competes
	// with openvas's guess on confidence in finalize.
	nmapOS *v1.OSGuess
}

func newHostAgg(ip string) *hostAgg {
	return &hostAgg{ip: ip, ports: map[string]*v1.Port{}, services: map[string]string{}}
}

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

// hostDetailsPort is the pseudo port the feed's "Host Details" test reports
// on. openvas sends those details as ordinary log results, one detail each;
// the "Host Detail" result type of OSP is accepted as well.
const hostDetailsPort = "general/Host_Details"

func isHostDetail(r osp.Result) bool {
	return r.Type == "Host Detail" || strings.EqualFold(strings.TrimSpace(r.Port), hostDetailsPort)
}

// absorb files one OSP result under the host.
func (h *hostAgg) absorb(r osp.Result) {
	if r.Hostname != "" && h.hostname == "" && r.Hostname != r.Host {
		h.hostname = strings.TrimSpace(r.Hostname)
	}
	if isHostDetail(r) {
		h.absorbDetail(r)
		return
	}
	switch r.Type {
	case "Alarm":
		h.alarms = append(h.alarms, r)
	case "Log Message":
		h.logs = append(h.logs, r)
	case "Error Message":
		h.errors++
		return
	default:
		return
	}
	if p, _ := r.PortNumber(); p > 0 {
		h.enginePorts = true
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
		case "best_os_txt":
			h.osTxt = value // the engine's own pick among the "OS" candidates
		case "os":
			// Each candidate arrives twice, as a name and as a CPE.
			if h.osTxt == "" && !strings.HasPrefix(value, "cpe:/") {
				h.osTxt = value
			}
		case "services":
			h.serviceDetail(value)
		case "ports", "tcp_ports":
			h.enginePorts = true // the engine's own list of open ports
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

// serviceDetail records one "Services" host detail, which reads
// "port,proto,service[,description]".
func (h *hostAgg) serviceDetail(value string) {
	f := strings.SplitN(value, ",", 4)
	if len(f) < 3 {
		return
	}
	p, err := strconv.Atoi(strings.TrimSpace(f[0]))
	svc := strings.ToLower(strings.TrimSpace(f[2]))
	if err != nil || p < 1 || p > 65535 || svc == "" || svc == "unknown" || svc == "wrapped" {
		return
	}
	if svc == "www" {
		svc = "http" // the label the log texts already produce
	}
	proto := strings.TrimSpace(f[1])
	if proto == "" {
		proto = "tcp"
	}
	if k := portKey(p, proto); h.services[k] == "" {
		h.services[k] = svc
	}
}

// detection is one "Detected <product>" block of a product detection
// result. Every detection test in the feed builds its report the same way:
//
//	Detected Apache HTTP Server
//
//	Version:       2.4.49
//	Location:      80/tcp
//	CPE:           cpe:/a:apache:http_server:2.4.49
type detection struct {
	product, version, cpe string
	port                  int // from "Location: 80/tcp"; 0 when it is a path
	proto                 string
}

var (
	detectedRe = regexp.MustCompile(`(?m)^Detected[ \t]+(\S.*?)[ \t]*$`)
	fieldRe    = regexp.MustCompile(`(?m)^(Version|Location|CPEs?):[ \t]*(\S.*?)[ \t]*$`)
	locPortRe  = regexp.MustCompile(`^(\d{1,5})/(tcp|udp)$`)
)

// detections splits a result text into its detection blocks. Only the
// first Version, Location and CPE line of a block count: the lines after
// them quote banners that may repeat those words.
func detections(text string) []detection {
	idx := detectedRe.FindAllStringSubmatchIndex(text, -1)
	out := make([]detection, 0, len(idx))
	for i, m := range idx {
		end := len(text)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		d := detection{product: strings.TrimSpace(text[m[2]:m[3]])}
		seen := map[string]bool{}
		for _, f := range fieldRe.FindAllStringSubmatch(text[m[1]:end], -1) {
			name, value := strings.TrimSuffix(f[1], "s"), strings.TrimSpace(f[2])
			if seen[name] {
				continue
			}
			seen[name] = true
			switch name {
			case "Version":
				if !strings.EqualFold(value, "unknown") {
					d.version = value
				}
			case "Location":
				if lm := locPortRe.FindStringSubmatch(strings.ToLower(value)); lm != nil {
					if n, _ := strconv.Atoi(lm[1]); n >= 1 && n <= 65535 {
						d.port, d.proto = n, lm[2]
					}
				}
			case "CPE":
				if c := cpeRe.FindString(value); strings.HasPrefix(c, "cpe:/a:") {
					d.cpe = c
				}
			}
		}
		out = append(out, d)
	}
	return out
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
			// A test that consolidates several detection methods reports
			// once on general/tcp, with one block per install naming its
			// port. Same rules as for a result on the port itself, below.
			for _, d := range detections(r.Text) {
				if d.port == 0 {
					continue
				}
				port := h.addPort(d.port, d.proto, "openvas:find_service")
				if d.cpe != "" && port.CPE == "" {
					port.CPE = d.cpe
					port.Source = "openvas:product_detection"
				}
				if port.Product == "" {
					port.Product, port.Version = d.product, d.version
				}
			}
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
	for k, svc := range h.services {
		if port, ok := h.ports[k]; ok && port.Service == "" {
			port.Service = svc
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
	if h.nmapOS != nil && (out.OSGuess == nil || h.nmapOS.Confidence > out.OSGuess.Confidence) {
		g := *h.nmapOS
		out.OSGuess = &g
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
