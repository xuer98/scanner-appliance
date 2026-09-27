package engine

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Fingerprint pass (PLAN §10.2 "Later", §20 Phase 5): nmap -sV, plus -O
// when the job asks for it, against the hosts and TCP ports the port scan
// found. nmap is NPSL-licensed and is only present on builds made after
// the legal sign-off (WITH_NMAP=1 / packer with_nmap=true); the control
// plane refuses the module until the sign-off is recorded, and the
// appliance skips the phase with a warning when the binary is absent. No
// NSE script is ever run: the invocation is version and OS detection only.
//
// The pass is an add-on to the detection phase, so a tool failure is a
// warning on the job, not a job failure: the openvas results stand.

// PhaseFingerprint is reported while nmap runs.
const PhaseFingerprint = "fingerprint"

// maxFingerprintHosts bounds one nmap invocation.
const maxFingerprintHosts = 4096

// Port and OS sources the pass writes.
const (
	sourceNmap        = "nmap"
	sourceNmapVersion = "nmap:version_detection"
	sourceNmapOS      = "nmap:os_detection"
)

// minOSAccuracy is nmap's osmatch accuracy below which a guess is ignored.
const minOSAccuracy = 85

// nmapRun is the subset of nmap's XML output (-oX) the pass reads.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
	OS    *struct {
		Matches []nmapOSMatch `xml:"osmatch"`
	} `xml:"os"`
}

type nmapPort struct {
	Proto string `xml:"protocol,attr"`
	ID    int    `xml:"portid,attr"`
	State struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service *struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Conf      int      `xml:"conf,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
	Classes  []struct {
		Type   string   `xml:"type,attr"`
		Vendor string   `xml:"vendor,attr"`
		Family string   `xml:"osfamily,attr"`
		Gen    string   `xml:"osgen,attr"`
		CPE    []string `xml:"cpe"`
	} `xml:"osclass"`
}

func (h nmapHost) ip() string {
	for _, a := range h.Addresses {
		if a.Type == "ipv4" || a.Type == "ipv6" {
			if ip := net.ParseIP(a.Addr); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func (h nmapHost) mac() string {
	for _, a := range h.Addresses {
		if a.Type == "mac" && a.Addr != "" {
			return strings.ToLower(a.Addr)
		}
	}
	return ""
}

func (h nmapHost) ptr() string {
	for _, n := range h.Hostnames {
		if n.Type == "PTR" && n.Name != "" {
			return strings.TrimSuffix(n.Name, ".")
		}
	}
	return ""
}

// parseNmap decodes the XML; a truncated document (nmap killed) still
// yields the hosts decoded so far.
func parseNmap(out []byte) (*nmapRun, error) {
	var r nmapRun
	if err := xml.Unmarshal(out, &r); err != nil {
		if len(r.Hosts) == 0 {
			return nil, fmt.Errorf("nmap output: %w", err)
		}
	}
	return &r, nil
}

// nmapServiceNames maps nmap's service names to the labels the rest of
// the pipeline uses (normalize.go serviceKeywords).
var nmapServiceNames = map[string]string{
	"http": "http", "http-proxy": "http", "http-alt": "http", "https": "https", "https-alt": "https", "ssl/http": "https",
	"microsoft-ds": "smb", "netbios-ssn": "netbios", "ms-wbt-server": "rdp", "domain": "dns", "ms-sql-s": "mssql", "ms-sql-m": "mssql",
	"oracle-tns": "oracle", "postgresql": "postgresql", "mysql": "mysql", "jetdirect": "jetdirect", "printer": "printer", "ipp": "ipp",
	"modbus": "modbus", "mbap": "modbus", "snmp": "snmp", "ssh": "ssh", "ftp": "ftp", "smtp": "smtp", "smtps": "smtp", "submission": "smtp",
	"imap": "imap", "imaps": "imap", "pop3": "pop3", "pop3s": "pop3", "telnet": "telnet", "ldap": "ldap", "ldapssl": "ldap", "vnc": "vnc",
	"rpcbind": "rpc", "msrpc": "rpc", "nfs": "nfs", "kerberos-sec": "kerberos", "wsman": "winrm", "wsmans": "winrm", "sip": "sip",
	"mqtt": "mqtt", "secure-mqtt": "mqtt", "redis": "redis", "mongodb": "mongodb", "memcached": "memcached", "ntp": "ntp",
	"upnp": "upnp", "EtherNet-IP-1": "ethernet-ip", "EtherNet-IP-2": "ethernet-ip", "iso-tsap": "s7comm", "bacnet": "bacnet",
	"asf-rmcp": "ipmi", "amqp": "amqp", "elasticsearch": "elasticsearch", "docker": "docker", "tcpwrapped": "", "unknown": "",
}

// nmapServiceLabel turns nmap's service name (+ tunnel) into a label.
func nmapServiceLabel(name, tunnel string) string {
	if name == "" {
		return ""
	}
	if tunnel == "ssl" && (name == "http" || name == "http-proxy" || name == "http-alt") {
		return "https"
	}
	if l, ok := nmapServiceNames[name]; ok {
		return l
	}
	return strings.ToLower(name)
}

func (r *run) fingerprintWarn(msg string) {
	r.stats.Warnings = append(r.stats.Warnings, "fingerprint: "+msg)
	r.log.Warn("fingerprint pass skipped", "reason", msg)
}

// fingerprint runs the pass for the whole job.
func (r *run) fingerprint(ctx context.Context) error {
	if r.e.NmapPath == "" {
		r.fingerprintWarn("nmap not installed (only builds made after the legal sign-off carry it)")
		return nil
	}
	if _, err := os.Stat(r.e.NmapPath); err != nil {
		r.fingerprintWarn("nmap: " + err.Error())
		return nil
	}
	params := r.spec.Fingerprint
	if params == nil {
		params = v1.DefaultFingerprintParams()
	}
	fragile := r.fragilePorts()
	var hosts []string
	ports := map[int]bool{}
	for _, ip := range r.order {
		h := r.hosts[ip]
		if r.excluded(ip) || len(h.ports) == 0 {
			continue
		}
		// The fragile-device policy applies here too: nmap's probes are as
		// heavy as openvas's service detection (PLAN §10.6).
		if skip, _ := r.fragileDecision(h, fragile); skip {
			continue
		}
		hosts = append(hosts, ip)
		for _, p := range h.ports {
			if p.Proto == "tcp" {
				ports[p.Port] = true
			}
		}
	}
	if len(hosts) == 0 || len(ports) == 0 {
		r.log.Info("fingerprint skipped: no eligible hosts with open TCP ports")
		return nil
	}
	if len(hosts) > maxFingerprintHosts {
		r.fingerprintWarn(fmt.Sprintf("%d eligible hosts; only the first %d are fingerprinted", len(hosts), maxFingerprintHosts))
		hosts = hosts[:maxFingerprintHosts]
	}
	args := r.e.nmapArgs(r.spec, r.site, params, hosts, ports)
	out, err := r.e.runTool(ctx, r.e.NmapPath, "nmap", args)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.fingerprintWarn(err.Error())
		return nil
	}
	parsed, err := parseNmap(out)
	if err != nil {
		r.fingerprintWarn(err.Error())
		return nil
	}
	handed := make(map[string]bool, len(hosts))
	for _, ip := range hosts {
		handed[ip] = true
	}
	n := r.mergeNmap(parsed, handed)
	r.stats.Fingerprinted = n
	r.log.Info("fingerprint done", "hosts", n, "ports", len(ports))
	return nil
}

// nmapArgs builds the invocation: version detection (and OS detection
// when privileged) on the pinned TCP port list, no host discovery (the
// hosts are known alive), no DNS, XML on stdout, rate and parallelism
// derived from the job's rate the way naabu's are.
func (e *Engine) nmapArgs(spec v1.JobSpec, site v1.SiteConfig, params *v1.FingerprintParams, hosts []string, ports map[int]bool) []string {
	list := make([]int, 0, len(ports))
	for p := range ports {
		list = append(list, p)
	}
	sort.Ints(list)
	priv := e.privileged()
	args := []string{"-sV", "--version-intensity", strconv.Itoa(params.Intensity), "-Pn", "-n", "--noninteractive", "-oX", "-",
		"-T3", "--max-rate", strconv.Itoa(spec.Rate.PPS), "--max-parallelism", strconv.Itoa(clamp(spec.Rate.PerHostParallel*10, 10, 80)),
		"--max-retries", "2", "--host-timeout", "15m", "-p", "T:" + joinInts(list)}
	if priv {
		args = append(args, "--privileged", "-sS")
		if params.OSDetection {
			args = append(args, "-O", "--osscan-limit")
		}
	} else {
		args = append(args, "--unprivileged", "-sT")
	}
	var excl []string
	excl = append(excl, spec.Excludes...)
	excl = append(excl, site.Excludes...)
	if len(excl) > 0 {
		args = append(args, "--exclude", strings.Join(excl, ","))
	}
	if iface := e.scanIface(spec); iface != "" {
		args = append(args, "-e", iface)
	}
	return append(args, hosts...)
}

// privileged reports whether nmap may use raw sockets (SYN scan, -O):
// overridable in tests, else the platform check.
func (e *Engine) privileged() bool {
	if e.Privileged != nil {
		return e.Privileged()
	}
	return rawSocketsAllowed()
}

// mergeNmap folds nmap's findings into the host aggregates: service labels
// and products for ports that had none (or only naabu's), CPEs, MAC and
// PTR name when unknown, and the OS match as a competing guess. Only hosts
// that were handed to nmap are merged; anything else in the output is
// ignored. Returns the number of handed hosts nmap covered.
func (r *run) mergeNmap(res *nmapRun, handed map[string]bool) int {
	n := 0
	for _, nh := range res.Hosts {
		ip := nh.ip()
		if ip == "" || !handed[ip] || r.excluded(ip) {
			continue
		}
		h, ok := r.hosts[ip]
		if !ok {
			continue
		}
		n++
		if h.mac == "" {
			h.mac = nh.mac()
		}
		if h.hostname == "" {
			h.hostname = nh.ptr()
		}
		for _, np := range nh.Ports {
			if np.State.State != "open" || np.ID <= 0 {
				continue
			}
			p := h.addPort(np.ID, np.Proto, sourceNmap)
			svc := np.Service
			if svc == nil {
				continue
			}
			label := nmapServiceLabel(svc.Name, svc.Tunnel)
			if label != "" && (p.Service == "" || p.Source == "naabu" || p.Source == sourceNmap) {
				p.Service = label
			}
			// conf 10 = matched a probe response; 3 = port-table guess.
			if svc.Product != "" && svc.Conf >= 5 && (p.Product == "" || p.Source == "naabu" || p.Source == sourceNmap) {
				p.Product = strings.TrimSpace(svc.Product)
				if svc.Version != "" {
					p.Version = strings.TrimSpace(svc.Version)
				}
				p.Source = sourceNmapVersion
			}
			if p.CPE == "" {
				for _, c := range svc.CPE {
					if strings.HasPrefix(c, "cpe:/a:") {
						p.CPE = c
						break
					}
				}
			}
		}
		if nh.OS != nil {
			if g := bestOSMatch(nh.OS.Matches); g != nil {
				h.nmapOS = g
			}
		}
	}
	return n
}

// bestOSMatch picks the most accurate osmatch at or above minOSAccuracy.
func bestOSMatch(matches []nmapOSMatch) *v1.OSGuess {
	var best *nmapOSMatch
	for i := range matches {
		m := &matches[i]
		if m.Accuracy < minOSAccuracy {
			continue
		}
		if best == nil || m.Accuracy > best.Accuracy {
			best = m
		}
	}
	if best == nil {
		return nil
	}
	g := &v1.OSGuess{Name: strings.TrimSpace(best.Name), Confidence: float64(best.Accuracy) / 100, Source: sourceNmapOS}
	family := ""
	for _, c := range best.Classes {
		if family == "" {
			family = c.Family + " " + c.Vendor
		}
		if g.CPE == "" {
			for _, cpe := range c.CPE {
				if strings.HasPrefix(cpe, "cpe:/o:") || strings.HasPrefix(cpe, "cpe:/h:") {
					g.CPE = cpe
					break
				}
			}
		}
	}
	g.Family = osFamily(g.CPE, family+" "+g.Name)
	return g
}

// ErrBudget is returned when a wide port range cannot finish inside the
// time left of max_duration_s (Phase 5 full-range option).
var ErrBudget = errors.New("port scan does not fit the remaining time budget")
