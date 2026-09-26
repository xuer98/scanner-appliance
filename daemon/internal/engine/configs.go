// Package engine orchestrates a job's phases (PLAN §10): naabu discovery
// and port scan, then openvas over OSP with the port list pinned from
// naabu, and normalizes everything into the v1 result model (PLAN §12.1).
package engine

import (
	"fmt"
	"sort"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// ScanConfig is one openvas scan config (PLAN §10.4). Phase 3 moves these
// into the signed bundle; until then they ship with the daemon.
type ScanConfig struct {
	Name     string
	Families []string
	// UDPPorts is the small UDP set openvas may probe (naabu is TCP-only).
	UDPPorts []int
	// Params are scanner_params sent with every scan of this config.
	Params map[string]string
}

var udpSmallSet = []int{53, 67, 69, 111, 123, 137, 161, 162, 500, 514, 520, 1434, 1900, 4500, 5353}

// detectionFamilies are always part of a scan: they feed service/product/OS
// detection and populate the port and os_guess fields.
var detectionFamilies = []string{"Service detection", "Product detection", "General"}

// remoteFamilies are the unauthenticated network-check families of the
// Greenbone community feed. Authenticated-only families ("* Local Security
// Checks", Credentials, Compliance, Policy, IT-Grundschutz) are never
// selected: the appliance has no credentials (PLAN non-goals). Denial of
// Service and Brute force attacks are excluded by policy (PLAN §10.4, §16).
var remoteFamilies = []string{
	"Buffer overflow", "CISCO", "Databases", "Default Accounts", "F5", "FTP", "Finger abuses", "Firewalls",
	"Gain a shell remotely", "Huawei", "JunOS", "Malware", "Nmap NSE", "Nmap NSE net", "Palo Alto PAN-OS",
	"Peer-To-Peer File Sharing", "Port scanners", "Privilege escalation", "RPC", "Remote file access",
	"SMTP problems", "SNMP", "SSL and TLS", "Useless services", "Web Servers", "Web application abuses",
	"Windows", "Windows : Microsoft Bulletins",
}

// ExcludedFamilies are never selectable in any config.
var ExcludedFamilies = map[string]bool{"Denial of Service": true, "Brute force attacks": true}

// Configs are the shipped scan configs, by name.
var Configs = map[string]ScanConfig{
	"inventory": {
		Name:     "inventory",
		Families: append(append([]string{}, detectionFamilies...), "Web Servers", "Windows", "Windows : Microsoft Bulletins", "SSL and TLS", "Databases", "Default Accounts"),
		UDPPorts: udpSmallSet,
		Params:   map[string]string{"optimize_test": "1", "auto_enable_dependencies": "1", "timeout_retry": "2", "scanner_plugins_timeout": "3600", "report_host_details": "1"},
	},
	"full": {
		Name:     "full",
		Families: append(append([]string{}, detectionFamilies...), remoteFamilies...),
		UDPPorts: udpSmallSet,
		Params:   map[string]string{"optimize_test": "1", "auto_enable_dependencies": "1", "timeout_retry": "3", "scanner_plugins_timeout": "7200", "report_host_details": "1"},
	},
}

// ConfigFor returns the config after removing anything on the exclusion list.
func ConfigFor(name string) (ScanConfig, error) {
	c, ok := Configs[name]
	if !ok {
		return ScanConfig{}, fmt.Errorf("unknown openvas config %q", name)
	}
	out := c
	out.Families = nil
	seen := map[string]bool{}
	for _, f := range c.Families {
		if !ExcludedFamilies[f] && !seen[f] {
			seen[f] = true
			out.Families = append(out.Families, f)
		}
	}
	return out, nil
}

// standardExtraPorts complement naabu's top-1000 list for warehouse/OT
// environments: remote access, printers, industrial protocols, databases,
// management planes.
var standardExtraPorts = []int{
	22, 23, 25, 53, 80, 88, 110, 111, 135, 137, 139, 143, 389, 443, 445, 464, 465, 587, 593, 636, 993, 995,
	1433, 1434, 1521, 1883, 2049, 2375, 2376, 3268, 3269, 3306, 3389, 4786, 5060, 5061, 5432, 5900, 5901,
	5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8883, 8888, 9090, 9100, 9200, 9443, 10000, 11211, 27017,
	102, 502, 515, 631, 1911, 2222, 4840, 20000, 44818, 47808, 623, 830, 161,
}

// portArgs turns a job port spec into naabu arguments.
func portArgs(spec string) ([]string, error) {
	ranges, err := v1.ParsePortSpec(spec)
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(spec) {
	case "", v1.PortsStandard:
		return []string{"-top-ports", "1000", "-p", joinInts(standardExtraPorts)}, nil
	case v1.PortsFull:
		return []string{"-p", "-"}, nil
	}
	var parts []string
	for _, r := range ranges {
		if r.Lo == r.Hi {
			parts = append(parts, fmt.Sprint(r.Lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return []string{"-p", strings.Join(parts, ",")}, nil
}

func joinInts(in []int) string {
	s := make([]string, len(in))
	for i, v := range in {
		s[i] = fmt.Sprint(v)
	}
	return strings.Join(s, ",")
}

// openvasPortList renders the pinned port list: the union of naabu's open
// TCP ports plus the config's UDP set.
func openvasPortList(tcp map[int]bool, udp []int) string {
	var t []int
	for p := range tcp {
		t = append(t, p)
	}
	sort.Ints(t)
	var sb strings.Builder
	if len(t) > 0 {
		sb.WriteString("T:" + joinInts(t))
	}
	if len(udp) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("U:" + joinInts(udp))
	}
	return sb.String()
}
