// Package scanconfig holds the openvas scan configs of PLAN §10.4. The
// defaults ship in the daemon; a signature bundle may carry
// configs/<name>.json files that override them (PLAN §13), so the same
// type and validation live here for both the daemon and cp-api's bundle
// builder.
package scanconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Config is one openvas scan config.
type Config struct {
	Name     string   `json:"name"`
	Families []string `json:"families"`
	// UDPPorts is the UDP part of the port list in a job that runs the udp
	// module, and unused otherwise. It bounds a UDP port scan when openvas
	// can run one (its nmap wrapper); it does not bound the UDP tests
	// themselves, which probe their own well-known ports.
	UDPPorts []int `json:"udp_ports"`
	// Params are scanner_params sent with every scan of this config.
	Params map[string]string `json:"params"`
}

// UDPSmallSet is the default UDPPorts.
var UDPSmallSet = []int{53, 67, 69, 111, 123, 137, 161, 162, 500, 514, 520, 1434, 1900, 4500, 5353}

// DetectionFamilies are always part of a scan: they feed service/product/OS
// detection and populate the port and os_guess fields.
var DetectionFamilies = []string{"Service detection", "Product detection", "General"}

// PortScannerVT is the feed's "SYN Scan" test, selected in every scan on
// top of the config's families. openvas treats a port as closed until one
// of its own port scanner tests has checked it, so a scan without one
// probes nothing and still finishes cleanly. This test checks only the
// port list the job pins from naabu. It is selected on its own because the
// "Port scanners" family also holds wrappers that run nmap, snmpwalk and
// pnscan when those tools are installed, and the feed's other built-in
// scanner ("OpenVAS TCP scanner") does not unblock the engine by itself.
const PortScannerVT = "1.3.6.1.4.1.25623.1.0.11219"

// RemoteFamilies are the unauthenticated network-check families of the
// Greenbone community feed. Authenticated-only families ("* Local Security
// Checks", Credentials, Compliance, Policy, IT-Grundschutz) are never
// selected: the appliance has no credentials (PLAN non-goals). Denial of
// Service and Brute force attacks are excluded by policy (PLAN §10.4, §16).
var RemoteFamilies = []string{
	"Buffer overflow", "CISCO", "Databases", "Default Accounts", "F5", "FTP", "Finger abuses", "Firewalls",
	"Gain a shell remotely", "Huawei", "JunOS", "Malware", "Nmap NSE", "Nmap NSE net", "Palo Alto PAN-OS",
	"Peer-To-Peer File Sharing", "Port scanners", "Privilege escalation", "RPC", "Remote file access",
	"SMTP problems", "SNMP", "SSL and TLS", "Useless services", "Web Servers", "Web application abuses",
	"Windows", "Windows : Microsoft Bulletins",
}

// ExcludedFamilies are never selectable in any config, shipped or bundled.
var ExcludedFamilies = map[string]bool{"Denial of Service": true, "Brute force attacks": true}

// forbiddenSuffix catches the authenticated families whatever their prefix.
const forbiddenSuffix = "Local Security Checks"

// Defaults returns the shipped configs (fresh copies).
func Defaults() map[string]Config {
	return map[string]Config{
		"inventory": {
			Name:     "inventory",
			Families: append(append([]string{}, DetectionFamilies...), "Web Servers", "Windows", "Windows : Microsoft Bulletins", "SSL and TLS", "Databases", "Default Accounts"),
			UDPPorts: append([]int{}, UDPSmallSet...),
			Params:   map[string]string{"optimize_test": "1", "auto_enable_dependencies": "1", "timeout_retry": "2", "scanner_plugins_timeout": "3600", "report_host_details": "1"},
		},
		"full": {
			Name:     "full",
			Families: append(append([]string{}, DetectionFamilies...), RemoteFamilies...),
			UDPPorts: append([]int{}, UDPSmallSet...),
			Params:   map[string]string{"optimize_test": "1", "auto_enable_dependencies": "1", "timeout_retry": "3", "scanner_plugins_timeout": "7200", "report_host_details": "1"},
		},
	}
}

// Validate checks a config (bundled or shipped) against policy.
func (c Config) Validate() error {
	if c.Name == "" || strings.ContainsAny(c.Name, "/\\ .") {
		return fmt.Errorf("scanconfig: bad name %q", c.Name)
	}
	if len(c.Families) == 0 {
		return fmt.Errorf("scanconfig %s: no families", c.Name)
	}
	for _, f := range c.Families {
		if ExcludedFamilies[f] || strings.HasSuffix(f, forbiddenSuffix) {
			return fmt.Errorf("scanconfig %s: family %q is not selectable", c.Name, f)
		}
	}
	for _, p := range c.UDPPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("scanconfig %s: bad udp port %d", c.Name, p)
		}
	}
	if v, ok := c.Params["safe_checks"]; ok && v != "1" {
		return fmt.Errorf("scanconfig %s: safe_checks may not be forced off", c.Name)
	}
	return nil
}

// Resolved returns a copy with excluded and duplicate families removed and
// the detection families guaranteed present.
func (c Config) Resolved() Config {
	out := c
	out.Families = nil
	seen := map[string]bool{}
	for _, f := range append(append([]string{}, DetectionFamilies...), c.Families...) {
		if !ExcludedFamilies[f] && !strings.HasSuffix(f, forbiddenSuffix) && !seen[f] {
			seen[f] = true
			out.Families = append(out.Families, f)
		}
	}
	out.Params = map[string]string{}
	for k, v := range c.Params {
		out.Params[k] = v
	}
	return out
}

// Load reads every *.json in dir. A missing dir yields an empty map.
func Load(dir string) (map[string]Config, error) {
	out := map[string]Config{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("scanconfig %s: %w", e.Name(), err)
		}
		if c.Name == "" {
			c.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		if c.Name != strings.TrimSuffix(e.Name(), ".json") {
			return nil, fmt.Errorf("scanconfig %s: name %q does not match the file", e.Name(), c.Name)
		}
		if err := c.Validate(); err != nil {
			return nil, err
		}
		out[c.Name] = c
	}
	return out, nil
}

// Lookup returns the named config from overrides, else the defaults, with
// policy exclusions applied.
func Lookup(name string, overrides map[string]Config) (Config, error) {
	if c, ok := overrides[name]; ok {
		return c.Resolved(), nil
	}
	if c, ok := Defaults()[name]; ok {
		return c.Resolved(), nil
	}
	return Config{}, fmt.Errorf("unknown openvas config %q", name)
}

// WriteDefaults writes the shipped configs as JSON files into dir (used by
// the bundle builder).
func WriteDefaults(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	d := Defaults()
	names := make([]string, 0, len(d))
	for n := range d {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := json.MarshalIndent(d[n], "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, n+".json"), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}
