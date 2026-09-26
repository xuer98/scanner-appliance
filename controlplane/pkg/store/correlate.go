package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Correlation of appliance results with agent data (PLAN §12.3):
//
//   - identity: MAC first, then hostname, then IP
//   - packages: agent inventory wins; the appliance never overrides it
//   - exposure: the appliance wins for open ports / reachable services
//   - findings: same host + same CVE from both sources → one finding with
//     two evidence entries; agent evidence marks it confirmed, openvas-only
//     stays network_observed; openvas with qod < 70 is suspected until a
//     second scan or agent data confirms it
//
// The logic is pure so the memory and Postgres stores share it: a backend
// loads the site's hosts and findings into a siteIndex, applies an ingest
// and persists what changed.

// QoDConfirmed is the quality-of-detection threshold (PLAN §12.3).
const QoDConfirmed = 70

type siteIndex struct {
	siteID   string
	hosts    []*Host
	findings map[string][]*Finding // by host id
	changed  map[string]*Host
	changedF map[string]*Finding
	newHosts map[string]bool
}

func newSiteIndex(siteID string, hosts []*Host, findings []*Finding) *siteIndex {
	ix := &siteIndex{siteID: siteID, hosts: hosts, findings: map[string][]*Finding{}, changed: map[string]*Host{}, changedF: map[string]*Finding{}, newHosts: map[string]bool{}}
	for _, f := range findings {
		ix.findings[f.HostID] = append(ix.findings[f.HostID], f)
	}
	return ix
}

func normMAC(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	m = strings.ReplaceAll(m, "-", ":")
	if m == "00:00:00:00:00:00" {
		return ""
	}
	return m
}

func normHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "."); i > 0 {
		h = h[:i] // short name: agents and reverse DNS disagree on domains
	}
	switch h {
	case "", "localhost", "unknown":
		return ""
	}
	return h
}

// match finds the host identified by any of the MACs, then the hostname,
// then the IP (weakest: DHCP segments).
func (ix *siteIndex) match(macs []string, hostname, ip string) *Host {
	for _, m := range macs {
		if m = normMAC(m); m != "" {
			for _, h := range ix.hosts {
				if normMAC(h.MAC) == m {
					return h
				}
			}
		}
	}
	if hn := normHostname(hostname); hn != "" {
		for _, h := range ix.hosts {
			if normHostname(h.Hostname) == hn {
				return h
			}
		}
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		for _, h := range ix.hosts {
			if h.IP == ip {
				return h
			}
		}
	}
	return nil
}

func (ix *siteIndex) touch(h *Host) { ix.changed[h.ID] = h }

func (ix *siteIndex) addHost(h *Host) {
	ix.hosts = append(ix.hosts, h)
	ix.newHosts[h.ID] = true
	ix.touch(h)
}

func (ix *siteIndex) touchF(f *Finding) { ix.changedF[f.ID] = f }

func (ix *siteIndex) addFinding(f *Finding) {
	ix.findings[f.HostID] = append(ix.findings[f.HostID], f)
	ix.touchF(f)
}

func mergeSource(existing, incoming string) string {
	if existing == "" || existing == incoming {
		return incoming
	}
	return v1.SourceBoth
}

// ingestAppliance applies one result chunk.
func (ix *siteIndex) ingestAppliance(jobID string, in []v1.Host, feedVersion string, at time.Time) (IngestSummary, []string) {
	var sum IngestSummary
	var touchedIDs []string
	for _, ih := range in {
		if strings.TrimSpace(ih.IP) == "" {
			continue
		}
		sum.Hosts++
		h := ix.match([]string{ih.MAC}, ih.Hostname, ih.IP)
		if h == nil {
			h = &Host{ID: NewID("host"), SiteID: ix.siteID, IP: ih.IP, Source: v1.SourceAppliance, FirstSeen: at}
			ix.addHost(h)
			sum.Created++
		} else {
			if h.Source == v1.SourceAgent {
				sum.Merged++
			}
			h.Source = mergeSource(h.Source, v1.SourceAppliance)
		}
		// Observation wins for reachability data; identity fields only fill gaps
		// (the agent's hostname is authoritative when present).
		h.IP = ih.IP
		if h.MAC == "" && ih.MAC != "" {
			h.MAC = normMAC(ih.MAC)
		}
		if h.Hostname == "" || (h.AgentID == "" && ih.Hostname != "") {
			if ih.Hostname != "" {
				h.Hostname = ih.Hostname
			}
		}
		if ih.OSGuess != nil {
			g := *ih.OSGuess
			h.OSGuess = &g
		}
		h.Ports = append([]v1.Port{}, ih.Ports...)
		h.Notes = append([]string{}, ih.Notes...)
		h.LastJobID = jobID
		h.LastSeen = at
		ix.touch(h)
		touchedIDs = append(touchedIDs, h.ID)
		sum.Findings += ix.applianceFindings(h, ih.Findings, jobID, feedVersion, at)
	}
	return sum, touchedIDs
}

func findingKey(f *Finding) string {
	return f.NVTOID + "|" + f.Proto + ":" + fmt.Sprint(f.Port)
}

func (ix *siteIndex) applianceFindings(h *Host, in []v1.Finding, jobID, feedVersion string, at time.Time) int {
	n := 0
	for _, inf := range in {
		n++
		ev := v1.Evidence{Source: inf.Source, JobID: jobID, At: at, QoD: inf.QoD, Detail: inf.Evidence}
		key := inf.NVTOID + "|" + inf.Proto + ":" + fmt.Sprint(inf.Port)
		var target *Finding
		for _, f := range ix.findings[h.ID] {
			if f.NVTOID != "" && findingKey(f) == key {
				target = f
				break
			}
		}
		if target == nil && len(inf.CVE) > 0 {
			// Cross-source dedupe by CVE (PLAN §12.3).
			for _, f := range ix.findings[h.ID] {
				if f.Source == v1.SourceAgent && overlaps(f.CVE, inf.CVE) {
					target = f
					break
				}
			}
		}
		if target == nil {
			f := &Finding{ID: NewID("fnd"), HostID: h.ID, Source: inf.Source, NVTOID: inf.NVTOID, Name: inf.Name, Family: inf.Family,
				Severity: inf.Severity, CVSS: inf.CVSS, CVE: append([]string{}, inf.CVE...), QoD: inf.QoD, Port: inf.Port, Proto: inf.Proto,
				Solution: inf.Solution, Evidence: []v1.Evidence{ev}, FeedVersion: feedVersion, FirstSeen: at, LastSeen: at}
			f.State = v1.FindingNetworkObserved
			if inf.QoD < QoDConfirmed {
				f.State = v1.FindingSuspected
			}
			ix.addFinding(f)
			continue
		}
		secondScan := false
		for _, e := range target.Evidence {
			if e.Source != v1.SourceAgent && e.JobID != jobID {
				secondScan = true
			}
		}
		target.Evidence = appendEvidence(target.Evidence, ev)
		target.LastSeen = at
		target.FeedVersion = feedVersion
		if target.NVTOID == "" {
			target.NVTOID, target.Family, target.Port, target.Proto, target.Solution = inf.NVTOID, inf.Family, inf.Port, inf.Proto, inf.Solution
		}
		if inf.Name != "" && (target.Name == "" || target.Source != v1.SourceAgent) {
			target.Name = inf.Name
		}
		if inf.CVSS > 0 {
			target.CVSS, target.Severity = inf.CVSS, inf.Severity
		}
		if inf.QoD > target.QoD {
			target.QoD = inf.QoD
		}
		target.CVE = union(target.CVE, inf.CVE)
		switch {
		case target.Source == v1.SourceAgent:
			target.Source = v1.SourceBoth
			target.State = v1.FindingConfirmed
		case target.State == v1.FindingSuspected && (inf.QoD >= QoDConfirmed || secondScan):
			target.State = v1.FindingNetworkObserved
		}
		ix.touchF(target)
	}
	return n
}

// ingestAgent applies agent-track inventory.
func (ix *siteIndex) ingestAgent(in []v1.AgentHost, at time.Time) IngestSummary {
	var sum IngestSummary
	for _, ah := range in {
		if ah.AgentID == "" && ah.Hostname == "" && ah.IP == "" {
			continue
		}
		sum.Hosts++
		var h *Host
		for _, x := range ix.hosts {
			if ah.AgentID != "" && x.AgentID == ah.AgentID {
				h = x
				break
			}
		}
		if h == nil {
			h = ix.match(ah.MACs, ah.Hostname, ah.IP)
		}
		if h == nil {
			h = &Host{ID: NewID("host"), SiteID: ix.siteID, Source: v1.SourceAgent, FirstSeen: at}
			ix.addHost(h)
			sum.Created++
		} else {
			if h.Source == v1.SourceAppliance {
				sum.Merged++
			}
			h.Source = mergeSource(h.Source, v1.SourceAgent)
		}
		h.AgentID = ah.AgentID
		if ah.Hostname != "" {
			h.Hostname = ah.Hostname // agent wins for identity
		}
		if h.MAC == "" {
			for _, m := range ah.MACs {
				if normMAC(m) != "" {
					h.MAC = normMAC(m)
					break
				}
			}
		}
		if h.IP == "" && ah.IP != "" {
			h.IP = ah.IP
		}
		if ah.OS != "" {
			h.AgentOS = ah.OS
		}
		if ah.Packages != nil {
			h.Packages = append([]v1.AgentPackage{}, ah.Packages...) // agent wins for packages
		}
		h.LastSeen = at
		ix.touch(h)
		for _, af := range ah.Findings {
			cve := strings.ToUpper(strings.TrimSpace(af.CVE))
			if cve == "" {
				continue
			}
			sum.Findings++
			ev := v1.Evidence{Source: v1.SourceAgent, At: at, Detail: strings.TrimSpace(af.Package + " " + af.Detail)}
			var target *Finding
			for _, f := range ix.findings[h.ID] {
				if contains(f.CVE, cve) {
					target = f
					break
				}
			}
			if target == nil {
				sev := af.Severity
				if sev == "" {
					sev = v1.SeverityFor(af.CVSS)
				}
				name := cve
				if af.Package != "" {
					name = cve + " in " + af.Package
				}
				ix.addFinding(&Finding{ID: NewID("fnd"), HostID: h.ID, Source: v1.SourceAgent, State: v1.FindingConfirmed, Name: name,
					Severity: sev, CVSS: af.CVSS, CVE: []string{cve}, Evidence: []v1.Evidence{ev}, FirstSeen: at, LastSeen: at})
				continue
			}
			target.Evidence = appendEvidence(target.Evidence, ev)
			target.LastSeen = at
			target.State = v1.FindingConfirmed
			if target.Source != v1.SourceAgent {
				target.Source = v1.SourceBoth
			}
			if target.CVSS == 0 && af.CVSS > 0 {
				target.CVSS, target.Severity = af.CVSS, v1.SeverityFor(af.CVSS)
			}
			ix.touchF(target)
		}
	}
	return sum
}

func appendEvidence(list []v1.Evidence, ev v1.Evidence) []v1.Evidence {
	for i, e := range list {
		if e.Source == ev.Source && e.JobID == ev.JobID && (ev.JobID != "" || e.Detail == ev.Detail) {
			list[i] = ev // same observation refreshed
			return list
		}
	}
	list = append(list, ev)
	if len(list) > 50 {
		list = list[len(list)-50:]
	}
	return list
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, x := range b {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// sortHosts orders by IP text then id for stable listings.
func sortHosts(hs []*Host) {
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].IP != hs[j].IP {
			return hs[i].IP < hs[j].IP
		}
		return hs[i].ID < hs[j].ID
	})
}

func sortFindings(fs []*Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].CVSS != fs[j].CVSS {
			return fs[i].CVSS > fs[j].CVSS
		}
		return fs[i].ID < fs[j].ID
	})
}
