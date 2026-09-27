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
	// excludes are the site's codified VT exclusions (NVT OIDs, nuclei
	// template ids with or without the "nuclei:" prefix).
	excludes   map[string]bool
	suppressed int
	// created collects findings this ingest created (Phase 6 events).
	created []*Finding
}

func newSiteIndex(siteID string, hosts []*Host, findings []*Finding) *siteIndex {
	ix := &siteIndex{siteID: siteID, hosts: hosts, findings: map[string][]*Finding{}, changed: map[string]*Host{}, changedF: map[string]*Finding{}, newHosts: map[string]bool{}, excludes: map[string]bool{}}
	for _, f := range findings {
		ix.findings[f.HostID] = append(ix.findings[f.HostID], f)
	}
	return ix
}

// setExcludes installs the site's VT exclusions.
func (ix *siteIndex) setExcludes(vts []string) {
	ix.excludes = map[string]bool{}
	for _, v := range vts {
		v = strings.TrimSpace(v)
		if v != "" {
			ix.excludes[v] = true
			ix.excludes[strings.TrimPrefix(v, "nuclei:")] = true
		}
	}
}

func (ix *siteIndex) excluded(nvtOID, templateID string) bool {
	if len(ix.excludes) == 0 {
		return false
	}
	return (nvtOID != "" && ix.excludes[nvtOID]) || (templateID != "" && (ix.excludes[templateID] || ix.excludes["nuclei:"+templateID]))
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
	// An external scanner's sighting neither makes nor breaks the
	// agent/appliance pairing (Phase 6).
	if incoming == v1.SourceExternal {
		return existing
	}
	if existing == v1.SourceExternal {
		return incoming
	}
	return v1.SourceBoth
}

// ingestAppliance applies one result chunk; scope is the job's openvas
// config name, inherited by new findings as their lifecycle scope.
func (ix *siteIndex) ingestAppliance(jobID string, in []v1.Host, feedVersion string, at time.Time, scope string) (IngestSummary, []string) {
	sum := IngestSummary{NewBySeverity: map[string]int{}}
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
		h.Ports = mergePorts(h.Ports, ih.Ports)
		h.Notes = append([]string{}, ih.Notes...)
		h.LastJobID = jobID
		h.LastSeen = at
		ix.touch(h)
		touchedIDs = append(touchedIDs, h.ID)
		ix.applianceFindings(&sum, h, ih.Findings, jobID, feedVersion, at, scope)
	}
	sum.Suppressed = ix.suppressed
	return sum, touchedIDs
}

// findingScope is the lifecycle scope of a new appliance finding: the web
// add-on for nuclei matches, else the job's openvas config, else full
// (only a full scan may resolve a finding of unknown scope).
func findingScope(inf v1.Finding, scope string) string {
	if inf.Source == "nuclei" || (inf.ID != "" && inf.NVTOID == "") {
		return v1.ScopeWeb
	}
	if scope == "" {
		return v1.ScopeFull
	}
	return scope
}

// noteNew records a created finding in the summary.
func noteNew(sum *IngestSummary, h *Host, f *Finding) {
	if sum == nil {
		return
	}
	sum.NewFindings++
	if sum.NewBySeverity == nil {
		sum.NewBySeverity = map[string]int{}
	}
	sum.NewBySeverity[f.Severity]++
	if (f.Severity == v1.SeverityCritical || f.Severity == v1.SeverityHigh) && len(sum.New) < maxNewRefs {
		sum.New = append(sum.New, FindingRef{ID: f.ID, HostID: h.ID, HostIP: h.IP, Name: f.Name, Severity: f.Severity, CVSS: f.CVSS, CVE: append([]string{}, f.CVE...), Detector: f.Detector()})
	}
}

// maxNewRefs caps the high/critical references an ingest summary carries.
const maxNewRefs = 200

// reopen brings a fixed finding back (Phase 6 lifecycle).
func reopen(f *Finding, at time.Time) {
	if f.Status != v1.FindingFixed {
		return
	}
	f.Status = v1.FindingOpen
	f.FixedAt = nil
	t := at
	f.ReopenedAt = &t
	f.Reopens++
}

// mergePorts: the new observation decides which ports are open, but the
// detail learned about a port earlier (service, product, version, CPE, the
// HTTP fingerprint) is kept when the new observation has none for it, so a
// discovery-only or port-scan-only job does not erase what an inventory or
// fingerprint pass found (Phase 5 depth; the feed-gap report reads it).
func mergePorts(prev, cur []v1.Port) []v1.Port {
	old := make(map[string]v1.Port, len(prev))
	for _, p := range prev {
		old[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = p
	}
	out := make([]v1.Port, 0, len(cur))
	for _, p := range cur {
		if o, ok := old[fmt.Sprintf("%s/%d", p.Proto, p.Port)]; ok {
			detail := false
			if p.Service == "" && o.Service != "" {
				p.Service, detail = o.Service, true
			}
			if p.Product == "" && p.Version == "" && (o.Product != "" || o.Version != "") {
				p.Product, p.Version, detail = o.Product, o.Version, true
			}
			if p.CPE == "" && o.CPE != "" {
				p.CPE, detail = o.CPE, true
			}
			if p.Web == nil && o.Web != nil {
				w := *o.Web
				p.Web = &w
			}
			if detail && (p.Source == "" || p.Source == "naabu") && o.Source != "" {
				p.Source = o.Source
			}
		}
		out = append(out, p)
	}
	return out
}

// findingIdent is the detector-side identity: the openvas OID or the
// nuclei template id.
func findingIdent(nvtOID, templateID string) string {
	if nvtOID != "" {
		return nvtOID
	}
	if templateID != "" {
		return "nuclei:" + templateID
	}
	return ""
}

func findingKey(f *Finding) string {
	return findingIdent(f.NVTOID, f.TemplateID) + "|" + f.Proto + ":" + fmt.Sprint(f.Port)
}

func (ix *siteIndex) applianceFindings(sum *IngestSummary, h *Host, in []v1.Finding, jobID, feedVersion string, at time.Time, scope string) {
	for _, inf := range in {
		sum.Findings++
		ev := v1.Evidence{Source: inf.Source, JobID: jobID, At: at, QoD: inf.QoD, Detail: inf.Evidence}
		ident := findingIdent(inf.NVTOID, inf.ID)
		key := ident + "|" + inf.Proto + ":" + fmt.Sprint(inf.Port)
		excluded := ix.excluded(inf.NVTOID, inf.ID)
		var target *Finding
		for _, f := range ix.findings[h.ID] {
			if ident != "" && findingKey(f) == key {
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
			f := &Finding{ID: NewID("fnd"), HostID: h.ID, Source: inf.Source, NVTOID: inf.NVTOID, TemplateID: inf.ID, Name: inf.Name, Family: inf.Family,
				Severity: inf.Severity, CVSS: inf.CVSS, CVE: append([]string{}, inf.CVE...), QoD: inf.QoD, Port: inf.Port, Proto: inf.Proto,
				Solution: inf.Solution, Evidence: []v1.Evidence{ev}, FeedVersion: feedVersion, FirstSeen: at, LastSeen: at,
				Status: v1.FindingOpen, Scope: findingScope(inf, scope)}
			f.State = v1.FindingNetworkObserved
			if inf.QoD < QoDConfirmed {
				f.State = v1.FindingSuspected
			}
			if excluded {
				// Codified exclusion (an older appliance still reported it):
				// keep the record for the audit trail, reviewed as a false positive.
				f.Review, f.ReviewedBy, f.ReviewReason, f.ReviewedAt = v1.ReviewFalsePositive, "policy", "site exclusion", &at
				ix.suppressed++
			}
			ix.addFinding(f)
			ix.created = append(ix.created, f)
			noteNew(sum, h, f)
			continue
		}
		reopen(target, at)
		if target.Scope == "" || (target.Scope == v1.ScopeFull && scope == v1.ScopeInventory && inf.Source != "nuclei") {
			// A finding an inventory scan can see is resolvable by one.
			target.Scope = findingScope(inf, scope)
		}
		if excluded && target.Review == "" {
			target.Review, target.ReviewedBy, target.ReviewReason, target.ReviewedAt = v1.ReviewFalsePositive, "policy", "site exclusion", &at
			ix.suppressed++
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
		if target.NVTOID == "" && target.TemplateID == "" {
			target.NVTOID, target.TemplateID, target.Family, target.Port, target.Proto, target.Solution = inf.NVTOID, inf.ID, inf.Family, inf.Port, inf.Proto, inf.Solution
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
}

// ingestExternal applies an external scanner's export (Qualys during the
// migration, PLAN §22 "accept exports from their own scanner as
// evidence"): hosts are matched by hostname then IP, findings by the
// scanner's id and port, else by CVE against any finding on the host, so
// the same CVE seen by the appliance and the external scanner becomes one
// finding with two evidence entries. Informational rows are skipped; a
// row the scanner reports as fixed closes the finding when only the
// external scanner ever saw it.
func (ix *siteIndex) ingestExternal(scanner string, in []v1.ExternalHost, at time.Time) IngestSummary {
	sum := IngestSummary{NewBySeverity: map[string]int{}}
	for _, eh := range in {
		ip := strings.TrimSpace(eh.IP)
		if ip == "" && strings.TrimSpace(eh.Hostname) == "" {
			continue
		}
		sum.Hosts++
		h := ix.match(nil, eh.Hostname, ip)
		if h == nil {
			h = &Host{ID: NewID("host"), SiteID: ix.siteID, IP: ip, Hostname: strings.TrimSpace(eh.Hostname), Source: v1.SourceExternal, FirstSeen: at}
			ix.addHost(h)
			sum.Created++
		} else {
			if h.Source != v1.SourceExternal {
				sum.Merged++
			}
			h.Source = mergeSource(h.Source, v1.SourceExternal)
		}
		if h.IP == "" {
			h.IP = ip
		}
		if h.Hostname == "" && eh.Hostname != "" {
			h.Hostname = strings.TrimSpace(eh.Hostname)
		}
		if eh.OS != "" && h.OSGuess == nil {
			h.OSGuess = &v1.OSGuess{Family: externalOSFamily(eh.OS), Name: eh.OS, Source: scanner + ":os", Confidence: 0.5}
		}
		if at.After(h.LastSeen) {
			h.LastSeen = at
		}
		ix.touch(h)
		for _, ef := range eh.Findings {
			typ := strings.ToLower(strings.TrimSpace(ef.Type))
			sev := strings.ToLower(strings.TrimSpace(ef.Severity))
			if sev == "" {
				sev = v1.SeverityFor(ef.CVSS)
			}
			if typ == "info" || (sev == v1.SeverityInfo && len(ef.CVE) == 0) {
				sum.Skipped++
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(ef.Proto))
			if proto == "" && ef.Port > 0 {
				proto = "tcp"
			}
			seen := at
			if ef.LastSeen != nil && !ef.LastSeen.IsZero() {
				seen = *ef.LastSeen
			}
			first := seen
			if ef.FirstSeen != nil && !ef.FirstSeen.IsZero() {
				first = *ef.FirstSeen
			}
			cves := normCVEs(ef.CVE)
			if ef.Port > 0 {
				addPortIfMissing(h, ef.Port, proto, scanner)
			}
			ev := v1.Evidence{Source: scanner, At: seen, Detail: strings.TrimSpace(ef.Evidence)}
			ident := scanner + ":" + strings.TrimSpace(ef.ID)
			var target *Finding
			for _, f := range ix.findings[h.ID] {
				if f.Source == scanner && f.ExternalID == strings.TrimSpace(ef.ID) && f.Port == ef.Port && f.Proto == proto {
					target = f
					break
				}
			}
			if target == nil && len(cves) > 0 {
				for _, f := range ix.findings[h.ID] {
					if overlaps(f.CVE, cves) {
						target = f
						break
					}
				}
			}
			status := strings.ToLower(strings.TrimSpace(ef.Status))
			if status == "fixed" {
				if target != nil && target.IsOpen() && target.Source == scanner {
					target.Status = v1.FindingFixed
					t := seen
					target.FixedAt = &t
					sum.Fixed++
					ix.touchF(target)
				} else {
					sum.Skipped++
				}
				continue
			}
			sum.Findings++
			if target == nil {
				f := &Finding{ID: NewID("fnd"), HostID: h.ID, Source: scanner, Name: strings.TrimSpace(ef.Name), Severity: sev, CVSS: ef.CVSS, CVE: cves,
					Port: ef.Port, Proto: proto, Solution: strings.TrimSpace(ef.Solution), Evidence: []v1.Evidence{ev}, FirstSeen: first, LastSeen: seen,
					Status: v1.FindingOpen, Scope: scanner, ExternalID: strings.TrimSpace(ef.ID)}
				f.State = v1.FindingNetworkObserved
				if typ == "potential" {
					f.State = v1.FindingSuspected
				}
				if f.Name == "" {
					f.Name = ident
				}
				ix.addFinding(f)
				ix.created = append(ix.created, f)
				noteNew(&sum, h, f)
				continue
			}
			reopen(target, seen)
			target.Evidence = appendEvidence(target.Evidence, ev)
			if seen.After(target.LastSeen) {
				target.LastSeen = seen
			}
			if target.ExternalID == "" {
				target.ExternalID = strings.TrimSpace(ef.ID)
			}
			target.CVE = union(target.CVE, cves)
			if target.CVSS == 0 && ef.CVSS > 0 {
				target.CVSS, target.Severity = ef.CVSS, sev
			}
			if target.Solution == "" {
				target.Solution = strings.TrimSpace(ef.Solution)
			}
			// Two independent scanners agreeing is as good as agent
			// confirmation; a "potential" match confirms nothing.
			if target.NetworkScanner() && typ != "potential" && target.State != v1.FindingConfirmed {
				target.State = v1.FindingConfirmed
			}
			ix.touchF(target)
		}
	}
	sum.Suppressed = ix.suppressed
	return sum
}

// addPortIfMissing records a port an external finding implies is open.
func addPortIfMissing(h *Host, port int, proto, source string) {
	for _, p := range h.Ports {
		if p.Port == port && p.Proto == proto {
			return
		}
	}
	h.Ports = append(h.Ports, v1.Port{Port: port, Proto: proto, Source: source})
}

func normCVEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if strings.HasPrefix(c, "CVE-") && !contains(out, c) {
			out = append(out, c)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func externalOSFamily(os string) string {
	s := strings.ToLower(os)
	switch {
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "linux"), strings.Contains(s, "ubuntu"), strings.Contains(s, "debian"), strings.Contains(s, "red hat"), strings.Contains(s, "centos"):
		return "linux"
	case strings.Contains(s, "cisco"), strings.Contains(s, "juniper"), strings.Contains(s, "forti"), strings.Contains(s, "palo alto"), strings.Contains(s, "pan-os"):
		return "network"
	case strings.Contains(s, "printer"), strings.Contains(s, "jetdirect"), strings.Contains(s, "embedded"):
		return "embedded"
	case s == "":
		return ""
	}
	return "other"
}

// fragileKeptAway reports whether the notes say detection skipped the host
// under the fragile-device policy (its findings were not tested).
func fragileKeptAway(notes []string) bool {
	for _, n := range notes {
		if strings.HasPrefix(n, "fragile:") && !strings.HasPrefix(n, "fragile:cleared:") {
			return true
		}
	}
	return false
}

// resolveScopes expands the scopes a job covers: a full scan also covers
// findings of unknown (pre-lifecycle) scope.
func resolveScopes(scopes []string) map[string]bool {
	set := map[string]bool{}
	for _, s := range scopes {
		set[s] = true
	}
	if set[v1.ScopeFull] {
		set[""] = true
	}
	return set
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
