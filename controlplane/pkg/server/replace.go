package server

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/qualys"
)

// Phase 6 (Qualys replacement): external scanner imports and the parity
// report that measures the appliance against them, the finding lifecycle
// hook at ingest, SLA ageing, per-site and per-vendor summaries, the
// weekly trend, and CSV exports for the portal and for auditors.

// DefaultSLADays are the days a finding may stay open per severity for
// Tier 1 and 2 vendors; Tier 3 and 4 get twice as long.
var DefaultSLADays = map[string]int{v1.SeverityCritical: 15, v1.SeverityHigh: 30, v1.SeverityMedium: 90, v1.SeverityLow: 180}

// riskWeights turn open findings into risk points (network-reachable
// findings are multiplied by v1.ExposureMultiplier, PLAN §12.3).
var riskWeights = map[string]int{v1.SeverityCritical: 10, v1.SeverityHigh: 5, v1.SeverityMedium: 2, v1.SeverityLow: 1}

const (
	maxExternalHosts    = 20000
	maxExternalFindings = 200000
	maxExternalBody     = 64 << 20
	parityDefaultDays   = 60
	parityTop           = 50
	summaryTop          = 10
	trendMaxWeeks       = 52
)

// slaDays is the SLA for a severity at a vendor tier (0 = unknown tier,
// treated as strict).
func (s *Server) slaDays(severity string, tier int) int {
	table := s.cfg.SLADays
	if len(table) == 0 {
		table = DefaultSLADays
	}
	d := table[severity]
	if tier >= 3 {
		d *= 2
	}
	return d
}

func daysOpen(f *store.Finding, now time.Time) int {
	end := now
	if !f.IsOpen() && f.FixedAt != nil {
		end = *f.FixedAt
	}
	d := int(end.Sub(f.FirstSeen).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func (s *Server) overdue(f *store.Finding, tier int, now time.Time) bool {
	if !f.IsOpen() || f.Review == v1.ReviewFalsePositive || f.Review == v1.ReviewAccepted {
		return false
	}
	sla := s.slaDays(f.Severity, tier)
	return sla > 0 && daysOpen(f, now) > sla
}

// findingView renders a finding with lifecycle and SLA fields (tier 0:
// strict SLA; callers with the vendor at hand use findingViewTier).
func (s *Server) findingView(f *store.Finding) v1.AdminFindingView { return s.findingViewTier(f, 0) }

func (s *Server) findingViewTier(f *store.Finding, tier int) v1.AdminFindingView {
	v := findingView(f)
	now := s.cfg.Now()
	v.Status = f.Status
	if v.Status == "" {
		v.Status = v1.FindingOpen
	}
	v.FixedAt, v.ReopenedAt, v.Reopens, v.Scope, v.ExternalID = f.FixedAt, f.ReopenedAt, f.Reopens, f.Scope, f.ExternalID
	v.DaysOpen = daysOpen(f, now)
	v.SLADays = s.slaDays(f.Severity, tier)
	v.Overdue = s.overdue(f, tier, now)
	return v
}

// ---- lifecycle hook (called by the results handler on the final chunk) ----

// jobScope is the openvas config a job runs (the lifecycle scope its
// findings inherit); "" for jobs without detection.
func jobScope(job *store.Job) string {
	if job.Spec.HasModule(v1.ModuleOpenVAS) && job.Spec.OpenVAS != nil {
		return job.Spec.OpenVAS.Config
	}
	return ""
}

// jobScopes lists the finding scopes a completed job can resolve: a full
// scan covers inventory findings too; the web module covers web findings,
// and those of the default-login checks only with the default_logins
// module; findings on UDP ports are covered only when the job ran the udp
// module. A web phase the appliance skipped or cut short (stats carries a
// "web:" warning) covers nothing: it did not look, so what it did not see
// is not fixed.
func jobScopes(job *store.Job, stats *v1.ScanStats) []string {
	var out []string
	switch jobScope(job) {
	case v1.ScopeFull:
		out = append(out, v1.ScopeInventory, v1.ScopeFull)
	case v1.ScopeInventory:
		out = append(out, v1.ScopeInventory)
	}
	if job.Spec.HasModule(v1.ModuleUDP) {
		for _, sc := range append([]string{}, out...) {
			out = append(out, v1.UDPScope(sc))
		}
	}
	if job.Spec.HasModule(v1.ModuleWeb) && !webIncomplete(stats) {
		out = append(out, v1.ScopeWeb)
		if job.Spec.HasModule(v1.ModuleDefaultLogins) {
			out = append(out, v1.ScopeWebLogins)
		}
	}
	return out
}

// webIncomplete reports whether the appliance warned about its web phase:
// the tools or the templates were missing, or there were more targets
// than it probes. Its note that a few templates did not load ("nuclei: ...")
// is not such a warning: the phase ran.
func webIncomplete(stats *v1.ScanStats) bool {
	if stats == nil {
		return false
	}
	for _, w := range stats.Warnings {
		if strings.HasPrefix(w, "web:") {
			return true
		}
	}
	return false
}

func jobStart(job *store.Job) time.Time {
	switch {
	case job.StartedAt != nil:
		return *job.StartedAt
	case job.DispatchedAt != nil:
		return *job.DispatchedAt
	}
	return job.CreatedAt
}

// jobAccum totals the ingest summaries of a job's chunks for the
// completion event (per control-plane instance).
type jobAccum struct {
	findings int
	created  int
	bySev    map[string]int
	newRefs  []store.FindingRef
}

func (s *Server) accumulate(jobID string, sum store.IngestSummary) *jobAccum {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	a := s.acc[jobID]
	if a == nil {
		a = &jobAccum{bySev: map[string]int{}}
		s.acc[jobID] = a
	}
	a.findings += sum.Findings
	a.created += sum.NewFindings
	for k, v := range sum.NewBySeverity {
		a.bySev[k] += v
	}
	if len(a.newRefs) < maxNewEventRefs {
		a.newRefs = append(a.newRefs, sum.New...)
	}
	return a
}

const maxNewEventRefs = 200

func (s *Server) finishAccum(jobID string) *jobAccum {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	a := s.acc[jobID]
	delete(s.acc, jobID)
	if a == nil {
		a = &jobAccum{bySev: map[string]int{}}
	}
	return a
}

// completeJob runs the lifecycle resolution for a job whose final chunk
// arrived and emits the completion events.
func (s *Server) completeJob(ctx context.Context, job *store.Job, stats *v1.ScanStats, now time.Time) {
	acc := s.finishAccum(job.ID)
	var fixed []*store.Finding
	if scopes := jobScopes(job, stats); len(scopes) > 0 {
		list, err := s.cfg.Store.ResolveFindings(ctx, job.SiteID, job.ID, scopes, jobStart(job), now)
		if err != nil {
			s.log.Warn("lifecycle resolution failed", "job", job.ID, "err", err)
		} else {
			fixed = list
		}
	}
	s.metrics.jobsDone.Add(1)
	s.metrics.findingsNew.Add(int64(acc.created))
	s.metrics.findingsFixed.Add(int64(len(fixed)))
	if len(fixed) > 0 {
		s.log.Info("findings fixed by rescan", "job", job.ID, "fixed", len(fixed))
	}
	for _, ref := range acc.newRefs {
		s.emit(ctx, EventFindingNew, job.SiteID, job.ApplianceID, job.ID, ref)
	}
	if len(fixed) > 0 {
		refs := make([]store.FindingRef, 0, len(fixed))
		for i, f := range fixed {
			if i >= maxNewEventRefs {
				break
			}
			refs = append(refs, store.FindingRef{ID: f.ID, HostID: f.HostID, Name: f.Name, Severity: f.Severity, CVSS: f.CVSS, CVE: f.CVE, Detector: f.Detector()})
		}
		s.emit(ctx, EventFindingsFixed, job.SiteID, job.ApplianceID, job.ID, map[string]any{"count": len(fixed), "findings": refs})
	}
	s.emit(ctx, EventJobCompleted, job.SiteID, job.ApplianceID, job.ID, map[string]any{
		"mode": job.Spec.Mode, "targets": job.Spec.Targets, "stats": stats, "findings_observed": acc.findings,
		"findings_new": acc.created, "new_by_severity": acc.bySev, "findings_fixed": len(fixed)})
}

// ---- external scanner imports ----

func validExternal(req *v1.ExternalScanRequest) error {
	req.Scanner = strings.ToLower(strings.TrimSpace(req.Scanner))
	switch req.Scanner {
	case "", v1.SourceAgent, v1.SourceAppliance, v1.SourceBoth, "openvas", "nuclei", v1.SourceExternal:
		return fmt.Errorf("scanner must name the external product (e.g. qualys)")
	}
	if strings.ContainsAny(req.Scanner, " :/|") || len(req.Scanner) > 32 {
		return errors.New("scanner: letters, digits, - and _ only")
	}
	if len(req.Hosts) > maxExternalHosts {
		return fmt.Errorf("too many hosts (%d)", len(req.Hosts))
	}
	n := 0
	for i := range req.Hosts {
		h := &req.Hosts[i]
		h.IP, h.Hostname, h.OS = clip(strings.TrimSpace(h.IP), 64), clip(strings.TrimSpace(h.Hostname), maxStringLen), clip(strings.TrimSpace(h.OS), maxStringLen)
		for j := range h.Findings {
			f := &h.Findings[j]
			n++
			f.ID, f.Name, f.Solution, f.Evidence = clip(strings.TrimSpace(f.ID), 64), clip(f.Name, maxStringLen), clip(f.Solution, maxEvidenceLen), clip(f.Evidence, maxEvidenceLen)
			if f.ID == "" {
				return fmt.Errorf("host %s: finding without id", h.IP)
			}
			if f.Port < 0 || f.Port > 65535 || f.CVSS < 0 || f.CVSS > 10 {
				return fmt.Errorf("host %s: bad port or cvss on %s", h.IP, f.ID)
			}
			if f.Severity != "" && !v1.KnownSeverities[strings.ToLower(f.Severity)] {
				return fmt.Errorf("host %s: bad severity %q", h.IP, f.Severity)
			}
			f.Severity = strings.ToLower(f.Severity)
			if len(f.CVE) > 256 {
				f.CVE = f.CVE[:256]
			}
		}
	}
	if n > maxExternalFindings {
		return fmt.Errorf("too many findings (%d)", n)
	}
	return nil
}

func (s *Server) importExternal(w http.ResponseWriter, r *http.Request, site *store.Site, req v1.ExternalScanRequest) {
	if err := validExternal(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_import")
		return
	}
	at := s.cfg.Now()
	if req.ScannedAt != nil && !req.ScannedAt.IsZero() {
		at = *req.ScannedAt
	}
	sum, err := s.cfg.Store.IngestExternal(r.Context(), site.ID, req.Scanner, req.Hosts, at)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.metrics.findingsNew.Add(int64(sum.NewFindings))
	resp := v1.ExternalScanResponse{Scanner: req.Scanner, Hosts: sum.Hosts, HostsCreated: sum.Created, HostsMerged: sum.Merged, Findings: sum.Findings, FindingsNew: sum.NewFindings, Fixed: sum.Fixed, Skipped: sum.Skipped}
	s.log.Info("external scan imported", "site", site.ID, "scanner", req.Scanner, "hosts", sum.Hosts, "findings", sum.Findings, "new", sum.NewFindings, "fixed", sum.Fixed, "by", s.actor(r))
	s.emit(r.Context(), EventImportDone, site.ID, "", "", resp)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminExternalScan(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.ExternalScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	s.importExternal(w, r, site, req)
}

// adminExternalScanQualys takes a raw Qualys export (CSV or host list
// detection XML) as the body; ?kb= is not supported here (the CLI joins
// the KnowledgeBase client-side) so XML imports without CVEs unless the
// export carries them.
func (s *Server) adminExternalScanQualys(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxExternalBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "export too large or unreadable", "too_large")
		return
	}
	hosts, err := qualys.Parse(body, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_export")
		return
	}
	req := v1.ExternalScanRequest{Scanner: qualys.Scanner, Hosts: hosts}
	if ts := r.URL.Query().Get("scanned_at"); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.ScannedAt = &t
		}
	}
	s.importExternal(w, r, site, req)
}

// ---- parity ----

func (s *Server) parity(ctx context.Context, site *store.Site, scanner string, since time.Time, minSev string) (v1.AdminParityReport, error) {
	rep := v1.AdminParityReport{SiteID: site.ID, Scanner: scanner, Since: since, MinSeverity: minSev, ComputedAt: s.cfg.Now(),
		BySeverity: map[string]v1.ParityCounts{}, NoCVE: map[string]int{"external": 0, "appliance": 0}, ExternalOnly: []v1.ParityItem{}, ApplianceOnly: []v1.ParityItem{}}
	hosts, err := s.cfg.Store.ListHosts(ctx, site.ID)
	if err != nil {
		return rep, err
	}
	findings, err := s.cfg.Store.ListFindings(ctx, site.ID, "")
	if err != nil {
		return rep, err
	}
	hostByID := map[string]*store.Host{}
	for _, h := range hosts {
		hostByID[h.ID] = h
	}
	minRank := v1.SeverityRank(minSev)
	extHosts, aplHosts := map[string]bool{}, map[string]bool{}
	for _, h := range hosts {
		if h.Source == v1.SourceExternal {
			extHosts[h.ID] = true
		}
		if h.Source == v1.SourceAppliance || h.Source == v1.SourceBoth {
			aplHosts[h.ID] = true
		}
	}
	type item struct {
		name, severity, detector, extID string
		hosts                           map[string]bool
		rank                            int
	}
	extOnly, aplOnly := map[string]*item{}, map[string]*item{}
	for _, f := range findings {
		if f.Review == v1.ReviewFalsePositive {
			continue
		}
		ext, apl := false, false
		for _, e := range f.Evidence {
			if e.At.Before(since) {
				continue
			}
			switch e.Source {
			case scanner:
				ext = true
			case "openvas", "nuclei":
				apl = true
			}
		}
		if ext {
			extHosts[f.HostID] = true
		}
		if apl {
			aplHosts[f.HostID] = true
		}
		if !ext && !apl {
			continue
		}
		if v1.SeverityRank(f.Severity) < minRank {
			continue
		}
		if len(f.CVE) == 0 {
			if ext {
				rep.NoCVE["external"]++
			}
			if apl {
				rep.NoCVE["appliance"]++
			}
			continue
		}
		for _, cve := range f.CVE {
			c := rep.BySeverity[f.Severity]
			switch {
			case ext && apl:
				rep.CVEs.Both++
				c.Both++
			case ext:
				rep.CVEs.ExternalOnly++
				c.ExternalOnly++
				it := extOnly[cve]
				if it == nil {
					it = &item{name: f.Name, severity: f.Severity, extID: f.ExternalID, hosts: map[string]bool{}, rank: v1.SeverityRank(f.Severity)}
					extOnly[cve] = it
				}
				it.hosts[f.HostID] = true
			default:
				rep.CVEs.ApplianceOnly++
				c.ApplianceOnly++
				it := aplOnly[cve]
				if it == nil {
					it = &item{name: f.Name, severity: f.Severity, detector: f.Detector(), hosts: map[string]bool{}, rank: v1.SeverityRank(f.Severity)}
					aplOnly[cve] = it
				}
				it.hosts[f.HostID] = true
			}
			rep.BySeverity[f.Severity] = c
		}
	}
	for id := range extHosts {
		if aplHosts[id] {
			rep.Hosts.Both++
		} else if h := hostByID[id]; h != nil {
			rep.Hosts.ExternalOnly = append(rep.Hosts.ExternalOnly, h.IP)
		}
	}
	for id := range aplHosts {
		if !extHosts[id] {
			if h := hostByID[id]; h != nil {
				rep.Hosts.ApplianceOnly = append(rep.Hosts.ApplianceOnly, h.IP)
			}
		}
	}
	rep.Hosts.External, rep.Hosts.Appliance = len(extHosts), len(aplHosts)
	sort.Strings(rep.Hosts.ExternalOnly)
	sort.Strings(rep.Hosts.ApplianceOnly)
	if rep.Hosts.ExternalOnly == nil {
		rep.Hosts.ExternalOnly = []string{}
	}
	if rep.Hosts.ApplianceOnly == nil {
		rep.Hosts.ApplianceOnly = []string{}
	}
	toItems := func(m map[string]*item) []v1.ParityItem {
		out := make([]v1.ParityItem, 0, len(m))
		for cve, it := range m {
			out = append(out, v1.ParityItem{CVE: cve, Name: it.name, Severity: it.severity, Hosts: len(it.hosts), Detector: it.detector, ExternalID: it.extID})
		}
		sort.Slice(out, func(i, j int) bool {
			ri, rj := v1.SeverityRank(out[i].Severity), v1.SeverityRank(out[j].Severity)
			if ri != rj {
				return ri > rj
			}
			if out[i].Hosts != out[j].Hosts {
				return out[i].Hosts > out[j].Hosts
			}
			return out[i].CVE < out[j].CVE
		})
		if len(out) > parityTop {
			out = out[:parityTop]
		}
		return out
	}
	rep.ExternalOnly, rep.ApplianceOnly = toItems(extOnly), toItems(aplOnly)
	if denom := rep.CVEs.Both + rep.CVEs.ExternalOnly; denom > 0 {
		rep.DetectionRate = float64(rep.CVEs.Both) / float64(denom)
	}
	rep.Verdict = parityVerdict(rep)
	return rep, nil
}

func parityVerdict(r v1.AdminParityReport) string {
	switch {
	case r.Hosts.External == 0:
		return fmt.Sprintf("no %s findings since %s: import an export of the same window first (admin import-qualys)", r.Scanner, r.Since.Format("2006-01-02"))
	case r.Hosts.Appliance == 0:
		return "no appliance findings in the window: run inventory or full scans of the same ranges first"
	case r.CVEs.Both+r.CVEs.ExternalOnly == 0:
		return fmt.Sprintf("%s reported no CVE-bearing findings at or above %s in the window; nothing to compare", r.Scanner, r.MinSeverity)
	case r.DetectionRate >= 0.9:
		return fmt.Sprintf("parity: the appliance sees %.0f%% of the host×CVE pairs %s sees (%d shared, %d %s-only, %d appliance-only); decommission can proceed once two cycles agree",
			r.DetectionRate*100, r.Scanner, r.CVEs.Both, r.CVEs.ExternalOnly, r.Scanner, r.CVEs.ApplianceOnly)
	case r.DetectionRate >= 0.7:
		return fmt.Sprintf("gap: %.0f%% detection rate; review the %s-only CVEs (top of the list first), check whether they concentrate on enterprise products (admin feed-gaps) or on hosts the fragile policy keeps away", r.DetectionRate*100, r.Scanner)
	default:
		return fmt.Sprintf("not ready: %.0f%% detection rate; keep %s until the gap is understood (scope, fragile exclusions, feed coverage)", r.DetectionRate*100, r.Scanner)
	}
}

func (s *Server) adminParity(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	scanner := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scanner")))
	if scanner == "" {
		scanner = qualys.Scanner
	}
	days := parityDefaultDays
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 3650 {
		days = d
	}
	minSev := strings.ToLower(r.URL.Query().Get("min_severity"))
	if minSev == "" {
		minSev = v1.SeverityMedium
	}
	if !v1.KnownSeverities[minSev] {
		writeErr(w, http.StatusBadRequest, "min_severity must be a severity", "bad_severity")
		return
	}
	rep, err := s.parity(r.Context(), site, scanner, s.cfg.Now().Add(-time.Duration(days)*24*time.Hour), minSev)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ---- summaries and trend ----

func newSummary() v1.AdminSummary {
	return v1.AdminSummary{Open: map[string]int{}, Overdue: map[string]int{}, Top: []v1.SummaryFinding{}}
}

func (s *Server) siteSummary(ctx context.Context, site *store.Site, tier int) (v1.AdminSummary, error) {
	now := s.cfg.Now()
	sum := newSummary()
	sum.SiteID, sum.VendorID, sum.Name, sum.ComputedAt = site.ID, site.VendorID, site.Name, now
	sum.SLADays = map[string]int{}
	for _, sev := range []string{v1.SeverityCritical, v1.SeverityHigh, v1.SeverityMedium, v1.SeverityLow} {
		sum.SLADays[sev] = s.slaDays(sev, tier)
		sum.Open[sev], sum.Overdue[sev] = 0, 0
	}
	hosts, err := s.cfg.Store.ListHosts(ctx, site.ID)
	if err != nil {
		return sum, err
	}
	hostIP := map[string]string{}
	for _, h := range hosts {
		hostIP[h.ID] = h.IP
		sum.Hosts.Total++
		if h.Source != v1.SourceAgent {
			sum.Hosts.NetworkVisible++
		}
	}
	findings, err := s.cfg.Store.ListFindings(ctx, site.ID, "")
	if err != nil {
		return sum, err
	}
	withOpen := map[string]bool{}
	ageSum, ageN := 0, 0
	var top []*store.Finding
	last30 := now.Add(-30 * 24 * time.Hour)
	for _, f := range findings {
		if f.Review == v1.ReviewFalsePositive {
			continue
		}
		if f.FixedAt != nil && !f.FixedAt.Before(last30) {
			sum.FixedLast30++
		}
		if f.ReopenedAt != nil && !f.ReopenedAt.Before(last30) {
			sum.ReopenedLast30++
		}
		if !f.IsOpen() {
			continue
		}
		if !f.FirstSeen.Before(last30) {
			sum.NewLast30++
		}
		sum.Open[f.Severity]++
		withOpen[f.HostID] = true
		age := daysOpen(f, now)
		ageSum += age
		ageN++
		if age > sum.OldestDays {
			sum.OldestDays = age
		}
		if s.overdue(f, tier, now) {
			sum.Overdue[f.Severity]++
		}
		if f.Review != v1.ReviewAccepted {
			pts := riskWeights[f.Severity]
			if f.Source != v1.SourceAgent {
				pts = int(float64(pts)*v1.ExposureMultiplier + 0.5)
			}
			sum.RiskPoints += pts
		}
		top = append(top, f)
	}
	sum.Hosts.WithOpenFindings = len(withOpen)
	if ageN > 0 {
		sum.MeanAgeDays = float64(ageSum) / float64(ageN)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].CVSS != top[j].CVSS {
			return top[i].CVSS > top[j].CVSS
		}
		return top[i].FirstSeen.Before(top[j].FirstSeen)
	})
	for i, f := range top {
		if i >= summaryTop {
			break
		}
		sum.Top = append(sum.Top, v1.SummaryFinding{ID: f.ID, HostID: f.HostID, HostIP: hostIP[f.HostID], Name: f.Name, Severity: f.Severity, CVSS: f.CVSS, CVE: f.CVE, DaysOpen: daysOpen(f, now), Overdue: s.overdue(f, tier, now)})
	}
	if jobs, err := s.cfg.Store.ListJobs(ctx, site.ID, ""); err == nil {
		for _, j := range jobs {
			if j.Status != v1.JobDone || j.FinishedAt == nil {
				continue
			}
			switch jobScope(j) {
			case v1.ScopeInventory:
				if sum.LastInventory == nil || j.FinishedAt.After(*sum.LastInventory) {
					t := *j.FinishedAt
					sum.LastInventory = &t
				}
			case v1.ScopeFull:
				if sum.LastFull == nil || j.FinishedAt.After(*sum.LastFull) {
					t := *j.FinishedAt
					sum.LastFull = &t
				}
			}
		}
	}
	if cov, err := s.siteCoverage(ctx, site, now); err == nil {
		sum.Coverage = cov.Score
	}
	return sum, nil
}

func (s *Server) vendorTier(ctx context.Context, vendorID string) int {
	if v, err := s.cfg.Store.GetVendor(ctx, vendorID); err == nil {
		return v.Tier
	}
	return 0
}

func (s *Server) adminSiteSummary(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	sum, err := s.siteSummary(r.Context(), site, s.vendorTier(r.Context(), site.VendorID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) vendorSites(ctx context.Context, vendorID string) ([]*store.Site, error) {
	all, err := s.cfg.Store.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	var out []*store.Site
	for _, site := range all {
		if site.VendorID == vendorID {
			out = append(out, site)
		}
	}
	return out, nil
}

func (s *Server) adminVendorSummary(w http.ResponseWriter, r *http.Request) {
	vendor, err := s.cfg.Store.GetVendor(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such vendor", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	sites, err := s.vendorSites(r.Context(), vendor.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	total := newSummary()
	total.VendorID, total.Name, total.ComputedAt = vendor.ID, vendor.Name, s.cfg.Now()
	total.SLADays = map[string]int{}
	for _, sev := range []string{v1.SeverityCritical, v1.SeverityHigh, v1.SeverityMedium, v1.SeverityLow} {
		total.SLADays[sev] = s.slaDays(sev, vendor.Tier)
		total.Open[sev], total.Overdue[sev] = 0, 0
	}
	ageN := 0.0
	covSum := 0
	for _, site := range sites {
		sum, err := s.siteSummary(r.Context(), site, vendor.Tier)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		total.Sites = append(total.Sites, sum)
		total.Hosts.Total += sum.Hosts.Total
		total.Hosts.NetworkVisible += sum.Hosts.NetworkVisible
		total.Hosts.WithOpenFindings += sum.Hosts.WithOpenFindings
		open := 0
		for k, v := range sum.Open {
			total.Open[k] += v
			open += v
		}
		for k, v := range sum.Overdue {
			total.Overdue[k] += v
		}
		total.NewLast30 += sum.NewLast30
		total.FixedLast30 += sum.FixedLast30
		total.ReopenedLast30 += sum.ReopenedLast30
		total.RiskPoints += sum.RiskPoints
		total.MeanAgeDays += sum.MeanAgeDays * float64(open)
		ageN += float64(open)
		if sum.OldestDays > total.OldestDays {
			total.OldestDays = sum.OldestDays
		}
		total.Top = append(total.Top, sum.Top...)
		covSum += sum.Coverage
	}
	if ageN > 0 {
		total.MeanAgeDays /= ageN
	}
	if len(sites) > 0 {
		total.Coverage = covSum / len(sites)
	}
	sort.Slice(total.Top, func(i, j int) bool { return total.Top[i].CVSS > total.Top[j].CVSS })
	if len(total.Top) > summaryTop {
		total.Top = total.Top[:summaryTop]
	}
	if total.Sites == nil {
		total.Sites = []v1.AdminSummary{}
	}
	writeJSON(w, http.StatusOK, total)
}

func startOfWeek(t time.Time) time.Time {
	t = t.UTC()
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	wd := int(d.Weekday()) // Sunday = 0
	if wd == 0 {
		wd = 7
	}
	return d.AddDate(0, 0, -(wd - 1)) // Monday
}

func (s *Server) trend(ctx context.Context, siteID string, weeks int) ([]v1.AdminTrendPoint, error) {
	findings, err := s.cfg.Store.ListFindings(ctx, siteID, "")
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	out := make([]v1.AdminTrendPoint, 0, weeks)
	thisWeek := startOfWeek(now)
	for w := weeks - 1; w >= 0; w-- {
		start := thisWeek.AddDate(0, 0, -7*w)
		end := start.AddDate(0, 0, 7)
		if end.After(now) {
			end = now.Add(time.Second)
		}
		pt := v1.AdminTrendPoint{WeekStart: start, OpenBySeverity: map[string]int{}}
		for _, f := range findings {
			if f.Review == v1.ReviewFalsePositive {
				continue
			}
			if !f.FirstSeen.Before(start) && f.FirstSeen.Before(end) {
				pt.New++
			}
			if f.FixedAt != nil && !f.FixedAt.Before(start) && f.FixedAt.Before(end) {
				pt.Fixed++
			}
			openAtEnd := f.FirstSeen.Before(end) && (f.IsOpen() || f.FixedAt == nil || !f.FixedAt.Before(end))
			if openAtEnd {
				pt.Open++
				pt.OpenBySeverity[f.Severity]++
			}
		}
		out = append(out, pt)
	}
	return out, nil
}

func (s *Server) adminTrend(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	weeks := 12
	if n, err := strconv.Atoi(r.URL.Query().Get("weeks")); err == nil && n > 0 && n <= trendMaxWeeks {
		weeks = n
	}
	out, err := s.trend(r.Context(), site.ID, weeks)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- CSV exports ----

var findingsCSVHeader = []string{"site_id", "site", "host_ip", "hostname", "mac", "finding_id", "status", "state", "severity", "cvss", "cve", "name", "detector", "external_id", "source", "port", "proto", "qod",
	"first_seen", "last_seen", "fixed_at", "days_open", "sla_days", "overdue", "review", "review_reason", "solution"}

func (s *Server) writeFindingsCSV(w http.ResponseWriter, r *http.Request, sites []*store.Site, tier int, status string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(findingsCSVHeader)
	now := s.cfg.Now()
	for _, site := range sites {
		hosts, err := s.cfg.Store.ListHosts(r.Context(), site.ID)
		if err != nil {
			return
		}
		byID := map[string]*store.Host{}
		for _, h := range hosts {
			byID[h.ID] = h
		}
		findings, err := s.cfg.Store.ListFindings(r.Context(), site.ID, "")
		if err != nil {
			return
		}
		for _, f := range findings {
			switch status {
			case "open":
				if !f.IsOpen() {
					continue
				}
			case "fixed":
				if f.IsOpen() {
					continue
				}
			}
			h := byID[f.HostID]
			ip, name, mac := "", "", ""
			if h != nil {
				ip, name, mac = h.IP, h.Hostname, h.MAC
			}
			st := f.Status
			if st == "" {
				st = v1.FindingOpen
			}
			fixed := ""
			if f.FixedAt != nil {
				fixed = f.FixedAt.UTC().Format(time.RFC3339)
			}
			_ = cw.Write([]string{site.ID, site.Name, ip, name, mac, f.ID, st, f.State, f.Severity, strconv.FormatFloat(f.CVSS, 'f', 1, 64), strings.Join(f.CVE, " "), f.Name, f.Detector(), f.ExternalID, f.Source,
				strconv.Itoa(f.Port), f.Proto, strconv.Itoa(f.QoD), f.FirstSeen.UTC().Format(time.RFC3339), f.LastSeen.UTC().Format(time.RFC3339), fixed,
				strconv.Itoa(daysOpen(f, now)), strconv.Itoa(s.slaDays(f.Severity, tier)), strconv.FormatBool(s.overdue(f, tier, now)), f.Review, f.ReviewReason, f.Solution})
		}
	}
	cw.Flush()
}

var hostsCSVHeader = []string{"site_id", "site", "host_id", "ip", "hostname", "mac", "source", "agent_id", "os_family", "os_name", "os_confidence", "ports", "notes", "open_findings", "first_seen", "last_seen"}

func (s *Server) writeHostsCSV(w http.ResponseWriter, r *http.Request, sites []*store.Site) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hosts.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(hostsCSVHeader)
	for _, site := range sites {
		hosts, err := s.cfg.Store.ListHosts(r.Context(), site.ID)
		if err != nil {
			return
		}
		findings, err := s.cfg.Store.ListFindings(r.Context(), site.ID, "")
		if err != nil {
			return
		}
		open := map[string]int{}
		for _, f := range findings {
			if f.IsOpen() && f.Review != v1.ReviewFalsePositive {
				open[f.HostID]++
			}
		}
		for _, h := range hosts {
			fam, name, conf := "", "", ""
			if h.OSGuess != nil {
				fam, name, conf = h.OSGuess.Family, h.OSGuess.Name, strconv.FormatFloat(h.OSGuess.Confidence, 'f', 2, 64)
			}
			ports := make([]string, 0, len(h.Ports))
			for _, p := range h.Ports {
				ps := fmt.Sprintf("%d/%s", p.Port, p.Proto)
				if p.Service != "" {
					ps += " " + p.Service
				}
				if p.Product != "" {
					ps += " " + strings.TrimSpace(p.Product+" "+p.Version)
				}
				ports = append(ports, ps)
			}
			_ = cw.Write([]string{site.ID, site.Name, h.ID, h.IP, h.Hostname, h.MAC, h.Source, h.AgentID, fam, name, conf, strings.Join(ports, "; "), strings.Join(h.Notes, "; "),
				strconv.Itoa(open[h.ID]), h.FirstSeen.UTC().Format(time.RFC3339), h.LastSeen.UTC().Format(time.RFC3339)})
		}
	}
	cw.Flush()
}

func exportStatus(r *http.Request) string {
	switch st := r.URL.Query().Get("status"); st {
	case "open", "fixed":
		return st
	}
	return "all"
}

func (s *Server) adminExportSiteFindings(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	s.writeFindingsCSV(w, r, []*store.Site{site}, s.vendorTier(r.Context(), site.VendorID), exportStatus(r))
}

func (s *Server) adminExportSiteHosts(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	s.writeHostsCSV(w, r, []*store.Site{site})
}

func (s *Server) adminExportVendorFindings(w http.ResponseWriter, r *http.Request) {
	vendor, err := s.cfg.Store.GetVendor(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such vendor", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	sites, err := s.vendorSites(r.Context(), vendor.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.writeFindingsCSV(w, r, sites, vendor.Tier, exportStatus(r))
}

func (s *Server) adminSLA(w http.ResponseWriter, _ *http.Request) {
	table := s.cfg.SLADays
	if len(table) == 0 {
		table = DefaultSLADays
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": table, "tier_3_and_4_multiplier": 2, "risk_weights": riskWeights, "exposure_multiplier": v1.ExposureMultiplier})
}

// ---- alerts watch (webhook events for raised and cleared alerts) ----

func alertKey(a v1.AdminAlert) string {
	return a.Kind + "|" + a.SiteID + "|" + a.ApplianceID + "|" + a.Subject
}

// RunWatch emits alert.raised / alert.cleared as the alert set changes.
func (s *Server) RunWatch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.withLock(ctx, "watch", func() error { return s.WatchTick(ctx) }); err != nil {
				s.log.Warn("watch tick", "err", err)
			}
		}
	}
}

// WatchTick diffs the current alerts against the previous tick.
func (s *Server) WatchTick(ctx context.Context) error {
	alerts, err := s.alerts(ctx)
	if err != nil {
		return err
	}
	current := map[string]v1.AdminAlert{}
	for _, a := range alerts {
		current[alertKey(a)] = a
	}
	s.accMu.Lock()
	prev := s.lastAlerts
	s.lastAlerts = current
	s.accMu.Unlock()
	for k, a := range current {
		if _, seen := prev[k]; !seen {
			s.emit(ctx, EventAlertRaised, a.SiteID, a.ApplianceID, "", a)
		}
	}
	for k, a := range prev {
		if _, still := current[k]; !still {
			s.emit(ctx, EventAlertCleared, a.SiteID, a.ApplianceID, "", a)
		}
	}
	return nil
}
