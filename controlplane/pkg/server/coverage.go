package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

// Coverage scoring and alerts (PLAN §8.4, §12.3, §20 Phase 4). The score
// is the network-scanning coverage input to the vendor score: 0-100 from
// three weighted components plus an attestation penalty, with the reasons
// spelled out so the portal can show them.

const (
	// SilentAfter is when a quiet appliance becomes an alert (PLAN §8.4).
	SilentAfter = 24 * time.Hour
	// DegradedAfter is how long the engine may be not-ready before the
	// appliance counts as degraded (PLAN §8.4).
	DegradedAfter = 15 * time.Minute

	weightAppliance = 40
	weightFreshness = 40
	weightHosts     = 20
	attestPenalty   = 10
)

// health derives the portal-facing health of an appliance.
func (s *Server) health(a *store.Appliance, now time.Time) string {
	if a.LastHeartbeatAt == nil {
		return v1.HealthNever
	}
	age := now.Sub(*a.LastHeartbeatAt)
	switch {
	case age > SilentAfter:
		return v1.HealthSilent
	case age > OnlineWindow:
		return v1.HealthStale
	case a.EngineDownSince != nil && now.Sub(*a.EngineDownSince) > DegradedAfter:
		return v1.HealthDegraded
	}
	return v1.HealthOnline
}

func healthRank(h string) int {
	switch h {
	case v1.HealthOnline:
		return 4
	case v1.HealthDegraded:
		return 3
	case v1.HealthStale:
		return 2
	case v1.HealthSilent:
		return 1
	}
	return 0
}

func (s *Server) siteCoverage(ctx context.Context, site *store.Site, now time.Time) (v1.AdminCoverage, error) {
	cov := v1.AdminCoverage{SiteID: site.ID, VendorID: site.VendorID, Reasons: []string{}, ComputedAt: now, Attested: site.AttestedAt,
		Weights:    map[string]int{"appliance": weightAppliance, "freshness": weightFreshness, "hosts": weightHosts},
		Components: map[string]int{"appliance": 0, "freshness": 0, "hosts": 0},
		Findings:   v1.CoverageFindings{BySeverity: map[string]int{}}}
	all, err := s.cfg.Store.ListAppliances(ctx)
	if err != nil {
		return cov, err
	}
	best := ""
	for _, a := range all {
		if a.SiteID != site.ID || a.Status == v1.StatusWiped || a.Status == v1.StatusRevoked {
			continue
		}
		cov.Appliance.Count++
		h := s.health(a, now)
		switch h {
		case v1.HealthOnline:
			cov.Appliance.Online++
		case v1.HealthDegraded:
			cov.Appliance.Degraded++
		case v1.HealthSilent:
			cov.Appliance.Silent++
		}
		if healthRank(h) > healthRank(best) {
			best = h
		}
	}
	cov.Appliance.Health = best
	switch best {
	case v1.HealthOnline:
		cov.Components["appliance"] = weightAppliance
	case v1.HealthDegraded:
		cov.Components["appliance"] = weightAppliance * 5 / 8
		cov.Reasons = append(cov.Reasons, "scan engine not ready for more than 15 minutes")
	case v1.HealthStale:
		cov.Components["appliance"] = weightAppliance * 3 / 8
		cov.Reasons = append(cov.Reasons, "appliance heartbeat is stale")
	case v1.HealthSilent:
		cov.Reasons = append(cov.Reasons, "appliance silent for more than 24 hours")
	default:
		cov.Reasons = append(cov.Reasons, "no appliance has reported yet")
	}

	jobs, err := s.cfg.Store.ListJobs(ctx, site.ID, "")
	if err != nil {
		return cov, err
	}
	latest := func(cur *time.Time, t *time.Time) *time.Time {
		if t == nil {
			return cur
		}
		if cur == nil || t.After(*cur) {
			return t
		}
		return cur
	}
	for _, j := range jobs {
		if j.Status != v1.JobDone {
			continue
		}
		switch j.Spec.Mode {
		case v1.ModeDiscovery:
			cov.Freshness.LastDiscovery = latest(cov.Freshness.LastDiscovery, j.FinishedAt)
		case v1.ModeInventory:
			cov.Freshness.LastInventory = latest(cov.Freshness.LastInventory, j.FinishedAt)
		case v1.ModeFull:
			cov.Freshness.LastFull = latest(cov.Freshness.LastFull, j.FinishedAt)
		}
	}
	// A full scan covers everything an inventory scan does.
	inv := latest(cov.Freshness.LastInventory, cov.Freshness.LastFull)
	switch {
	case inv == nil:
		cov.Freshness.Overdue = true
		if cov.Freshness.LastDiscovery != nil && now.Sub(*cov.Freshness.LastDiscovery) <= 31*24*time.Hour {
			cov.Components["freshness"] = weightFreshness / 8
			cov.Reasons = append(cov.Reasons, "only a discovery scan has completed; no inventory scan yet")
		} else {
			cov.Reasons = append(cov.Reasons, "no inventory scan has completed")
		}
	default:
		age := now.Sub(*inv)
		cov.Freshness.InventoryAgeH = math.Round(age.Hours()*10) / 10
		switch {
		case age <= 8*24*time.Hour:
			cov.Components["freshness"] = weightFreshness
		case age <= 15*24*time.Hour:
			cov.Components["freshness"] = weightFreshness * 5 / 8
			cov.Freshness.Overdue = true
			cov.Reasons = append(cov.Reasons, fmt.Sprintf("last inventory scan is %.0f days old (weekly expected)", age.Hours()/24))
		case age <= 31*24*time.Hour:
			cov.Components["freshness"] = weightFreshness / 4
			cov.Freshness.Overdue = true
			cov.Reasons = append(cov.Reasons, fmt.Sprintf("last inventory scan is %.0f days old", age.Hours()/24))
		default:
			cov.Freshness.Overdue = true
			cov.Reasons = append(cov.Reasons, fmt.Sprintf("last inventory scan is %.0f days old", age.Hours()/24))
		}
	}

	hosts, err := s.cfg.Store.ListHosts(ctx, site.ID)
	if err != nil {
		return cov, err
	}
	for _, h := range hosts {
		cov.Hosts.Total++
		switch h.Source {
		case v1.SourceAppliance:
			cov.Hosts.ApplianceSeen++
			cov.Hosts.Agentless++
		case v1.SourceAgent:
			cov.Hosts.AgentSeen++
		case v1.SourceBoth:
			cov.Hosts.ApplianceSeen++
			cov.Hosts.AgentSeen++
			cov.Hosts.Both++
		}
	}
	if cov.Hosts.ApplianceSeen > 0 {
		cov.Hosts.AgentFraction = math.Round(float64(cov.Hosts.Both)/float64(cov.Hosts.ApplianceSeen)*100) / 100
		cov.Components["hosts"] = int(math.Round(weightHosts * cov.Hosts.AgentFraction))
		if cov.Hosts.Agentless > 0 {
			cov.Reasons = append(cov.Reasons, fmt.Sprintf("%d of %d network-visible hosts have no agent", cov.Hosts.Agentless, cov.Hosts.ApplianceSeen))
		}
	} else {
		cov.Reasons = append(cov.Reasons, "no hosts observed by the appliance yet")
	}

	findings, err := s.cfg.Store.ListFindings(ctx, site.ID, "")
	if err != nil {
		return cov, err
	}
	for _, f := range findings {
		if f.Review == v1.ReviewFalsePositive {
			cov.Findings.FalsePositives++
			continue
		}
		if f.Review == v1.ReviewAccepted {
			continue
		}
		cov.Findings.Open++
		cov.Findings.BySeverity[f.Severity]++
		if f.Source != v1.SourceAgent {
			cov.Findings.NetworkReachable++
		}
		if f.State == v1.FindingSuspected {
			cov.Findings.Suspected++
		}
	}

	score := 0
	for _, c := range cov.Components {
		score += c
	}
	if site.AttestedAt == nil || now.Sub(*site.AttestedAt) > AttestationMaxAge {
		score -= attestPenalty
		cov.Reasons = append(cov.Reasons, "scope attestation missing or older than 90 days")
	}
	if score < 0 {
		score = 0
	}
	cov.Score = score
	return cov, nil
}

func (s *Server) adminSiteCoverage(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	cov, err := s.siteCoverage(r.Context(), site, s.cfg.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

func (s *Server) adminVendorCoverage(w http.ResponseWriter, r *http.Request) {
	vendor, err := s.cfg.Store.GetVendor(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such vendor", "not_found")
		return
	}
	sites, err := s.cfg.Store.ListSites(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	now := s.cfg.Now()
	out := v1.AdminCoverage{VendorID: vendor.ID, Reasons: []string{}, ComputedAt: now, Sites: []v1.AdminCoverage{}, Weights: map[string]int{}, Components: map[string]int{},
		Findings: v1.CoverageFindings{BySeverity: map[string]int{}}}
	total := 0
	for _, site := range sites {
		if site.VendorID != vendor.ID {
			continue
		}
		cov, err := s.siteCoverage(r.Context(), site, now)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		out.Sites = append(out.Sites, cov)
		total += cov.Score
		out.Findings.Open += cov.Findings.Open
		out.Findings.NetworkReachable += cov.Findings.NetworkReachable
		out.Findings.Suspected += cov.Findings.Suspected
		out.Findings.FalsePositives += cov.Findings.FalsePositives
		for k, v := range cov.Findings.BySeverity {
			out.Findings.BySeverity[k] += v
		}
		out.Hosts.Total += cov.Hosts.Total
		out.Hosts.ApplianceSeen += cov.Hosts.ApplianceSeen
		out.Hosts.AgentSeen += cov.Hosts.AgentSeen
		out.Hosts.Both += cov.Hosts.Both
		out.Hosts.Agentless += cov.Hosts.Agentless
		out.Appliance.Count += cov.Appliance.Count
		out.Appliance.Online += cov.Appliance.Online
		out.Appliance.Degraded += cov.Appliance.Degraded
		out.Appliance.Silent += cov.Appliance.Silent
		for _, reason := range cov.Reasons {
			out.Reasons = append(out.Reasons, site.Name+": "+reason)
		}
	}
	if n := len(out.Sites); n > 0 {
		out.Score = int(math.Round(float64(total) / float64(n)))
	} else {
		out.Reasons = append(out.Reasons, "vendor has no sites")
	}
	writeJSON(w, http.StatusOK, out)
}

// adminAlerts lists what needs a human (PLAN §8.4, §14, §16, §19).
// alerts computes the current alert set (the admin view and the watch loop share it).
func (s *Server) alerts(ctx context.Context) ([]v1.AdminAlert, error) {
	now := s.cfg.Now()
	out := []v1.AdminAlert{}
	apls, err := s.cfg.Store.ListAppliances(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range apls {
		if a.Status != v1.StatusEnrolled {
			continue
		}
		switch s.health(a, now) {
		case v1.HealthSilent:
			out = append(out, v1.AdminAlert{Kind: "silent", Severity: "high", SiteID: a.SiteID, ApplianceID: a.ID, Subject: a.ID, Since: a.LastHeartbeatAt,
				Detail: fmt.Sprintf("no heartbeat for %s", now.Sub(*a.LastHeartbeatAt).Round(time.Hour))})
		case v1.HealthStale:
			out = append(out, v1.AdminAlert{Kind: "stale", Severity: "medium", SiteID: a.SiteID, ApplianceID: a.ID, Subject: a.ID, Since: a.LastHeartbeatAt,
				Detail: fmt.Sprintf("no heartbeat for %s", now.Sub(*a.LastHeartbeatAt).Round(time.Minute))})
		case v1.HealthDegraded:
			out = append(out, v1.AdminAlert{Kind: "degraded", Severity: "medium", SiteID: a.SiteID, ApplianceID: a.ID, Subject: a.ID, Since: a.EngineDownSince,
				Detail: "scan engine not ready (ospd_up / vt_cache_loaded)"})
		}
		if a.UpdateError != "" {
			out = append(out, v1.AdminAlert{Kind: "update_error", Severity: "medium", SiteID: a.SiteID, ApplianceID: a.ID, Subject: a.ID, Detail: a.UpdateError, Since: a.LastHeartbeatAt})
		}
	}
	if bundles, err := s.cfg.Store.ListBundles(ctx); err == nil {
		for _, b := range bundles {
			if b.Status == v1.RolloutHeld {
				out = append(out, v1.AdminAlert{Kind: "rollout_held", Severity: "high", Subject: "bundle " + b.Version, Detail: b.HeldReason, Since: &b.PublishedAt})
			}
		}
	}
	if rels, err := s.cfg.Store.ListReleases(ctx); err == nil {
		for _, rel := range rels {
			if rel.Status == v1.RolloutHeld {
				out = append(out, v1.AdminAlert{Kind: "rollout_held", Severity: "high", Subject: rel.Component + " " + rel.Version, Detail: rel.HeldReason, Since: &rel.PublishedAt})
			}
		}
	}
	sites, err := s.cfg.Store.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	for _, site := range sites {
		if pending, err := s.cfg.Store.ListScopeRequests(ctx, site.ID, v1.ScopePending); err == nil {
			for _, sr := range pending {
				out = append(out, v1.AdminAlert{Kind: "scope_pending", Severity: "low", SiteID: site.ID, Subject: sr.ID, Since: &sr.RequestedAt,
					Detail: fmt.Sprintf("scope change to %v awaits the vendor owner (%s)", sr.AllowedCIDRs, sr.Reason)})
			}
		}
		if site.AttestedAt == nil || now.Sub(*site.AttestedAt) > AttestationMaxAge {
			out = append(out, v1.AdminAlert{Kind: "attestation_stale", Severity: "low", SiteID: site.ID, Subject: site.Name, Since: site.AttestedAt,
				Detail: "scope attestation missing or older than 90 days (PLAN §19.2: quarterly)"})
		}
		if scheds, err := s.cfg.Store.ListSchedules(ctx, site.ID); err == nil {
			for _, sc := range scheds {
				if !sc.Enabled || sc.LastJobID == "" {
					continue
				}
				if job, err := s.cfg.Store.GetJob(ctx, sc.LastJobID); err == nil && (job.Status == v1.JobFailed || job.Status == v1.JobRejected) {
					out = append(out, v1.AdminAlert{Kind: "scan_failed", Severity: "medium", SiteID: site.ID, Subject: sc.Name, Since: job.FinishedAt,
						Detail: fmt.Sprintf("last occurrence %s ended %s: %s", job.ID, job.Status, job.RejectReason)})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) > sevRank(out[j].Severity) })
	return out, nil
}

func (s *Server) adminAlerts(w http.ResponseWriter, r *http.Request) {
	out, err := s.alerts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func sevRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
