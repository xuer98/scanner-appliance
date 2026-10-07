package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// ---- /admin/jobs ----

func (s *Server) adminCreateJob(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminJobRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	job, st, msg, code := s.buildJob(r.Context(), req)
	if st != 0 {
		writeErr(w, st, msg, code)
		return
	}
	if err := s.cfg.Store.CreateJob(r.Context(), job); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("job created", "job", job.ID, "appliance", job.ApplianceID, "mode", job.Spec.Mode, "scheduled_for", job.ScheduledFor)
	writeJSON(w, http.StatusCreated, jobView(job))
}

func (s *Server) adminListJobs(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListJobs(r.Context(), r.URL.Query().Get("site"), r.URL.Query().Get("appliance"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminJobView, 0, len(list))
	for _, j := range list {
		out = append(out, jobView(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadJob(w http.ResponseWriter, r *http.Request) *store.Job {
	job, err := s.cfg.Store.GetJob(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such job", "not_found")
		return nil
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return nil
	}
	return job
}

func (s *Server) adminGetJob(w http.ResponseWriter, r *http.Request) {
	if job := s.loadJob(w, r); job != nil {
		writeJSON(w, http.StatusOK, jobView(job))
	}
}

func (s *Server) adminCancelJob(w http.ResponseWriter, r *http.Request) {
	job := s.loadJob(w, r)
	if job == nil {
		return
	}
	switch job.Status {
	case v1.JobQueued, v1.JobDispatched:
	case v1.JobRunning:
		writeErr(w, http.StatusConflict, "job is running; queue a stop_all directive to halt it", "running")
		return
	default:
		writeErr(w, http.StatusConflict, "job is "+job.Status, "terminal")
		return
	}
	now := s.cfg.Now()
	job.Status = v1.JobCancelled
	job.FinishedAt = &now
	if err := s.cfg.Store.UpdateJob(r.Context(), job); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, jobView(job))
}

// adminRunJobNow drops the window (the spec is re-signed at dispatch) and
// queues a run_job_now directive so the appliance polls immediately.
func (s *Server) adminRunJobNow(w http.ResponseWriter, r *http.Request) {
	job := s.loadJob(w, r)
	if job == nil {
		return
	}
	if job.Status != v1.JobQueued && job.Status != v1.JobDispatched {
		writeErr(w, http.StatusConflict, "job is "+job.Status, "status")
		return
	}
	now := s.cfg.Now()
	job.Spec.Window = nil
	job.ScheduledFor = &now
	job.Status = v1.JobQueued
	job.DispatchedAt = nil
	if err := s.cfg.Store.UpdateJob(r.Context(), job); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if _, err := s.cfg.Store.CreateDirective(r.Context(), job.ApplianceID, v1.DirectiveRunJobNow, map[string]any{"job_id": job.ID}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, jobView(job))
}

func (s *Server) adminJobHosts(w http.ResponseWriter, r *http.Request) {
	job := s.loadJob(w, r)
	if job == nil {
		return
	}
	hosts, err := s.cfg.Store.ListJobHosts(r.Context(), job.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.writeHosts(w, r, hosts)
}

func jobView(j *store.Job) v1.AdminJobView {
	return v1.AdminJobView{ID: j.ID, SiteID: j.SiteID, ApplianceID: j.ApplianceID, Status: j.Status, Spec: j.Spec, ScheduledFor: j.ScheduledFor,
		DispatchedAt: j.DispatchedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, ProgressPct: j.ProgressPct, Phase: j.Phase,
		RejectReason: j.RejectReason, Batches: j.Batches, Stats: j.Stats, CreatedAt: j.CreatedAt, ScheduleID: j.ScheduleID}
}

// ---- /admin/sites ----

func (s *Server) siteView(r *http.Request, site *store.Site) v1.AdminSiteView {
	v := v1.AdminSiteView{ID: site.ID, VendorID: site.VendorID, Name: site.Name, Config: site.Config(), AttestedAt: site.AttestedAt, AttestedBy: site.AttestedBy}
	if vendor, err := s.cfg.Store.GetVendor(r.Context(), site.VendorID); err == nil {
		v.VendorName, v.VendorTier = vendor.Name, vendor.Tier
	}
	if pending, err := s.cfg.Store.ListScopeRequests(r.Context(), site.ID, v1.ScopePending); err == nil {
		v.PendingScope = len(pending)
	}
	v.AttestionStale = site.AttestedAt == nil || s.cfg.Now().Sub(*site.AttestedAt) > AttestationMaxAge
	return v
}

func (s *Server) adminListSites(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListSites(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminSiteView, 0, len(list))
	for _, site := range list {
		out = append(out, s.siteView(r, site))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadSite(w http.ResponseWriter, r *http.Request) *store.Site {
	site, err := s.cfg.Store.GetSite(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such site", "not_found")
		return nil
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return nil
	}
	return site
}

func (s *Server) adminGetSite(w http.ResponseWriter, r *http.Request) {
	if site := s.loadSite(w, r); site != nil {
		writeJSON(w, http.StatusOK, s.siteView(r, site))
	}
}

func (s *Server) adminUpdateSite(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.AdminSiteUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	var changes []store.SiteChange
	note := func(kind, field string, old, cur any) {
		if jsonStr(old) != jsonStr(cur) {
			changes = append(changes, store.SiteChange{Kind: kind, Field: field, Old: jsonStr(old), New: jsonStr(cur)})
		}
	}
	if req.AllowedCIDRs != nil {
		if err := guard.ValidCIDRs(*req.AllowedCIDRs); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error(), "bad_cidr")
			return
		}
		if jsonStr(*req.AllowedCIDRs) != jsonStr(site.AllowedCIDRs) {
			// PLAN §16: no change to allowed_cidrs without the vendor owner.
			if s.role(r) != v1.RoleVendorOwner {
				writeErr(w, http.StatusConflict, "allowed_cidrs changes need a scope request approved by the vendor owner (POST /admin/sites/{id}/scope-requests)", "scope_approval_required")
				return
			}
			note("scope", "allowed_cidrs", site.AllowedCIDRs, *req.AllowedCIDRs)
			site.AllowedCIDRs = *req.AllowedCIDRs
		}
	}
	if req.Excludes != nil {
		note("policy", "excludes", site.Excludes, *req.Excludes)
		site.Excludes = *req.Excludes
	}
	if req.FragilePorts != nil {
		note("fragile", "fragile_ports", site.FragilePorts, *req.FragilePorts)
		site.FragilePorts = *req.FragilePorts
	}
	if req.TZ != nil {
		if _, err := time.LoadLocation(*req.TZ); err != nil {
			writeErr(w, http.StatusBadRequest, "bad tz", "bad_tz")
			return
		}
		note("policy", "tz", site.TZ, *req.TZ)
		site.TZ = *req.TZ
	}
	if req.MaxPPS != nil {
		note("policy", "max_pps", site.MaxPPS, *req.MaxPPS)
		site.MaxPPS = *req.MaxPPS
	}
	if req.MaxConcurrency != nil {
		note("policy", "max_concurrency", site.MaxConcurrency, *req.MaxConcurrency)
		site.MaxConcurrency = *req.MaxConcurrency
	}
	if req.UnsafeOK != nil {
		if *req.UnsafeOK {
			if vendor, err := s.cfg.Store.GetVendor(r.Context(), site.VendorID); err == nil && vendor.Tier <= 1 {
				writeErr(w, http.StatusBadRequest, "unsafe_ok is never allowed for Tier 1 vendors", "safe_checks")
				return
			}
		}
		note("policy", "unsafe_ok", site.UnsafeOK, *req.UnsafeOK)
		site.UnsafeOK = *req.UnsafeOK
	}
	if req.AllowPublic != nil {
		note("policy", "allow_public", site.AllowPublic, *req.AllowPublic)
		site.AllowPublic = *req.AllowPublic
	}
	if req.LANRoutes != nil {
		for _, rt := range *req.LANRoutes {
			if _, _, err := net.ParseCIDR(rt.CIDR); err != nil {
				writeErr(w, http.StatusBadRequest, "lan_routes: bad cidr "+rt.CIDR, "bad_cidr")
				return
			}
			if ip := net.ParseIP(rt.Via); ip == nil || ip.To4() == nil {
				writeErr(w, http.StatusBadRequest, "lan_routes: bad gateway "+rt.Via, "bad_gateway")
				return
			}
		}
		note("policy", "lan_routes", site.LANRoutes, *req.LANRoutes)
		site.LANRoutes = *req.LANRoutes
	}
	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, s.siteView(r, site))
		return
	}
	if err := s.commitSite(r.Context(), site, s.actor(r), changes); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("site updated", "site", site.ID, "version", site.Version, "changes", len(changes), "allowed_cidrs", site.AllowedCIDRs)
	writeJSON(w, http.StatusOK, s.siteView(r, site))
}

func (s *Server) adminSiteHosts(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	hosts, err := s.cfg.Store.ListHosts(r.Context(), site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.writeHosts(w, r, hosts)
}

func (s *Server) adminSiteFindings(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	list, err := s.cfg.Store.ListFindings(r.Context(), site.ID, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	tier := s.vendorTier(r.Context(), site.VendorID)
	out := make([]v1.AdminFindingView, 0, len(list))
	for _, f := range list {
		out = append(out, s.findingViewTier(f, tier))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminAgentInventory(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.AdminAgentInventoryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if len(req.Hosts) > maxHostsPerChunk {
		writeErr(w, http.StatusBadRequest, "too many hosts", "too_large")
		return
	}
	sum, err := s.cfg.Store.IngestAgentHosts(r.Context(), site.ID, req.Hosts, s.cfg.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, v1.AdminAgentInventoryResponse{Hosts: sum.Hosts, Merged: sum.Merged, Created: sum.Created})
}

func (s *Server) writeHosts(w http.ResponseWriter, r *http.Request, hosts []*store.Host) {
	out := make([]v1.AdminHostView, 0, len(hosts))
	tiers := map[string]int{}
	for _, h := range hosts {
		v := hostView(h)
		findings, err := s.cfg.Store.ListFindings(r.Context(), "", h.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		tier, ok := tiers[h.SiteID]
		if !ok {
			tier = s.siteTier(r.Context(), h.SiteID)
			tiers[h.SiteID] = tier
		}
		for _, f := range findings {
			v.Findings = append(v.Findings, s.findingViewTier(f, tier))
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// siteTier is the vendor tier of a site (0 when unknown).
func (s *Server) siteTier(ctx context.Context, siteID string) int {
	site, err := s.cfg.Store.GetSite(ctx, siteID)
	if err != nil {
		return 0
	}
	return s.vendorTier(ctx, site.VendorID)
}

func hostView(h *store.Host) v1.AdminHostView {
	v := v1.AdminHostView{ID: h.ID, SiteID: h.SiteID, IP: h.IP, MAC: h.MAC, Hostname: h.Hostname, Source: h.Source, AgentID: h.AgentID,
		OSGuess: h.OSGuess, Ports: h.Ports, Notes: h.Notes, CPEs: h.CPEs, LastJobID: h.LastJobID, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen, Findings: []v1.AdminFindingView{}}
	if v.Ports == nil {
		v.Ports = []v1.Port{}
	}
	return v
}

func findingView(f *store.Finding) v1.AdminFindingView {
	v := v1.AdminFindingView{ID: f.ID, HostID: f.HostID, Source: f.Source, State: f.State, NVTOID: f.NVTOID, TemplateID: f.TemplateID, Name: f.Name, Family: f.Family,
		Severity: f.Severity, CVSS: f.CVSS, CVE: f.CVE, QoD: f.QoD, Port: f.Port, Proto: f.Proto, Solution: f.Solution, Evidence: f.Evidence,
		FeedVersion: f.FeedVersion, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		Review: f.Review, ReviewedAt: f.ReviewedAt, ReviewedBy: f.ReviewedBy, ReviewReason: f.ReviewReason,
		NetworkReachable: f.Source != v1.SourceAgent, ExposureMultiplier: 1}
	if v.NetworkReachable {
		v.ExposureMultiplier = v1.ExposureMultiplier
	}
	if v.CVE == nil {
		v.CVE = []string{}
	}
	if v.Evidence == nil {
		v.Evidence = []v1.Evidence{}
	}
	return v
}
