package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/cron"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// ---- /admin/jobs ----

func (s *Server) adminCreateJob(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminJobRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	ctx := r.Context()
	apl, err := s.cfg.Store.GetAppliance(ctx, req.ApplianceID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	if apl.Status != v1.StatusEnrolled {
		writeErr(w, http.StatusConflict, "appliance is "+apl.Status, "status")
		return
	}
	site, err := s.cfg.Store.GetSite(ctx, apl.SiteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	vendor, err := s.cfg.Store.GetVendor(ctx, site.VendorID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	spec := v1.JobSpec{JobID: store.NewID("job"), SiteID: site.ID, ApplianceID: apl.ID, Targets: req.Targets, Excludes: req.Excludes,
		Ports: req.Ports, Modules: req.Modules, OpenVAS: req.OpenVAS, Window: req.Window, SafeChecks: true, AllowPublic: req.AllowPublic, Iface: req.Iface}
	if req.Rate != nil {
		spec.Rate = *req.Rate
	}
	if req.SafeChecks != nil {
		spec.SafeChecks = *req.SafeChecks
	}
	if !v1.KnownModes[req.Mode] {
		writeErr(w, http.StatusBadRequest, "mode must be discovery|inventory|full", "bad_mode")
		return
	}
	spec.DefaultsFor(req.Mode)
	if spec.Window != nil && spec.Window.TZ == "" {
		spec.Window.TZ = site.TZ
	}
	if spec.Iface == "" && !strings.EqualFold(req.Iface, "any") {
		spec.Iface = "lan0"
	}
	if !spec.SafeChecks && vendor.Tier <= 1 {
		writeErr(w, http.StatusBadRequest, "safe_checks=false is never allowed for Tier 1 vendors", "safe_checks")
		return
	}
	// Everything but the window is checked now; the window is checked at dispatch.
	probe := spec
	probe.Window = nil
	if fails := guard.Check(guard.Input{Spec: probe, Site: site.Config(), Now: s.cfg.Now()}); len(fails) > 0 {
		writeErr(w, http.StatusBadRequest, fails[0].Error(), "guardrail_"+fails[0].Check)
		return
	}
	job := &store.Job{ID: spec.JobID, SiteID: site.ID, ApplianceID: apl.ID, Status: v1.JobQueued, Spec: spec, ScheduledFor: req.ScheduledFor}
	if job.ScheduledFor == nil && spec.Window != nil && spec.Window.Cron != "" {
		now := s.cfg.Now()
		open, err := cron.WindowOpen(spec.Window.Cron, spec.Window.TZ, time.Duration(spec.Window.MaxDurationS)*time.Second, now, 0)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error(), "bad_window")
			return
		}
		if !open {
			next, err := cron.NextStart(spec.Window.Cron, spec.Window.TZ, now)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error(), "bad_window")
				return
			}
			job.ScheduledFor = &next
		}
	}
	if err := s.cfg.Store.CreateJob(ctx, job); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("job created", "job", job.ID, "appliance", apl.ID, "mode", spec.Mode, "scheduled_for", job.ScheduledFor)
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
		RejectReason: j.RejectReason, Batches: j.Batches, Stats: j.Stats, CreatedAt: j.CreatedAt}
}

// ---- /admin/sites ----

func (s *Server) siteView(r *http.Request, site *store.Site) v1.AdminSiteView {
	v := v1.AdminSiteView{ID: site.ID, VendorID: site.VendorID, Name: site.Name, Config: site.Config()}
	if vendor, err := s.cfg.Store.GetVendor(r.Context(), site.VendorID); err == nil {
		v.VendorName, v.VendorTier = vendor.Name, vendor.Tier
	}
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
	if req.AllowedCIDRs != nil {
		if err := guard.ValidCIDRs(*req.AllowedCIDRs); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error(), "bad_cidr")
			return
		}
		site.AllowedCIDRs = *req.AllowedCIDRs
	}
	if req.Excludes != nil {
		site.Excludes = *req.Excludes
	}
	if req.FragilePorts != nil {
		site.FragilePorts = *req.FragilePorts
	}
	if req.TZ != nil {
		if _, err := time.LoadLocation(*req.TZ); err != nil {
			writeErr(w, http.StatusBadRequest, "bad tz", "bad_tz")
			return
		}
		site.TZ = *req.TZ
	}
	if req.MaxPPS != nil {
		site.MaxPPS = *req.MaxPPS
	}
	if req.MaxConcurrency != nil {
		site.MaxConcurrency = *req.MaxConcurrency
	}
	if req.UnsafeOK != nil {
		if *req.UnsafeOK {
			if vendor, err := s.cfg.Store.GetVendor(r.Context(), site.VendorID); err == nil && vendor.Tier <= 1 {
				writeErr(w, http.StatusBadRequest, "unsafe_ok is never allowed for Tier 1 vendors", "safe_checks")
				return
			}
		}
		site.UnsafeOK = *req.UnsafeOK
	}
	if req.AllowPublic != nil {
		site.AllowPublic = *req.AllowPublic
	}
	if err := s.cfg.Store.UpdateSite(r.Context(), site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("site scope updated", "site", site.ID, "allowed_cidrs", site.AllowedCIDRs)
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
	out := make([]v1.AdminFindingView, 0, len(list))
	for _, f := range list {
		out = append(out, findingView(f))
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
	for _, h := range hosts {
		v := hostView(h)
		findings, err := s.cfg.Store.ListFindings(r.Context(), "", h.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		for _, f := range findings {
			v.Findings = append(v.Findings, findingView(f))
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func hostView(h *store.Host) v1.AdminHostView {
	v := v1.AdminHostView{ID: h.ID, SiteID: h.SiteID, IP: h.IP, MAC: h.MAC, Hostname: h.Hostname, Source: h.Source, AgentID: h.AgentID,
		OSGuess: h.OSGuess, Ports: h.Ports, Notes: h.Notes, LastJobID: h.LastJobID, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen, Findings: []v1.AdminFindingView{}}
	if v.Ports == nil {
		v.Ports = []v1.Port{}
	}
	return v
}

func findingView(f *store.Finding) v1.AdminFindingView {
	v := v1.AdminFindingView{ID: f.ID, HostID: f.HostID, Source: f.Source, State: f.State, NVTOID: f.NVTOID, Name: f.Name, Family: f.Family,
		Severity: f.Severity, CVSS: f.CVSS, CVE: f.CVE, QoD: f.QoD, Port: f.Port, Proto: f.Proto, Solution: f.Solution, Evidence: f.Evidence,
		FeedVersion: f.FeedVersion, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen}
	if v.CVE == nil {
		v.CVE = []string{}
	}
	if v.Evidence == nil {
		v.Evidence = []v1.Evidence{}
	}
	return v
}
