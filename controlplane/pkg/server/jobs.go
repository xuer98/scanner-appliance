package server

import (
	"errors"
	"net/http"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/cron"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// DispatchLease is how long a dispatched job may go without a "running"
// report before it is offered again.
const DispatchLease = 10 * time.Minute

// ---- GET /v1/appliances/{id}/jobs ----
//
// The server-side half of the guardrails (PLAN §11): the job is checked
// against the site scope, its window and the appliance's last reported
// state before it is signed and handed out.
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	now := s.cfg.Now()
	if apl.LastHeartbeat != nil && apl.LastHeartbeat.StopAll {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	site, err := s.cfg.Store.GetSite(r.Context(), apl.SiteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	jobs, err := s.cfg.Store.DispatchableJobs(r.Context(), apl.ID, now, DispatchLease)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	for _, job := range jobs {
		log := s.log.With("job", job.ID, "appliance", apl.ID)
		spec := job.Spec
		spec.SiteID, spec.ApplianceID = site.ID, apl.ID
		fails := guard.Check(guard.Input{Spec: spec, Site: site.Config(), Now: now, SkewTolerance: MaxSkew})
		if len(fails) > 0 {
			if len(fails) == 1 && fails[0].Check == guard.CheckWindow && spec.Window != nil {
				// Missed or not-yet-open window: roll to the next start.
				tz := spec.Window.TZ
				if tz == "" {
					tz = site.TZ
				}
				if next, err := cron.NextStart(spec.Window.Cron, tz, now); err == nil {
					job.ScheduledFor = &next
					job.Status = v1.JobQueued
					_ = s.cfg.Store.UpdateJob(r.Context(), job)
					log.Info("job window closed; rescheduled", "next", next.UTC().Format(time.RFC3339))
					continue
				}
			}
			job.Status = v1.JobRejected
			job.RejectReason = "server " + fails[0].Error()
			job.FinishedAt = &now
			_ = s.cfg.Store.UpdateJob(r.Context(), job)
			log.Warn("job rejected at dispatch", "reason", job.RejectReason)
			continue
		}
		if spec.HasModule(v1.ModuleOpenVAS) && (apl.LastHeartbeat == nil || !apl.LastHeartbeat.Engine.Ready()) {
			log.Info("job waiting: engine not ready")
			continue
		}
		spec.IssuedAt = now.Unix()
		spec.Sig = ""
		body, err := spec.SigningBytes()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "sign error", "sign")
			return
		}
		sig, err := s.cfg.CA.SignJob(body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "sign error", "sign")
			return
		}
		spec.Sig = sig
		job.Spec = spec
		job.Status = v1.JobDispatched
		job.DispatchedAt = &now
		if err := s.cfg.Store.UpdateJob(r.Context(), job); err != nil {
			writeErr(w, http.StatusInternalServerError, "store error", "store")
			return
		}
		log.Info("job dispatched", "mode", spec.Mode, "targets", spec.Targets)
		writeJSON(w, http.StatusOK, v1.JobsResponse{Job: spec, Site: site.Config(), ServerEpoch: now.Unix()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- POST /v1/jobs/{job}/status ----

func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	job, err := s.cfg.Store.GetJob(r.Context(), r.PathValue("job"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such job", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	if job.ApplianceID != apl.ID {
		writeErr(w, http.StatusForbidden, "job belongs to another appliance", "job_owner")
		return
	}
	var req v1.JobStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	now := s.cfg.Now()
	log := s.log.With("job", job.ID, "appliance", apl.ID)
	if job.Terminal() {
		if job.Status == req.Status {
			w.WriteHeader(http.StatusNoContent) // idempotent repeat
			return
		}
		writeErr(w, http.StatusConflict, "job is already "+job.Status, "terminal")
		return
	}
	switch req.Status {
	case v1.JobRunning:
		job.Status = v1.JobRunning
		if job.StartedAt == nil {
			job.StartedAt = &now
		}
		job.ProgressPct, job.Phase = clampPct(req.ProgressPct), req.Phase
	case v1.JobRejected:
		job.Status = v1.JobRejected
		job.RejectReason = "appliance " + req.Check + ": " + req.Reason
		job.FinishedAt = &now
		log.Warn("job rejected by appliance", "check", req.Check, "reason", req.Reason)
	case v1.JobFailed:
		job.Status = v1.JobFailed
		job.RejectReason = req.Reason
		job.ProgressPct, job.Phase = clampPct(req.ProgressPct), req.Phase
		job.FinishedAt = &now
		log.Warn("job failed", "reason", req.Reason)
	case v1.JobDone:
		job.Status = v1.JobDone
		job.ProgressPct, job.Phase = 100, req.Phase
		if job.FinishedAt == nil {
			job.FinishedAt = &now
		}
		log.Info("job done")
	default:
		writeErr(w, http.StatusBadRequest, "status must be running|rejected|failed|done", "bad_status")
		return
	}
	if err := s.cfg.Store.UpdateJob(r.Context(), job); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func clampPct(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
