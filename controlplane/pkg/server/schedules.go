package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/cron"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// Recurring scans and the job calendar (PLAN §17.4). A schedule is a cron
// window plus a job template; the scheduler materializes one job per
// occurrence ahead of time so the calendar shows it and dispatch picks it
// up when the window opens. Jobs remember their schedule for history.

// ScheduleHorizon: occurrences are materialized this far ahead.
const ScheduleHorizon = 45 * 24 * time.Hour

func scheduleView(sc *store.Schedule) v1.AdminScheduleView {
	v := v1.AdminScheduleView{ID: sc.ID, SiteID: sc.SiteID, ApplianceID: sc.ApplianceID, Name: sc.Name, Mode: sc.Mode, Targets: sc.Targets, Excludes: sc.Excludes,
		Ports: sc.Ports, Modules: sc.Modules, Cron: sc.Cron, TZ: sc.TZ, MaxDurationS: sc.MaxDurationS, Enabled: sc.Enabled, NextOccurrence: sc.NextOccurrence, NextJobID: sc.NextJobID,
		LastJobID: sc.LastJobID, CreatedAt: sc.CreatedAt}
	if v.Targets == nil {
		v.Targets = []string{}
	}
	if v.Excludes == nil {
		v.Excludes = []string{}
	}
	if v.Modules == nil {
		v.Modules = []string{}
	}
	return v
}

func validTargets(in []string) error {
	if len(in) == 0 {
		return errors.New("targets required")
	}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if net.ParseIP(t) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(t); err != nil {
			return errors.New("bad target " + t)
		}
	}
	return nil
}

// buildJob turns an admin request into a validated, queued job for the
// appliance (shared by manual jobs and the scheduler).
func (s *Server) buildJob(ctx context.Context, req v1.AdminJobRequest) (*store.Job, int, string, string) {
	apl, err := s.cfg.Store.GetAppliance(ctx, req.ApplianceID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusNotFound, "no such appliance", "not_found"
	}
	if err != nil {
		return nil, http.StatusInternalServerError, "store error", "store"
	}
	if apl.Status != v1.StatusEnrolled {
		return nil, http.StatusConflict, "appliance is " + apl.Status, "status"
	}
	site, err := s.cfg.Store.GetSite(ctx, apl.SiteID)
	if err != nil {
		return nil, http.StatusInternalServerError, "store error", "store"
	}
	vendor, err := s.cfg.Store.GetVendor(ctx, site.VendorID)
	if err != nil {
		return nil, http.StatusInternalServerError, "store error", "store"
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
		return nil, http.StatusBadRequest, "mode must be discovery|inventory|full", "bad_mode"
	}
	spec.DefaultsFor(req.Mode)
	if req.UDP && !spec.HasModule(v1.ModuleUDP) {
		spec.Modules = append(spec.Modules, v1.ModuleUDP)
	}
	if req.DefaultLogins && !spec.HasModule(v1.ModuleDefaultLogins) {
		spec.Modules = append(spec.Modules, v1.ModuleDefaultLogins)
	}
	if spec.Window != nil && spec.Window.TZ == "" {
		spec.Window.TZ = site.TZ
	}
	if spec.Iface == "" && !strings.EqualFold(req.Iface, "any") {
		spec.Iface = "lan0"
	}
	if !spec.SafeChecks && vendor.Tier <= 1 {
		return nil, http.StatusBadRequest, "safe_checks=false is never allowed for Tier 1 vendors", "safe_checks"
	}
	if st, msg, code := s.applyDepth(ctx, req, site, &spec); st != 0 {
		return nil, st, msg, code
	}
	// Guardrails at creation: the window's cron is not checked (a closed
	// window is rescheduled at dispatch) but its duration is, so the Phase
	// 5 full-range budget sees the real max_duration_s.
	probe := spec
	if probe.Window != nil {
		probe.Window = &v1.Window{MaxDurationS: probe.Window.MaxDurationS}
	}
	if fails := guard.Check(guard.Input{Spec: probe, Site: site.Config(), Now: s.cfg.Now()}); len(fails) > 0 {
		return nil, http.StatusBadRequest, fails[0].Error(), "guardrail_" + fails[0].Check
	}
	job := &store.Job{ID: spec.JobID, SiteID: site.ID, ApplianceID: apl.ID, Status: v1.JobQueued, Spec: spec, ScheduledFor: req.ScheduledFor}
	if job.ScheduledFor == nil && spec.Window != nil && spec.Window.Cron != "" {
		now := s.cfg.Now()
		open, err := cron.WindowOpen(spec.Window.Cron, spec.Window.TZ, time.Duration(spec.Window.MaxDurationS)*time.Second, now, 0)
		if err != nil {
			return nil, http.StatusBadRequest, err.Error(), "bad_window"
		}
		if !open {
			next, err := cron.NextStart(spec.Window.Cron, spec.Window.TZ, now)
			if err != nil {
				return nil, http.StatusBadRequest, err.Error(), "bad_window"
			}
			job.ScheduledFor = &next
		}
	}
	return job, 0, "", ""
}

func (s *Server) scheduleFromRequest(ctx context.Context, req v1.AdminScheduleRequest, sc *store.Schedule) (int, string, string) {
	if sc.ID == "" {
		apl, err := s.cfg.Store.GetAppliance(ctx, req.ApplianceID)
		if errors.Is(err, store.ErrNotFound) {
			return http.StatusNotFound, "no such appliance", "not_found"
		}
		if err != nil {
			return http.StatusInternalServerError, "store error", "store"
		}
		sc.SiteID, sc.ApplianceID = apl.SiteID, apl.ID
	}
	if req.Mode != "" {
		sc.Mode = req.Mode
	}
	if !v1.KnownModes[sc.Mode] {
		return http.StatusBadRequest, "mode must be discovery|inventory|full", "bad_mode"
	}
	if req.Targets != nil {
		sc.Targets = req.Targets
	}
	if err := validTargets(sc.Targets); err != nil {
		return http.StatusBadRequest, err.Error(), "bad_targets"
	}
	if req.Excludes != nil {
		sc.Excludes = req.Excludes
	}
	if req.Ports != "" {
		sc.Ports = req.Ports
	}
	if req.Modules != nil {
		sc.Modules = req.Modules
		if len(sc.Modules) == 0 {
			sc.Modules = nil
		}
	}
	if req.Name != "" {
		sc.Name = req.Name
	}
	if req.Cron != "" {
		sc.Cron = req.Cron
	}
	if _, err := cron.Parse(sc.Cron); err != nil {
		return http.StatusBadRequest, "cron: " + err.Error(), "bad_cron"
	}
	if req.TZ != "" {
		sc.TZ = req.TZ
	}
	if sc.TZ == "" {
		if site, err := s.cfg.Store.GetSite(ctx, sc.SiteID); err == nil {
			sc.TZ = site.TZ
		}
	}
	if _, err := time.LoadLocation(sc.TZ); err != nil {
		return http.StatusBadRequest, "bad tz", "bad_tz"
	}
	if req.MaxDurationS != 0 {
		sc.MaxDurationS = req.MaxDurationS
	}
	if sc.MaxDurationS <= 0 {
		sc.MaxDurationS = 6 * 3600
	}
	if req.Enabled != nil {
		sc.Enabled = *req.Enabled
	}
	// The template must pass the same guardrails as a manual job (scope,
	// ports, rate) so a schedule never produces a stream of rejected jobs.
	if _, st, msg, code := s.buildJob(ctx, v1.AdminJobRequest{ApplianceID: sc.ApplianceID, Mode: sc.Mode, Targets: sc.Targets, Excludes: sc.Excludes, Ports: sc.Ports, Modules: sc.Modules}); st != 0 {
		return st, msg, code
	}
	return 0, "", ""
}

func (s *Server) adminCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminScheduleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	sc := &store.Schedule{Enabled: true, CreatedAt: s.cfg.Now()}
	if st, msg, code := s.scheduleFromRequest(r.Context(), req, sc); st != 0 {
		writeErr(w, st, msg, code)
		return
	}
	if err := s.cfg.Store.CreateSchedule(r.Context(), sc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("schedule created", "schedule", sc.ID, "site", sc.SiteID, "appliance", sc.ApplianceID, "mode", sc.Mode, "cron", sc.Cron, "tz", sc.TZ)
	if err := s.materialize(r.Context(), sc); err != nil {
		s.log.Warn("schedule not materialized", "schedule", sc.ID, "err", err)
	}
	writeJSON(w, http.StatusCreated, scheduleView(sc))
}

func (s *Server) adminListSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListSchedules(r.Context(), r.URL.Query().Get("site"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminScheduleView, 0, len(list))
	for _, sc := range list {
		out = append(out, scheduleView(sc))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadSchedule(w http.ResponseWriter, r *http.Request) *store.Schedule {
	sc, err := s.cfg.Store.GetSchedule(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such schedule", "not_found")
		return nil
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return nil
	}
	return sc
}

func (s *Server) adminGetSchedule(w http.ResponseWriter, r *http.Request) {
	if sc := s.loadSchedule(w, r); sc != nil {
		writeJSON(w, http.StatusOK, scheduleView(sc))
	}
}

func (s *Server) adminUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.loadSchedule(w, r)
	if sc == nil {
		return
	}
	var req v1.AdminScheduleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	before := *sc
	if st, msg, code := s.scheduleFromRequest(r.Context(), req, sc); st != 0 {
		writeErr(w, st, msg, code)
		return
	}
	// A changed template invalidates the job queued for the next occurrence.
	if before.Cron != sc.Cron || before.TZ != sc.TZ || strings.Join(before.Targets, ",") != strings.Join(sc.Targets, ",") || before.Mode != sc.Mode ||
		strings.Join(before.Modules, ",") != strings.Join(sc.Modules, ",") || !sc.Enabled {
		s.cancelNext(r.Context(), sc)
	}
	if err := s.cfg.Store.UpdateSchedule(r.Context(), sc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if err := s.materialize(r.Context(), sc); err != nil {
		s.log.Warn("schedule not materialized", "schedule", sc.ID, "err", err)
	}
	writeJSON(w, http.StatusOK, scheduleView(sc))
}

func (s *Server) adminDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.loadSchedule(w, r)
	if sc == nil {
		return
	}
	s.cancelNext(r.Context(), sc)
	if err := s.cfg.Store.DeleteSchedule(r.Context(), sc.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// cancelNext cancels the not-yet-started job queued for the next occurrence.
func (s *Server) cancelNext(ctx context.Context, sc *store.Schedule) {
	if sc.NextJobID == "" {
		return
	}
	if job, err := s.cfg.Store.GetJob(ctx, sc.NextJobID); err == nil && (job.Status == v1.JobQueued || job.Status == v1.JobDispatched) {
		now := s.cfg.Now()
		job.Status, job.FinishedAt, job.RejectReason = v1.JobCancelled, &now, "schedule changed"
		_ = s.cfg.Store.UpdateJob(ctx, job)
	}
	sc.NextJobID, sc.NextOccurrence = "", nil
}

// occurrence returns the schedule's current (window open) or next start.
func occurrence(sc *store.Schedule, now time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(sc.TZ)
	if err != nil {
		return time.Time{}, err
	}
	sched, err := cron.Parse(sc.Cron)
	if err != nil {
		return time.Time{}, err
	}
	t := now.In(loc)
	if start, ok := sched.LastStart(t, time.Duration(sc.MaxDurationS)*time.Second); ok {
		return start, nil
	}
	return sched.Next(t)
}

// nextAfter is the first start strictly after now.
func nextAfter(sc *store.Schedule, now time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(sc.TZ)
	if err != nil {
		return time.Time{}, err
	}
	sched, err := cron.Parse(sc.Cron)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(now.In(loc))
}

// RunScheduler materializes schedule occurrences every interval.
func (s *Server) RunScheduler(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.withLock(ctx, "scheduler", func() error { return s.SchedulerTick(ctx) }); err != nil {
				s.log.Warn("scheduler tick", "err", err)
			}
		}
	}
}

// SchedulerTick creates the job for each enabled schedule's next occurrence.
func (s *Server) SchedulerTick(ctx context.Context) error {
	list, err := s.cfg.Store.ListSchedules(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	for _, sc := range list {
		if !sc.Enabled {
			continue
		}
		if err := s.materialize(ctx, sc); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// materialize ensures a queued job exists for the schedule's next occurrence.
func (s *Server) materialize(ctx context.Context, sc *store.Schedule) error {
	if !sc.Enabled {
		return nil
	}
	now := s.cfg.Now()
	occ, err := occurrence(sc, now)
	if err != nil {
		return err
	}
	if occ.Sub(now) > ScheduleHorizon {
		return nil
	}
	if sc.NextJobID != "" {
		job, err := s.cfg.Store.GetJob(ctx, sc.NextJobID)
		if err == nil && !job.Terminal() {
			return nil // queued, dispatched or running: nothing to add (dispatch rolls a missed window forward)
		}
		if err == nil && sc.NextOccurrence != nil && sc.NextOccurrence.Equal(occ) {
			// The job for the window that is open now already ran: the next
			// occurrence is the one after it.
			next, err := nextAfter(sc, now)
			if err != nil {
				return err
			}
			occ = next
			if occ.Sub(now) > ScheduleHorizon {
				sc.LastJobID, sc.NextJobID, sc.NextOccurrence = sc.NextJobID, "", nil
				return s.cfg.Store.UpdateSchedule(ctx, sc)
			}
		}
		sc.LastJobID = sc.NextJobID
	}
	req := v1.AdminJobRequest{ApplianceID: sc.ApplianceID, Mode: sc.Mode, Targets: sc.Targets, Excludes: sc.Excludes, Ports: sc.Ports, Modules: sc.Modules,
		Window: &v1.Window{Cron: sc.Cron, TZ: sc.TZ, MaxDurationS: sc.MaxDurationS}, ScheduledFor: &occ}
	job, st, msg, _ := s.buildJob(ctx, req)
	if st != 0 {
		return errors.New("schedule " + sc.ID + ": " + msg)
	}
	job.ScheduleID = sc.ID
	if err := s.cfg.Store.CreateJob(ctx, job); err != nil {
		return err
	}
	sc.NextJobID, sc.NextOccurrence = job.ID, &occ
	if err := s.cfg.Store.UpdateSchedule(ctx, sc); err != nil {
		return err
	}
	s.log.Info("schedule occurrence queued", "schedule", sc.ID, "job", job.ID, "at", occ.UTC().Format(time.RFC3339))
	return nil
}

// adminCalendar lists the site's jobs and computed schedule occurrences in
// [now-days, now+days].
func (s *Server) adminCalendar(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	days := 30
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 366 {
		days = d
	}
	now := s.cfg.Now()
	from, to := now.Add(-time.Duration(days)*24*time.Hour), now.Add(time.Duration(days)*24*time.Hour)
	jobs, err := s.cfg.Store.ListJobs(r.Context(), site.ID, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	schedules, err := s.cfg.Store.ListSchedules(r.Context(), site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	names := map[string]string{}
	for _, sc := range schedules {
		names[sc.ID] = sc.Name
	}
	out := []v1.AdminCalendarEntry{}
	queued := map[string]bool{}
	for _, j := range jobs {
		at := j.CreatedAt
		switch {
		case j.StartedAt != nil:
			at = *j.StartedAt
		case j.ScheduledFor != nil:
			at = *j.ScheduledFor
		}
		if at.Before(from) || at.After(to) {
			continue
		}
		if j.ScheduleID != "" && j.ScheduledFor != nil && !j.Terminal() {
			queued[j.ScheduleID+"@"+j.ScheduledFor.UTC().Format(time.RFC3339)] = true
		}
		out = append(out, v1.AdminCalendarEntry{At: at, Kind: "job", ScheduleID: j.ScheduleID, ScheduleName: names[j.ScheduleID], JobID: j.ID, Mode: j.Spec.Mode,
			Status: j.Status, RejectReason: j.RejectReason, Targets: j.Spec.Targets})
	}
	for _, sc := range schedules {
		if !sc.Enabled {
			continue
		}
		loc, err := time.LoadLocation(sc.TZ)
		if err != nil {
			continue
		}
		sched, err := cron.Parse(sc.Cron)
		if err != nil {
			continue
		}
		t := now.In(loc)
		for i := 0; i < 200; i++ {
			next, err := sched.Next(t)
			if err != nil || next.After(to) {
				break
			}
			if !queued[sc.ID+"@"+next.UTC().Format(time.RFC3339)] {
				out = append(out, v1.AdminCalendarEntry{At: next, Kind: "occurrence", ScheduleID: sc.ID, ScheduleName: sc.Name, Mode: sc.Mode, Targets: sc.Targets})
			}
			t = next
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	for i := range out {
		if out[i].Targets == nil {
			out[i].Targets = []string{}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
