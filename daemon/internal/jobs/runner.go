package jobs

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/cpclient"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/internal/guard"
	"github.com/tprm/scanner-appliance/internal/seal"
)

// Control is the subset of cpclient the runner needs (mockable).
type Control interface {
	Jobs(ctx context.Context, cpURL, id string) (*v1.JobsResponse, error)
	JobStatus(ctx context.Context, cpURL, jobID string, st v1.JobStatusRequest) error
	UploadResults(ctx context.Context, cpURL, jobID string, seq int, final bool, sha256Hex string, body []byte) (*v1.ResultAck, error)
}

// Checks the appliance adds to the shared guardrails.
const (
	CheckSignature = "signature"
	CheckAppliance = "appliance"
	CheckEngine    = "engine"
	CheckStopAll   = "stop_all"
	CheckSpoolKey  = "spool_key"
)

// Runner owns at most one running job.
type Runner struct {
	Store  *state.Store
	Engine *engine.Engine
	Spool  *spool.Spool
	Roots  *x509.CertPool
	Log    *slog.Logger
	Now    func() time.Time
	// Fresh bounds issued_at (default 1 h); SkewTolerance widens the window check (default 5 min).
	Fresh         time.Duration
	SkewTolerance time.Duration

	mu      sync.Mutex
	cur     *current
	control Control
	cpURL   string
	// StopAll reason while the current job is being cancelled.
	stopReason string
}

type current struct {
	spec     v1.JobSpec
	started  time.Time
	progress engine.Progress
	cancel   context.CancelFunc
	done     chan struct{}
}

func (r *Runner) init() {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Fresh == 0 {
		r.Fresh = time.Hour
	}
	if r.SkewTolerance == 0 {
		r.SkewTolerance = 5 * time.Minute
	}
}

// Idle reports whether no job is running.
func (r *Runner) Idle() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur == nil
}

// Progress is the heartbeat's current_job (nil when idle).
func (r *Runner) Progress() *v1.JobProgress {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil {
		return nil
	}
	return &v1.JobProgress{ID: r.cur.spec.JobID, Phase: r.cur.progress.Phase, ProgressPct: r.cur.progress.Pct, StartedAt: r.cur.started.Unix()}
}

// Pending is the spool backlog.
func (r *Runner) Pending() int {
	if r.Spool == nil {
		return 0
	}
	return r.Spool.Count()
}

// StopAll cancels the running job (PLAN §8.2: stop_scan over OSP + kill naabu).
func (r *Runner) StopAll(reason string) {
	r.mu.Lock()
	c := r.cur
	if c != nil {
		r.stopReason = reason
	}
	r.mu.Unlock()
	if c != nil {
		r.Log.Warn("stopping running job", "job", c.spec.JobID, "reason", reason)
		c.cancel()
	}
}

// Wait blocks until the current job (if any) has finished (tests, shutdown).
func (r *Runner) Wait() {
	r.mu.Lock()
	c := r.cur
	r.mu.Unlock()
	if c != nil {
		<-c.done
	}
}

// Poll asks the control plane for a job and starts it if every check passes.
func (r *Runner) Poll(ctx context.Context, cl Control, st *state.State, health v1.EngineHealth) {
	r.init()
	r.mu.Lock()
	r.control, r.cpURL = cl, st.CPURL
	busy := r.cur != nil
	r.mu.Unlock()
	if busy || st.ApplianceID == "" {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	resp, err := cl.Jobs(pctx, st.CPURL, st.ApplianceID)
	cancel()
	if err != nil {
		r.Log.Warn("job poll failed", "err", err)
		return
	}
	if resp == nil {
		return
	}
	spec := resp.Job
	log := r.Log.With("job", spec.JobID, "mode", spec.Mode)
	// The dispatched site config is authoritative: persist it.
	st.Site = resp.Site
	if err := r.Store.Save(st); err != nil {
		log.Warn("site config not saved", "err", err)
	}
	reject := func(check, detail string) {
		log.Warn("job rejected", "check", check, "detail", detail)
		r.report(ctx, spec.JobID, v1.JobStatusRequest{Status: v1.JobRejected, Check: check, Reason: detail})
	}
	if spec.ApplianceID != st.ApplianceID {
		reject(CheckAppliance, "job is addressed to "+spec.ApplianceID)
		return
	}
	chain, err := r.chain()
	if err != nil {
		reject(CheckSignature, err.Error())
		return
	}
	if err := VerifySpec(spec, chain, r.Roots, r.Now(), r.Fresh); err != nil {
		reject(CheckSignature, err.Error())
		return
	}
	if fails := guard.Check(guard.Input{Spec: spec, Site: resp.Site, Now: r.Now(), SkewTolerance: r.SkewTolerance}); len(fails) > 0 {
		for _, f := range fails[1:] {
			log.Warn("guardrail failed", "check", f.Check, "detail", f.Detail)
		}
		reject(fails[0].Check, fails[0].Detail)
		return
	}
	if st.StopAll {
		reject(CheckStopAll, "stop_all is active on this appliance")
		return
	}
	if spec.HasModule(v1.ModuleOpenVAS) && !health.Ready() {
		reject(CheckEngine, fmt.Sprintf("engine not ready (ospd_up=%v vt_cache_loaded=%v %s)", health.OSPDUp, health.VTCacheLoaded, health.Error))
		return
	}
	if st.SpoolPubKey == "" {
		reject(CheckSpoolKey, spool.ErrNoKey.Error())
		return
	}
	pub, err := seal.ParsePublic(st.SpoolPubKey)
	if err != nil {
		reject(CheckSpoolKey, "bad spool key: "+err.Error())
		return
	}
	r.Spool.Pub = pub
	r.Engine.ApplianceID = st.ApplianceID
	r.start(ctx, spec, resp.Site)
}

// chain returns the CA certificates stored with the client certificate.
func (r *Runner) chain() ([]*x509.Certificate, error) {
	cert, err := r.Store.Certificate()
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *Runner) start(parent context.Context, spec v1.JobSpec, site v1.SiteConfig) {
	deadline := r.Now().Add(time.Duration(spec.MaxDuration()) * time.Second)
	jctx, cancel := context.WithDeadline(parent, deadline)
	c := &current{spec: spec, started: r.Now(), cancel: cancel, done: make(chan struct{}), progress: engine.Progress{Phase: engine.PhaseDiscovery}}
	r.mu.Lock()
	r.cur = c
	r.stopReason = ""
	r.mu.Unlock()
	r.Log.Info("job starting", "job", spec.JobID, "mode", spec.Mode, "targets", spec.Targets, "deadline", deadline.UTC().Format(time.RFC3339))
	r.report(parent, spec.JobID, v1.JobStatusRequest{Status: v1.JobRunning, Phase: engine.PhaseDiscovery})
	go func() {
		defer close(c.done)
		defer cancel()
		stats, err := r.Engine.Run(jctx, spec, site, &sink{r: r, c: c})
		term := v1.JobStatusRequest{Status: v1.JobDone, ProgressPct: 100, Phase: engine.PhaseFinalize}
		r.mu.Lock()
		reason := r.stopReason
		r.mu.Unlock()
		switch {
		case err == nil:
			r.Log.Info("job done", "job", spec.JobID, "hosts_alive", stats.HostsAlive, "findings", stats.Findings, "duration_s", stats.DurationS)
		case errors.Is(err, engine.ErrStopped) && reason != "":
			term = v1.JobStatusRequest{Status: v1.JobFailed, Reason: "stopped: " + reason, Phase: c.progress.Phase, ProgressPct: c.progress.Pct}
		case errors.Is(err, engine.ErrStopped):
			term = v1.JobStatusRequest{Status: v1.JobFailed, Reason: "stopped: daemon shutting down", Phase: c.progress.Phase, ProgressPct: c.progress.Pct}
		case errors.Is(err, engine.ErrTimeout):
			term = v1.JobStatusRequest{Status: v1.JobFailed, Reason: fmt.Sprintf("max_duration_s (%d) exceeded", spec.MaxDuration()), Phase: c.progress.Phase, ProgressPct: c.progress.Pct}
		default:
			term = v1.JobStatusRequest{Status: v1.JobFailed, Reason: err.Error(), Phase: c.progress.Phase, ProgressPct: c.progress.Pct}
		}
		if term.Status != v1.JobDone {
			r.Log.Warn("job failed", "job", spec.JobID, "reason", term.Reason)
		}
		if err := r.Spool.SetTerminal(spec.JobID, term); err != nil {
			r.Log.Error("terminal status not recorded", "job", spec.JobID, "err", err)
		}
		r.mu.Lock()
		r.cur = nil
		r.mu.Unlock()
		// Flush with a fresh context: the parent may be shutting down.
		fctx, fcancel := context.WithTimeout(context.Background(), 2*time.Minute)
		r.Flush(fctx)
		fcancel()
	}()
}

// sink spools chunks and tracks progress for the heartbeat.
type sink struct {
	r *Runner
	c *current
}

func (s *sink) Emit(_ context.Context, b v1.ResultBatch) error {
	ch, err := s.r.Spool.Put(b)
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	s.r.Log.Info("result chunk spooled", "job", b.JobID, "seq", b.Seq, "final", b.Final, "hosts", len(b.Hosts), "bytes", ch.Size)
	return nil
}

func (s *sink) Progress(p engine.Progress) {
	s.r.mu.Lock()
	s.c.progress = p
	s.r.mu.Unlock()
}

// report sends a status; failures fall back to the spool's terminal marker
// for terminal states so they are retried by Flush.
func (r *Runner) report(ctx context.Context, jobID string, st v1.JobStatusRequest) {
	r.mu.Lock()
	cl, cpURL := r.control, r.cpURL
	r.mu.Unlock()
	if cl == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := cl.JobStatus(rctx, cpURL, jobID, st); err != nil {
		r.Log.Warn("job status not delivered", "job", jobID, "status", st.Status, "err", err)
		if st.Status != v1.JobRunning && !cpclient.IsPermanent(err) {
			_ = r.Spool.SetTerminal(jobID, st)
		}
	}
}

// Flush uploads pending chunks in order and reports recorded terminal
// statuses once their chunks are gone. Transport errors stop the pass
// (retried on the next heartbeat); permanent rejections drop the item.
func (r *Runner) Flush(ctx context.Context) {
	r.init()
	r.mu.Lock()
	cl, cpURL := r.control, r.cpURL
	r.mu.Unlock()
	if cl == nil || r.Spool == nil {
		return
	}
	pending, err := r.Spool.Pending()
	if err != nil {
		r.Log.Warn("spool unreadable", "err", err)
		return
	}
	for _, ch := range pending {
		body, err := r.Spool.Read(ch)
		if err != nil {
			r.Log.Warn("chunk unreadable; dropping", "path", ch.Path, "err", err)
			_ = r.Spool.Remove(ch)
			continue
		}
		uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		ack, err := cl.UploadResults(uctx, cpURL, ch.JobID, ch.Seq, ch.Final, ch.SHA256, body)
		cancel()
		if err != nil {
			if cpclient.IsPermanent(err) {
				r.Log.Warn("chunk rejected permanently; dropping", "job", ch.JobID, "seq", ch.Seq, "err", err)
				_ = r.Spool.Remove(ch)
				continue
			}
			r.Log.Warn("chunk upload failed; will retry", "job", ch.JobID, "seq", ch.Seq, "err", err)
			return
		}
		r.Log.Info("result chunk uploaded", "job", ch.JobID, "seq", ch.Seq, "hosts", ack.Hosts, "duplicate", ack.Duplicate)
		_ = r.Spool.Remove(ch)
	}
	for _, jobID := range r.Spool.Jobs() {
		if r.Spool.HasChunks(jobID) {
			continue
		}
		st, ok := r.Spool.Terminal(jobID)
		if !ok {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := cl.JobStatus(sctx, cpURL, jobID, *st)
		cancel()
		if err != nil && !cpclient.IsPermanent(err) {
			r.Log.Warn("terminal status not delivered; will retry", "job", jobID, "err", err)
			return
		}
		if err != nil {
			r.Log.Warn("terminal status rejected; dropping", "job", jobID, "err", err)
		}
		_ = r.Spool.ClearTerminal(jobID)
	}
}
