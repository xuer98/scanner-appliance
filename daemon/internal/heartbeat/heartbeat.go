// Package heartbeat runs the appliance's only control channel (PLAN §8, §9).
//
// The loop owns the daemon state machine:
//
//	Unenrolled → Enrolling → Idle ⇄ Scanning ⇄ (directives) → Wiped
//
// Nothing is inbound. Directives arrive in heartbeat responses and are
// acknowledged by ID in the next heartbeat. After every successful
// heartbeat the loop flushes spooled results and, when idle, polls for the
// next job (Phase 2, PLAN §11).
package heartbeat

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/cpclient"
	"github.com/tprm/scanner-appliance/daemon/internal/enroll"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/netcfg"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

const (
	StateUnenrolled = "unenrolled"
	StateEnrolling  = "enrolling"
	StateIdle       = "idle"
	StateScanning   = "scanning"
	StateRevoked    = "revoked"
	StateWiped      = "wiped"

	maxSkew        = 5 * time.Second
	enrollRetryMin = 15 * time.Second
	enrollRetryMax = 5 * time.Minute
	failureBackoff = 4 // multiply interval by up to this on consecutive failures
	unenrolledPoll = 3 * time.Second
)

// MinInterval floors any configured interval; tests lower it.
var MinInterval = 10 * time.Second

// Loop is the heartbeat runner.
type Loop struct {
	Store   *state.Store
	Roots   *x509.CertPool
	Version string
	Log     *slog.Logger
	// PowerOff is invoked after a wipe; overridable in tests.
	PowerOff func() error
	// Now is overridable in tests.
	Now func() time.Time
	// OSPSocket is the ospd-openvas socket probed for engine health.
	OSPSocket string
	// Jobs runs scans; nil disables job polling (Phase 1 behaviour).
	Jobs *jobs.Runner

	client    *cpclient.Client
	clientKey string // proxy + cert mtime; rebuild when it changes
	acks      []string
	failures  int
	skew      int64
	lastHB    *time.Time
	lastErr   string
	reachable bool
	stateName string
	engine    v1.EngineHealth
	pollNow   bool
}

func (l *Loop) init() {
	if l.Log == nil {
		l.Log = slog.Default()
	}
	if l.Now == nil {
		l.Now = time.Now
	}
	if l.PowerOff == nil {
		l.PowerOff = func() error { return exec.Command("systemctl", "poweroff").Run() }
	}
}

// Run blocks until ctx is done.
func (l *Loop) Run(ctx context.Context) {
	l.init()
	for {
		st, err := l.Store.Load()
		if err != nil {
			l.Log.Error("state unreadable", "err", err)
			l.stateName = StateUnenrolled
			l.lastErr = err.Error()
			l.publish(st)
			if !sleep(ctx, unenrolledPoll) {
				return
			}
			continue
		}
		if st.ApplianceID == "" || !l.Store.Enrolled() {
			if !l.unenrolledTick(ctx, st) {
				return
			}
			continue
		}
		l.stateName = StateIdle
		if l.Jobs != nil && !l.Jobs.Idle() {
			l.stateName = StateScanning
		}
		wait := l.tick(ctx, st)
		if !sleep(ctx, wait) {
			return
		}
	}
}

// unenrolledTick tries the pending seed code (if any) with backoff, else waits for the console.
func (l *Loop) unenrolledTick(ctx context.Context, st *state.State) bool {
	l.stateName = StateUnenrolled
	if st.PendingCode == "" {
		l.publish(st)
		return sleep(ctx, unenrolledPoll)
	}
	l.stateName = StateEnrolling
	l.publish(st)
	l.Log.Info("enrolling with seed code", "url", st.EnrollURL)
	_, err := enroll.Enroll(ctx, l.Store, enroll.Options{EnrollURL: st.EnrollURL, Code: st.PendingCode, Proxy: st.Proxy, Version: l.Version, Roots: l.Roots})
	if err == nil {
		l.Log.Info("enrolled")
		l.failures = 0
		l.lastErr = ""
		l.reachable = true
		return true
	}
	l.lastErr = err.Error()
	l.Log.Warn("enrollment failed", "err", err)
	if cpclient.IsAuthError(err) {
		// Bad, used, or expired code: stop burning attempts (3 wrong → locked server-side).
		st.PendingCode = ""
		st.SeedConsumed = true
		_ = l.Store.Save(st)
		l.Log.Warn("seed code rejected; waiting for a code from the console")
		l.publish(st)
		return sleep(ctx, unenrolledPoll)
	}
	l.failures++
	l.publish(st)
	return sleep(ctx, backoff(enrollRetryMin, enrollRetryMax, l.failures))
}

func (l *Loop) interval(st *state.State) time.Duration {
	s := st.PollIntervalS
	if st.IntervalOverrideS > 0 {
		s = st.IntervalOverrideS
	}
	d := time.Duration(s) * time.Second
	if d < MinInterval {
		d = 60 * time.Second
	}
	return d
}

// tick sends one heartbeat and returns how long to wait before the next.
func (l *Loop) tick(ctx context.Context, st *state.State) time.Duration {
	base := l.interval(st)
	if err := l.ensureClient(st); err != nil {
		l.lastErr = err.Error()
		l.Log.Error("client", "err", err)
		l.publish(st)
		return base
	}
	if err := l.maybeRenew(ctx, st); err != nil {
		l.Log.Warn("renewal failed", "err", err)
	}
	hb := l.build(st)
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	resp, err := l.client.Heartbeat(cctx, st.CPURL, st.ApplianceID, hb)
	cancel()
	if err != nil {
		l.failures++
		l.reachable = false
		l.lastErr = err.Error()
		l.Log.Warn("heartbeat failed", "err", err, "failures", l.failures)
		if cpclient.IsAuthError(err) {
			l.stateName = StateRevoked
			l.publish(st)
			return 10 * time.Minute
		}
		l.publish(st)
		return jitter(backoff(base, base*failureBackoff, l.failures))
	}
	now := l.Now()
	l.lastHB = &now
	l.failures = 0
	l.reachable = true
	l.lastErr = ""
	l.acks = nil
	l.skew = resp.ServerEpoch - now.Unix()
	if d := time.Duration(l.skew) * time.Second; d > maxSkew || d < -maxSkew {
		l.Log.Warn("clock skew; stepping clock", "skew_s", l.skew)
		if err := setClock(time.Unix(resp.ServerEpoch, 0)); err != nil {
			l.Log.Warn("clock step failed", "err", err)
		}
	}
	for _, d := range resp.Directives {
		if l.apply(ctx, st, d) {
			l.acks = append(l.acks, d.ID)
		}
	}
	// apply() may have changed state (interval, stop_all); reload for the wait.
	if fresh, err := l.Store.Load(); err == nil {
		st = fresh
	}
	if l.stateName == StateWiped {
		l.publish(st)
		return time.Hour
	}
	if l.Jobs != nil {
		l.Jobs.Flush(ctx)
		if !st.StopAll && (l.Jobs.Idle() || l.pollNow) {
			l.pollNow = false
			l.Jobs.Poll(ctx, l.client, st, hb.Engine)
		}
		if l.Jobs.Idle() {
			l.stateName = StateIdle
		} else {
			l.stateName = StateScanning
		}
	}
	l.publish(st)
	return jitter(l.interval(st))
}

func (l *Loop) ensureClient(st *state.State) error {
	certPath := filepath.Join(l.Store.Dir, "cert.pem")
	key := st.Proxy
	if fi, err := os.Stat(certPath); err == nil {
		key += "|" + fi.ModTime().String()
	}
	if l.client != nil && key == l.clientKey {
		return nil
	}
	cert, err := l.Store.Certificate()
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	cl, err := cpclient.New(cpclient.Options{Roots: l.Roots, ClientCert: cert, Proxy: st.Proxy})
	if err != nil {
		return err
	}
	l.client, l.clientKey = cl, key
	return nil
}

func (l *Loop) maybeRenew(ctx context.Context, st *state.State) error {
	cert, err := l.Store.Certificate()
	if err != nil || !enroll.NeedsRenewal(cert.Leaf, l.Now()) {
		return err
	}
	l.Log.Info("certificate past 2/3 lifetime; renewing")
	if err := enroll.Renew(ctx, l.Store, l.Roots, l.Version); err != nil {
		return err
	}
	l.client = nil // force rebuild with the new cert
	return nil
}

func (l *Loop) build(st *state.State) v1.Heartbeat {
	pctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	engine := osp.New(l.OSPSocket).Health(pctx)
	cancel()
	l.engine = engine
	hb := v1.Heartbeat{
		Engine:  engine,
		Version: l.Version, BundleVersion: st.BundleVersion, FeedVersion: engine.FeedVersion,
		UptimeS: uptimeSeconds(), Load1: load1(), DiskFreeMB: diskFreeMB(l.Store.Dir), MemFreeMB: memFreeMB(),
		Ifaces: netcfg.Interfaces(), BinarySHA256: binaryHashes(),
		ClockEpoch: l.Now().Unix(), AckedDirectiveIDs: l.acks, State: l.stateName, SkewS: l.skew, StopAll: st.StopAll,
	}
	if l.Jobs != nil {
		hb.CurrentJob = l.Jobs.Progress()
		hb.PendingResults = l.Jobs.Pending()
		if hb.CurrentJob != nil {
			hb.State = StateScanning
		}
	}
	if hb.AckedDirectiveIDs == nil {
		hb.AckedDirectiveIDs = []string{}
	}
	if hb.Ifaces == nil {
		hb.Ifaces = []v1.Iface{}
	}
	return hb
}

// apply executes one directive; returns whether to ack it.
func (l *Loop) apply(ctx context.Context, st *state.State, d v1.Directive) bool {
	log := l.Log.With("directive", d.ID, "type", d.Type)
	switch d.Type {
	case v1.DirectiveNoop:
		log.Info("noop")
		return true
	case v1.DirectiveSetInterval:
		s, _ := d.Payload["s"].(float64)
		if s < 10 || s > 3600 {
			log.Warn("set_interval out of range; ignoring", "s", s)
			return true
		}
		st.IntervalOverrideS = int(s)
		if err := l.Store.Save(st); err != nil {
			log.Error("save", "err", err)
			return false
		}
		log.Info("interval set", "s", int(s))
		return true
	case v1.DirectiveStopAll:
		clear, _ := d.Payload["clear"].(bool)
		st.StopAll = !clear
		if err := l.Store.Save(st); err != nil {
			log.Error("save", "err", err)
			return false
		}
		if clear {
			log.Info("stop_all cleared")
		} else {
			log.Warn("stop_all active: no jobs will run until cleared")
			if l.Jobs != nil {
				l.Jobs.StopAll("stop_all directive " + d.ID)
			}
		}
		return true
	case v1.DirectiveRunJobNow:
		if l.Jobs == nil {
			log.Warn("run_job_now: no job runner in this build")
			return true
		}
		jobID, _ := d.Payload["job_id"].(string)
		log.Info("run_job_now: polling immediately", "job_id", jobID)
		l.pollNow = true
		return true
	case v1.DirectiveRenewCert:
		if err := enroll.Renew(ctx, l.Store, l.Roots, l.Version); err != nil {
			log.Warn("renew failed; will retry on next delivery", "err", err)
			return false
		}
		l.client = nil
		log.Info("certificate renewed on request")
		return true
	case v1.DirectiveWipe:
		tok, _ := d.Payload["confirm_token"].(string)
		if tok != st.ApplianceID {
			log.Warn("wipe refused: confirm_token must equal appliance id")
			return true
		}
		l.wipe(ctx, st, "directive "+d.ID)
		return true
	case v1.DirectiveUpdateDaemon, v1.DirectiveUpdateBundle:
		log.Warn("directive not supported by this version; acknowledging without effect")
		l.lastErr = "unsupported directive " + d.Type
		return true
	default:
		log.Warn("unknown directive type; acknowledging without effect")
		return true
	}
}

// wipe implements PLAN §6/§9: tell the control plane, shred state, power off.
func (l *Loop) wipe(ctx context.Context, st *state.State, reason string) {
	l.Log.Warn("WIPE", "reason", reason)
	if l.Jobs != nil {
		l.Jobs.StopAll("wipe")
		l.Jobs.Wait()
	}
	if l.client != nil && st.ApplianceID != "" {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := l.client.Wipe(cctx, st.CPURL, st.ApplianceID, reason); err != nil {
			l.Log.Warn("could not report wipe to control plane", "err", err)
		}
		cancel()
	}
	if err := l.Store.Wipe(); err != nil {
		l.Log.Error("wipe incomplete", "err", err)
	}
	l.stateName = StateWiped
	l.client = nil
	l.publish(&state.State{})
	if err := l.PowerOff(); err != nil {
		l.Log.Error("poweroff", "err", err)
	}
}

// Wipe is the console entry point; it goes through the same path.
func Wipe(ctx context.Context, st *state.Store, roots *x509.CertPool, version, reason string, powerOff func() error) {
	l := &Loop{Store: st, Roots: roots, Version: version, PowerOff: powerOff}
	l.init()
	s, err := st.Load()
	if err != nil {
		s = &state.State{}
	}
	_ = l.ensureClient(s)
	l.wipe(ctx, s, reason)
}

func (l *Loop) publish(st *state.State) {
	if st == nil {
		st = &state.State{}
	}
	s := &state.Status{
		Version: l.Version, BundleVersion: st.BundleVersion, State: l.stateName, ApplianceID: st.ApplianceID,
		CPURL: st.CPURL, Reachable: l.reachable, LastError: l.lastErr, LastHeartbeat: l.lastHB, SkewS: l.skew,
		IntervalS: int(l.interval(st) / time.Second), Ifaces: netcfg.Interfaces(), StopAll: st.StopAll, CertNotAfter: st.CertNotAfter,
		Engine: l.engine, FeedVersion: l.engine.FeedVersion,
	}
	if l.Jobs != nil {
		s.CurrentJob = l.Jobs.Progress()
		s.PendingResults = l.Jobs.Pending()
	}
	if s.CPURL == "" {
		s.CPURL = st.EnrollURL
	}
	if err := l.Store.WriteStatus(s); err != nil {
		l.Log.Debug("status write", "err", err)
	}
}

func backoff(min, max time.Duration, failures int) time.Duration {
	d := min
	for i := 1; i < failures && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// jitter spreads ±10% so a fleet doesn't synchronize.
func jitter(d time.Duration) time.Duration {
	f := 0.9 + rand.Float64()*0.2
	return time.Duration(float64(d) * f)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
