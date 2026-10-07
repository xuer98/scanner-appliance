package heartbeat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/netcfg"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/update"
)

// Phase 3 control-channel work (PLAN §13, §14): update_bundle,
// update_daemon and reload_vts run in the background so heartbeats keep
// flowing; the loop persists their outcome when it drains results at the
// start of the next tick. While one runs no job is started, and none is
// started while a job runs.

// StateUpdating is reported while a bundle or daemon update is in progress.
const StateUpdating = "updating"

// MaintenanceHour is the site-local hour (MaintenanceHour:00-59) in which an
// idle appliance reboots when the OS asks for it after unattended-upgrades.
var MaintenanceHour = 3

type updateResult struct {
	kind    string // bundle | daemon | reload_vts
	version string
	bundle  string // installed bundle version on success
	err     error
}

// startupUpdate handles a staged self-update when the daemon starts.
func (l *Loop) startupUpdate() {
	if l.Update == nil {
		return
	}
	await, report := l.Update.Startup()
	if report != "" {
		l.Log.Error("self-update did not stick", "report", report)
		if st, err := l.Store.Load(); err == nil {
			st.LastUpdateError = report
			_ = l.Store.Save(st)
		}
	}
	if await {
		l.awaitConfirm = true
		l.confirmDeadline = l.Now().Add(update.ConfirmWindow)
	}
}

// confirmOverdue rolls the daemon back when the new binary never managed
// a heartbeat; returns true when the loop must stop for a restart.
func (l *Loop) confirmOverdue() bool {
	if !l.awaitConfirm || l.Now().Before(l.confirmDeadline) {
		return false
	}
	l.awaitConfirm = false
	err := l.Update.Rollback(fmt.Sprintf("no successful heartbeat within %s", update.ConfirmWindow))
	if errors.Is(err, update.ErrRestartRequired) {
		l.requestRestart()
		return true
	}
	l.Log.Error("rollback failed", "err", err)
	return false
}

// startUpdate launches one task; false means "not now, redeliver".
func (l *Loop) startUpdate(ctx context.Context, kind, version string, st *state.State, task func(ctx context.Context) updateResult) bool {
	if l.Update == nil {
		l.Log.Warn("directive not supported by this build; acknowledging without effect", "type", kind)
		l.lastErr = "unsupported directive " + kind
		return true
	}
	if l.busy != "" {
		l.Log.Info("deferring directive: another update is running", "type", kind, "running", l.busy)
		return false
	}
	if l.Jobs != nil && !l.Jobs.Idle() {
		l.Log.Info("deferring directive until the running job finishes", "type", kind)
		return false
	}
	cl, cpURL := l.client, st.CPURL
	l.Update.Fetch = update.FetchFunc(func(ctx context.Context, path string, w io.Writer, max int64) (http.Header, int64, error) {
		if cl == nil {
			return nil, 0, errors.New("no control-plane client")
		}
		return cl.Download(ctx, cpURL, path, w, max)
	})
	l.busy = kind + " " + version
	l.Log.Info("update started", "type", kind, "version", version)
	go func() {
		l.results <- task(ctx)
		select {
		case l.wake <- struct{}{}:
		default: // a wake-up is already pending
		}
	}()
	return true
}

// drainUpdates folds finished tasks into the state; true when it changed.
func (l *Loop) drainUpdates(st *state.State) bool {
	changed := false
	for {
		select {
		case r := <-l.results:
			l.busy = ""
			switch {
			case r.err == nil:
				if r.kind == "bundle" && r.bundle != "" && st.BundleVersion != r.bundle {
					st.BundleVersion = r.bundle
					changed = true
				}
				if st.LastUpdateError != "" {
					st.LastUpdateError = ""
					changed = true
				}
				l.Log.Info("update finished", "type", r.kind, "version", r.version)
			case errors.Is(r.err, update.ErrRestartRequired):
				l.Log.Warn("new daemon installed; restarting", "version", r.version)
				l.requestRestart()
			case errors.Is(r.err, update.ErrNotApplicable):
				l.Log.Warn(r.err.Error(), "version", r.version)
				l.lastErr = r.err.Error()
			default:
				l.Log.Error("update failed", "type", r.kind, "version", r.version, "err", r.err)
				if st.LastUpdateError != r.err.Error() {
					st.LastUpdateError = r.err.Error()
					changed = true
				}
			}
		default:
			return changed
		}
	}
}

func (l *Loop) applyUpdateBundle(ctx context.Context, st *state.State, d v1.Directive) bool {
	p, err := update.PayloadFrom(d.Payload)
	if err != nil {
		l.Log.Warn("update_bundle: bad payload; acknowledging without effect", "directive", d.ID, "err", err)
		l.lastErr = "update_bundle: " + err.Error()
		return true
	}
	return l.startUpdate(ctx, "bundle", p.Version, st, func(ctx context.Context) updateResult {
		mf, err := l.Update.ApplyBundle(ctx, p)
		r := updateResult{kind: "bundle", version: p.Version, err: err}
		if mf != nil {
			r.bundle = mf.Version
		}
		return r
	})
}

func (l *Loop) applyUpdateDaemon(ctx context.Context, st *state.State, d v1.Directive) bool {
	p, err := update.PayloadFrom(d.Payload)
	if err != nil {
		l.Log.Warn("update_daemon: bad payload; acknowledging without effect", "directive", d.ID, "err", err)
		l.lastErr = "update_daemon: " + err.Error()
		return true
	}
	return l.startUpdate(ctx, "daemon", p.Version, st, func(ctx context.Context) updateResult {
		return updateResult{kind: "daemon", version: p.Version, err: l.Update.ApplyDaemon(ctx, p)}
	})
}

func (l *Loop) applyReloadVTs(ctx context.Context, st *state.State, d v1.Directive) bool {
	want, _ := d.Payload[v1.PayloadFeedVersion].(string)
	return l.startUpdate(ctx, "reload_vts", want, st, func(ctx context.Context) updateResult {
		err := l.Update.ReloadVTs(ctx, want)
		if err != nil {
			// Framed as a bundle failure so a canary holds the rollout (PLAN §14).
			err = fmt.Errorf("bundle %s: reload_vts: %w", l.Update.InstalledVersion(), err)
		}
		return updateResult{kind: "reload_vts", version: want, err: err}
	})
}

// requestRestart makes Run return; main exits 0 and the supervisor
// (systemd Restart=always) starts the binary now in place.
func (l *Loop) requestRestart() {
	if !l.restart {
		l.restart = true
		close(l.stop)
	}
}

// RestartRequested reports whether Run returned to hand over to a new binary.
func (l *Loop) RestartRequested() bool { return l.restart }

// wait sleeps unless the context ends, a restart is requested or an update
// finishes. The last one starts the next beat early.
func (l *Loop) wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-l.stop:
		return false
	case <-l.wake:
		return true
	case <-t.C:
		return true
	}
}

// applyRoutes writes the site's LAN routes into lan0's networkd unit when
// they change (PLAN §15).
func (l *Loop) applyRoutes(ctx context.Context, st *state.State) {
	key := fmt.Sprint(st.Site.LANRoutes)
	if key == l.routesKey || (len(st.Site.LANRoutes) == 0 && l.routesKey == "") {
		return
	}
	if err := netcfg.Apply(ctx, st.Network, st.Site.LANRoutes...); err != nil {
		l.Log.Warn("lan routes not applied", "err", err)
	} else {
		l.Log.Info("lan routes applied", "routes", len(st.Site.LANRoutes))
	}
	l.routesKey = key
}

// maybeReboot reboots an idle appliance in the maintenance slot when
// unattended-upgrades asked for it (PLAN §14: reboot in maintenance window).
func (l *Loop) maybeReboot(st *state.State) {
	if !rebootRequired() || l.busy != "" || (l.Jobs != nil && !l.Jobs.Idle()) {
		return
	}
	loc := time.UTC
	if st.Site.TZ != "" {
		if z, err := time.LoadLocation(st.Site.TZ); err == nil {
			loc = z
		}
	}
	if l.Now().In(loc).Hour() != MaintenanceHour {
		return
	}
	l.Log.Warn("OS updates request a reboot; rebooting in the maintenance slot", "hour", MaintenanceHour, "tz", loc)
	if err := l.Reboot(); err != nil {
		l.Log.Error("reboot", "err", err)
	}
}
