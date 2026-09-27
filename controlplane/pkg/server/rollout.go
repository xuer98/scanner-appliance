package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

// Staged rollout (PLAN §14): a published bundle or release goes to the
// canary group first; once the canary period has passed and at least one
// canary appliance confirmed it (or there are no canaries), it is released
// to everyone. A canary that reports an update error holds the rollout.
// Delivery is by update_bundle / update_daemon directives, one per
// appliance, re-queued at most every RequeueAfter until the appliance
// reports the version.

const (
	// DefaultCanaryPeriod before general release.
	DefaultCanaryPeriod = 48 * time.Hour
	// DefaultRequeueAfter is how long the rollout waits for an appliance to
	// report a version after its directive was acked before queueing again.
	DefaultRequeueAfter = time.Hour
)

// RunRollout evaluates rollouts every interval until ctx ends.
func (s *Server) RunRollout(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.rolloutTick(ctx); err != nil {
				s.log.Warn("rollout tick", "err", err)
			}
		}
	}
}

// RolloutTick is the exported form for tests and the CLI.
func (s *Server) RolloutTick(ctx context.Context) error { return s.rolloutTick(ctx) }

func (s *Server) rolloutTick(ctx context.Context) error {
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	fleet, err := s.cfg.Store.ListAppliances(ctx)
	if err != nil {
		return err
	}
	var enrolled []*store.Appliance
	for _, a := range fleet {
		if a.Status == v1.StatusEnrolled {
			enrolled = append(enrolled, a)
		}
	}
	var errs []error
	if err := s.rolloutBundles(ctx, enrolled); err != nil {
		errs = append(errs, err)
	}
	if err := s.rolloutReleases(ctx, enrolled); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// current picks the newest deliverable item (canary or released).
func (s *Server) rolloutBundles(ctx context.Context, fleet []*store.Appliance) error {
	list, err := s.cfg.Store.ListBundles(ctx)
	if err != nil {
		return err
	}
	var cur *store.Bundle
	for _, b := range list {
		if b.Status == v1.RolloutCanary || b.Status == v1.RolloutReleased {
			cur = b
			break
		}
	}
	if cur == nil {
		return nil
	}
	now := s.cfg.Now()
	if cur.Status == v1.RolloutCanary {
		if promote, why := s.canaryDone(fleet, cur.CanaryUntil, now, func(a *store.Appliance) bool { return a.BundleVersion == cur.Version }); promote {
			s.log.Info("bundle leaves canary", "version", cur.Version, "why", why)
			if err := s.cfg.Store.SetBundleStatus(ctx, cur.Version, v1.RolloutReleased, ""); err != nil {
				return err
			}
			cur.Status = v1.RolloutReleased
		}
	}
	payload := map[string]any{
		v1.PayloadURL: "/v1/bundles/" + cur.Version + "/manifest", v1.PayloadSHA256: cur.SHA256, v1.PayloadSig: cur.Sig,
		v1.PayloadVersion: cur.Version, v1.PayloadFeedVersion: cur.FeedVersion,
	}
	for _, a := range fleet {
		if cur.Status == v1.RolloutCanary && !a.Canary {
			continue
		}
		if a.BundleVersion == cur.Version || failedOn(a.UpdateError, "bundle", cur.Version) {
			continue
		}
		if err := s.queueUpdate(ctx, a, v1.DirectiveUpdateBundle, cur.Version, payload, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) rolloutReleases(ctx context.Context, fleet []*store.Appliance) error {
	list, err := s.cfg.Store.ListReleases(ctx)
	if err != nil {
		return err
	}
	// Newest deliverable release per component.
	cur := map[string]*store.Release{}
	for _, r := range list {
		if r.Status != v1.RolloutCanary && r.Status != v1.RolloutReleased {
			continue
		}
		if _, ok := cur[r.Component]; !ok {
			cur[r.Component] = r
		}
	}
	now := s.cfg.Now()
	for component, rel := range cur {
		var group []*store.Appliance
		for _, a := range fleet {
			if a.Fingerprint != nil && a.Fingerprint.Hypervisor == "container" {
				continue // container images are updated by pulling a new image
			}
			if a.OS != "" && a.Arch != "" && v1.ReleaseComponent(a.OS, a.Arch) == component {
				group = append(group, a)
			}
		}
		if rel.Status == v1.RolloutCanary {
			if promote, why := s.canaryDone(group, rel.CanaryUntil, now, func(a *store.Appliance) bool { return a.Version == rel.Version }); promote {
				s.log.Info("release leaves canary", "component", component, "version", rel.Version, "why", why)
				if err := s.cfg.Store.SetReleaseStatus(ctx, component, rel.Version, v1.RolloutReleased, ""); err != nil {
					return err
				}
				rel.Status = v1.RolloutReleased
			}
		}
		payload := map[string]any{
			v1.PayloadURL: "/v1/releases/" + component + "/" + rel.Version, v1.PayloadSHA256: rel.SHA256, v1.PayloadSig: rel.Sig,
			v1.PayloadVersion: rel.Version,
		}
		for _, a := range group {
			if rel.Status == v1.RolloutCanary && !a.Canary {
				continue
			}
			if a.Version == rel.Version || failedOn(a.UpdateError, "daemon", rel.Version) {
				continue
			}
			if err := s.queueUpdate(ctx, a, v1.DirectiveUpdateDaemon, rel.Version, payload, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// canaryDone reports whether a canary item may go to general release: the
// canary period has passed and, when canary appliances exist, at least one
// of them reports the version. A held item never gets here.
func (s *Server) canaryDone(group []*store.Appliance, until *time.Time, now time.Time, installed func(*store.Appliance) bool) (bool, string) {
	if until != nil && now.Before(*until) {
		return false, ""
	}
	canaries, confirmed := 0, 0
	for _, a := range group {
		if !a.Canary {
			continue
		}
		canaries++
		if installed(a) {
			confirmed++
		}
	}
	if canaries == 0 {
		return true, "canary period over, no canary appliances"
	}
	if confirmed == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("canary period over, %d/%d canary appliances confirmed", confirmed, canaries)
}

// failedOn reports whether the appliance's last update error concerns this
// item ("bundle <v>: ..." / "daemon <v>: ..."), in which case it is not
// re-queued automatically.
func failedOn(updateError, kind, version string) bool {
	return updateError != "" && strings.HasPrefix(updateError, kind+" "+version+":")
}

// queueUpdate creates the directive unless one for this version is still
// pending or was acked less than RequeueAfter ago.
func (s *Server) queueUpdate(ctx context.Context, a *store.Appliance, typ, version string, payload map[string]any, now time.Time) error {
	dirs, err := s.cfg.Store.ListDirectives(ctx, a.ID)
	if err != nil {
		return err
	}
	requeue := s.cfg.RequeueAfter
	if requeue <= 0 {
		requeue = DefaultRequeueAfter
	}
	for _, d := range dirs {
		if d.Type != typ {
			continue
		}
		if v, _ := d.Payload[v1.PayloadVersion].(string); v != version {
			continue
		}
		if d.AckedAt == nil || now.Sub(*d.AckedAt) < requeue {
			return nil
		}
	}
	if _, err := s.cfg.Store.CreateDirective(ctx, a.ID, typ, payload); err != nil {
		return err
	}
	s.log.Info("update queued", "appliance", a.ID, "type", typ, "version", version, "canary", a.Canary)
	return nil
}

// noteUpdateError holds a canary rollout when a canary appliance reports a
// failure for the item under canary (PLAN §14: feed deltas are held if the
// lab appliance's VT reload fails). Called from the heartbeat handler.
func (s *Server) noteUpdateError(ctx context.Context, a *store.Appliance, hb *v1.Heartbeat) {
	if hb.UpdateError == "" {
		return
	}
	s.log.Warn("appliance reports update error", "appliance", a.ID, "canary", a.Canary, "err", hb.UpdateError)
	if !a.Canary {
		return
	}
	kind, version, ok := parseUpdateError(hb.UpdateError)
	if !ok {
		return
	}
	reason := fmt.Sprintf("canary %s: %s", a.ID, hb.UpdateError)
	switch kind {
	case "bundle":
		if b, err := s.cfg.Store.GetBundle(ctx, version); err == nil && b.Status == v1.RolloutCanary {
			_ = s.cfg.Store.SetBundleStatus(ctx, version, v1.RolloutHeld, reason)
			s.log.Warn("bundle rollout held", "version", version, "reason", reason)
		}
	case "daemon":
		component := v1.ReleaseComponent(hb.OS, hb.Arch)
		if r, err := s.cfg.Store.GetRelease(ctx, component, version); err == nil && r.Status == v1.RolloutCanary {
			_ = s.cfg.Store.SetReleaseStatus(ctx, component, version, v1.RolloutHeld, reason)
			s.log.Warn("release rollout held", "component", component, "version", version, "reason", reason)
		}
	}
}

// parseUpdateError splits "bundle <version>: <detail>".
func parseUpdateError(e string) (kind, version string, ok bool) {
	kind, rest, found := strings.Cut(e, " ")
	if !found || (kind != "bundle" && kind != "daemon") {
		return "", "", false
	}
	version, _, found = strings.Cut(rest, ":")
	if !found || version == "" {
		return "", "", false
	}
	return kind, version, true
}
