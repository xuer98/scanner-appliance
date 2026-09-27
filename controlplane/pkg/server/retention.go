package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Retention (Phase 6, PLAN §23 item 3): raw result chunks are deleted
// from the object store after RawRetention (findings and hosts stay),
// support bundles after SupportRetention. One pass handles a bounded
// batch; the loop runs hourly under the cluster lock.

const (
	DefaultRawRetention     = 90 * 24 * time.Hour
	DefaultSupportRetention = 180 * 24 * time.Hour
	retentionBatch          = 500
)

// RunRetention runs retention passes every interval.
func (s *Server) RunRetention(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.withLock(ctx, "retention", func() error {
				_, err := s.RetentionTick(ctx, false)
				return err
			}); err != nil {
				s.log.Warn("retention tick", "err", err)
			}
		}
	}
}

// RetentionTick purges (or, dry run, counts) what is past retention.
func (s *Server) RetentionTick(ctx context.Context, dryRun bool) (v1.AdminRetentionResult, error) {
	now := s.cfg.Now()
	raw, sup := s.cfg.RawRetention, s.cfg.SupportRetention
	if raw <= 0 {
		raw = DefaultRawRetention
	}
	if sup <= 0 {
		sup = DefaultSupportRetention
	}
	res := v1.AdminRetentionResult{DryRun: dryRun, Before: now.Add(-raw)}
	batches, err := s.cfg.Store.ListResultBatches(ctx, res.Before, retentionBatch)
	if err != nil {
		return res, err
	}
	for _, b := range batches {
		if dryRun {
			res.RawBatches++
			continue
		}
		if err := s.cfg.Objects.Delete(ctx, b.ObjectKey); err != nil && !errors.Is(err, ErrObjectNotFound) {
			res.Errors++
			s.log.Warn("retention: delete object", "key", b.ObjectKey, "err", err)
			continue
		}
		if err := s.cfg.Store.MarkResultBatchPurged(ctx, b.JobID, b.Seq); err != nil {
			res.Errors++
			continue
		}
		res.RawBatches++
	}
	bundles, err := s.cfg.Store.ListSupportBundles(ctx, now.Add(-sup), retentionBatch)
	if err != nil {
		return res, err
	}
	for _, b := range bundles {
		if dryRun {
			res.SupportBundles++
			continue
		}
		if err := s.cfg.Objects.Delete(ctx, b.ObjectKey); err != nil && !errors.Is(err, ErrObjectNotFound) {
			res.Errors++
			continue
		}
		if err := s.cfg.Store.MarkSupportBundlePurged(ctx, b.ID); err != nil {
			res.Errors++
			continue
		}
		res.SupportBundles++
	}
	if !dryRun && (res.RawBatches > 0 || res.SupportBundles > 0) {
		s.log.Info("retention pass", "raw_batches", res.RawBatches, "support_bundles", res.SupportBundles, "errors", res.Errors)
	}
	return res, nil
}

func (s *Server) adminRetention(w http.ResponseWriter, r *http.Request) {
	dry := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	res, err := s.RetentionTick(r.Context(), dry)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// withLock runs fn while holding a cluster-wide named lock; when another
// control-plane instance holds it the tick is skipped.
func (s *Server) withLock(ctx context.Context, name string, fn func() error) error {
	release, ok, err := s.cfg.Store.TryLock(ctx, name)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer release()
	return fn()
}
