package store

import (
	"context"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func (p *Postgres) ResolveFindings(ctx context.Context, siteID, jobID string, scopes []string, before, at time.Time) ([]*Finding, error) {
	set := resolveScopes(scopes)
	list := make([]string, 0, len(set))
	for s := range set {
		list = append(list, s)
	}
	// Hosts the job observed, minus those the fragile-device policy kept
	// away from detection (their findings were never tested).
	return loadFindings(ctx, p.pool, `UPDATE finding f SET status=$5, fixed_at=$6
		FROM job_host jh JOIN host h ON h.id=jh.host_id
		WHERE jh.job_id=$1 AND h.site_id=$2 AND f.host_id=h.id
		  AND (f.status='' OR f.status=$7) AND f.source IN ('openvas','nuclei') AND f.scope = ANY($3::text[]) AND f.last_seen < $4
		  AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(h.notes) AS n(v) WHERE n.v LIKE 'fragile:%' AND n.v NOT LIKE 'fragile:cleared:%')
		RETURNING f.`+findingColsPrefixed("f."), jobID, siteID, list, before, v1.FindingFixed, at, v1.FindingOpen)
}

func (p *Postgres) IngestExternal(ctx context.Context, siteID, scanner string, hosts []v1.ExternalHost, at time.Time) (IngestSummary, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return IngestSummary{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	ix, err := p.loadSiteIndex(ctx, tx, siteID)
	if err != nil {
		return IngestSummary{}, err
	}
	sum := ix.ingestExternal(scanner, hosts, at)
	if err := p.commitIndex(ctx, tx, ix); err != nil {
		return IngestSummary{}, err
	}
	return sum, tx.Commit(ctx)
}

func (p *Postgres) ListResultBatches(ctx context.Context, before time.Time, limit int) ([]ResultBatchRec, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := p.pool.Query(ctx, `SELECT job_id, seq, received_at, object_key, sha256, final, hosts, purged FROM result_batch
		WHERE NOT purged AND received_at < $1 ORDER BY received_at, job_id, seq LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultBatchRec
	for rows.Next() {
		var r ResultBatchRec
		if err := rows.Scan(&r.JobID, &r.Seq, &r.ReceivedAt, &r.ObjectKey, &r.SHA256, &r.Final, &r.Hosts, &r.Purged); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) MarkResultBatchPurged(ctx context.Context, jobID string, seq int) error {
	return execOne(p.pool.Exec(ctx, `UPDATE result_batch SET purged=true WHERE job_id=$1 AND seq=$2`, jobID, seq))
}

func (p *Postgres) ListSupportBundles(ctx context.Context, before time.Time, limit int) ([]SupportBundleRec, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := p.pool.Query(ctx, `SELECT id, appliance_id, at, object_key, bytes, purged FROM support_bundle WHERE NOT purged AND at < $1 ORDER BY at, id LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SupportBundleRec
	for rows.Next() {
		var r SupportBundleRec
		if err := rows.Scan(&r.ID, &r.ApplianceID, &r.At, &r.ObjectKey, &r.Bytes, &r.Purged); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) MarkSupportBundlePurged(ctx context.Context, id int64) error {
	return execOne(p.pool.Exec(ctx, `UPDATE support_bundle SET purged=true WHERE id=$1`, id))
}

// TryLock holds a session-level advisory lock on a dedicated connection
// until release runs, so exactly one control-plane instance runs each
// background loop's tick.
func (p *Postgres) TryLock(ctx context.Context, name string) (func(), bool, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, name).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(rctx, `SELECT pg_advisory_unlock(hashtext($1))`, name)
		conn.Release()
	}, true, nil
}
