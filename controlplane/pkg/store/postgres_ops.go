package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const bundleCols = `version, feed_version, object_key, sha256, sig, files, bytes, status, held_reason, published_at, canary_until, confirmed_at, content_sha256`

func scanBundle(row pgx.Row) (*Bundle, error) {
	b := &Bundle{}
	err := row.Scan(&b.Version, &b.FeedVersion, &b.ObjectKey, &b.SHA256, &b.Sig, &b.Files, &b.Bytes, &b.Status, &b.HeldReason, &b.PublishedAt, &b.CanaryUntil, &b.ConfirmedAt, &b.Content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (p *Postgres) PutBundle(ctx context.Context, b *Bundle) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO bundle(version, feed_version, object_key, sha256, sig, files, bytes, status, held_reason, published_at, canary_until, confirmed_at, content_sha256)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT(version) DO UPDATE SET feed_version=EXCLUDED.feed_version, object_key=EXCLUDED.object_key, sha256=EXCLUDED.sha256,
		  sig=EXCLUDED.sig, files=EXCLUDED.files, bytes=EXCLUDED.bytes, status=EXCLUDED.status, held_reason=EXCLUDED.held_reason,
		  published_at=EXCLUDED.published_at, canary_until=EXCLUDED.canary_until, confirmed_at=EXCLUDED.confirmed_at,
		  content_sha256=EXCLUDED.content_sha256`,
		b.Version, b.FeedVersion, b.ObjectKey, b.SHA256, b.Sig, b.Files, b.Bytes, b.Status, b.HeldReason, b.PublishedAt, b.CanaryUntil, b.ConfirmedAt, b.Content)
	return err
}

func (p *Postgres) GetBundle(ctx context.Context, version string) (*Bundle, error) {
	return scanBundle(p.pool.QueryRow(ctx, `SELECT `+bundleCols+` FROM bundle WHERE version=$1`, version))
}

func (p *Postgres) ListBundles(ctx context.Context) ([]*Bundle, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+bundleCols+` FROM bundle ORDER BY published_at DESC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Bundle
	for rows.Next() {
		b, err := scanBundle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *Postgres) SetBundleStatus(ctx context.Context, version, status, reason string) error {
	return execOne(p.pool.Exec(ctx, `UPDATE bundle SET status=$2, held_reason=$3 WHERE version=$1`, version, status, reason))
}

func (p *Postgres) ConfirmBundle(ctx context.Context, version string, at time.Time) error {
	return execOne(p.pool.Exec(ctx, `UPDATE bundle SET confirmed_at=COALESCE(confirmed_at, $2) WHERE version=$1`, version, at))
}

func (p *Postgres) PutBundleFiles(ctx context.Context, files []BundleFileRec) error {
	if len(files) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, f := range files {
		batch.Queue(`INSERT INTO bundle_file(sha256, size, object_key) VALUES($1,$2,$3) ON CONFLICT(sha256) DO UPDATE SET size=EXCLUDED.size, object_key=EXCLUDED.object_key`,
			f.SHA256, f.Size, f.ObjectKey)
	}
	br := p.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range files {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) HasBundleFiles(ctx context.Context, sha256 []string) (map[string]bool, error) {
	out := make(map[string]bool, len(sha256))
	if len(sha256) == 0 {
		return out, nil
	}
	rows, err := p.pool.Query(ctx, `SELECT sha256 FROM bundle_file WHERE sha256 = ANY($1)`, sha256)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for _, s := range sha256 {
		out[s] = false
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out[s] = true
	}
	return out, rows.Err()
}

const releaseCols = `component, version, object_key, sha256, sig, bytes, status, held_reason, published_at, canary_until`

func scanRelease(row pgx.Row) (*Release, error) {
	r := &Release{}
	err := row.Scan(&r.Component, &r.Version, &r.ObjectKey, &r.SHA256, &r.Sig, &r.Bytes, &r.Status, &r.HeldReason, &r.PublishedAt, &r.CanaryUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (p *Postgres) PutRelease(ctx context.Context, r *Release) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO release(component, version, object_key, sha256, sig, bytes, status, held_reason, published_at, canary_until)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(component, version) DO UPDATE SET object_key=EXCLUDED.object_key, sha256=EXCLUDED.sha256, sig=EXCLUDED.sig, bytes=EXCLUDED.bytes,
		  status=EXCLUDED.status, held_reason=EXCLUDED.held_reason, published_at=EXCLUDED.published_at, canary_until=EXCLUDED.canary_until`,
		r.Component, r.Version, r.ObjectKey, r.SHA256, r.Sig, r.Bytes, r.Status, r.HeldReason, r.PublishedAt, r.CanaryUntil)
	return err
}

func (p *Postgres) GetRelease(ctx context.Context, component, version string) (*Release, error) {
	return scanRelease(p.pool.QueryRow(ctx, `SELECT `+releaseCols+` FROM release WHERE component=$1 AND version=$2`, component, version))
}

func (p *Postgres) ListReleases(ctx context.Context) ([]*Release, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+releaseCols+` FROM release ORDER BY published_at DESC, component DESC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Release
	for rows.Next() {
		r, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) SetReleaseStatus(ctx context.Context, component, version, status, reason string) error {
	return execOne(p.pool.Exec(ctx, `UPDATE release SET status=$3, held_reason=$4 WHERE component=$1 AND version=$2`, component, version, status, reason))
}

func (p *Postgres) SetApplianceCanary(ctx context.Context, id string, canary bool) error {
	return execOne(p.pool.Exec(ctx, `UPDATE appliance SET canary=$2 WHERE id=$1`, id, canary))
}
