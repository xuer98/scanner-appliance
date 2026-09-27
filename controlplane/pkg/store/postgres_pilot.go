package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func (p *Postgres) RecordSiteChange(ctx context.Context, c *SiteChange) error {
	if c.ID == "" {
		c.ID = NewID("chg")
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO site_change(id, site_id, version, at, actor, kind, field, old_value, new_value, reason)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.ID, c.SiteID, c.Version, c.At, c.Actor, c.Kind, c.Field, c.Old, c.New, c.Reason)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) ListSiteChanges(ctx context.Context, siteID string) ([]*SiteChange, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, site_id, version, at, actor, kind, field, old_value, new_value, reason FROM site_change WHERE site_id=$1 ORDER BY at DESC, id DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SiteChange
	for rows.Next() {
		c := &SiteChange{}
		if err := rows.Scan(&c.ID, &c.SiteID, &c.Version, &c.At, &c.Actor, &c.Kind, &c.Field, &c.Old, &c.New, &c.Reason); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const scopeCols = `id, site_id, status, allowed_cidrs, reason, requested_at, requested_by, decided_at, decided_by, decision`

func scanScope(row pgx.Row) (*ScopeRequest, error) {
	r := &ScopeRequest{}
	err := row.Scan(&r.ID, &r.SiteID, &r.Status, &r.AllowedCIDRs, &r.Reason, &r.RequestedAt, &r.RequestedBy, &r.DecidedAt, &r.DecidedBy, &r.Decision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if r.AllowedCIDRs == nil {
		r.AllowedCIDRs = []string{}
	}
	return r, err
}

func (p *Postgres) CreateScopeRequest(ctx context.Context, r *ScopeRequest) error {
	if r.ID == "" {
		r.ID = NewID("scr")
	}
	cidrs := r.AllowedCIDRs
	if cidrs == nil {
		cidrs = []string{}
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO scope_request(`+scopeCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		r.ID, r.SiteID, r.Status, cidrs, r.Reason, r.RequestedAt, r.RequestedBy, r.DecidedAt, r.DecidedBy, r.Decision)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetScopeRequest(ctx context.Context, id string) (*ScopeRequest, error) {
	return scanScope(p.pool.QueryRow(ctx, `SELECT `+scopeCols+` FROM scope_request WHERE id=$1`, id))
}

func (p *Postgres) ListScopeRequests(ctx context.Context, siteID, status string) ([]*ScopeRequest, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+scopeCols+` FROM scope_request WHERE ($1='' OR site_id=$1) AND ($2='' OR status=$2) ORDER BY requested_at DESC`, siteID, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScopeRequest
	for rows.Next() {
		r, err := scanScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateScopeRequest(ctx context.Context, r *ScopeRequest) error {
	cidrs := r.AllowedCIDRs
	if cidrs == nil {
		cidrs = []string{}
	}
	return execOne(p.pool.Exec(ctx, `UPDATE scope_request SET status=$2, allowed_cidrs=$3, reason=$4, decided_at=$5, decided_by=$6, decision=$7 WHERE id=$1`,
		r.ID, r.Status, cidrs, r.Reason, r.DecidedAt, r.DecidedBy, r.Decision))
}

const scheduleCols = `id, site_id, appliance_id, name, mode, targets, excludes, ports, cron, tz, max_duration_s, enabled, next_occurrence, next_job_id, last_job_id, created_at, modules`

func scanSchedule(row pgx.Row) (*Schedule, error) {
	s := &Schedule{}
	err := row.Scan(&s.ID, &s.SiteID, &s.ApplianceID, &s.Name, &s.Mode, &s.Targets, &s.Excludes, &s.Ports, &s.Cron, &s.TZ, &s.MaxDurationS, &s.Enabled,
		&s.NextOccurrence, &s.NextJobID, &s.LastJobID, &s.CreatedAt, &s.Modules)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if s.Targets == nil {
		s.Targets = []string{}
	}
	if s.Excludes == nil {
		s.Excludes = []string{}
	}
	if len(s.Modules) == 0 {
		s.Modules = nil
	}
	return s, err
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (p *Postgres) CreateSchedule(ctx context.Context, sc *Schedule) error {
	if sc.ID == "" {
		sc.ID = NewID("sch")
	}
	if sc.CreatedAt.IsZero() {
		sc.CreatedAt = time.Now()
	}
	targets, excl := sc.Targets, sc.Excludes
	if targets == nil {
		targets = []string{}
	}
	if excl == nil {
		excl = []string{}
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO schedule(`+scheduleCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		sc.ID, sc.SiteID, sc.ApplianceID, sc.Name, sc.Mode, targets, excl, sc.Ports, sc.Cron, sc.TZ, sc.MaxDurationS, sc.Enabled, sc.NextOccurrence, sc.NextJobID, sc.LastJobID, sc.CreatedAt, orEmpty(sc.Modules))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetSchedule(ctx context.Context, id string) (*Schedule, error) {
	return scanSchedule(p.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM schedule WHERE id=$1`, id))
}

func (p *Postgres) ListSchedules(ctx context.Context, siteID string) ([]*Schedule, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+scheduleCols+` FROM schedule WHERE ($1='' OR site_id=$1) ORDER BY created_at, id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateSchedule(ctx context.Context, sc *Schedule) error {
	targets, excl := sc.Targets, sc.Excludes
	if targets == nil {
		targets = []string{}
	}
	if excl == nil {
		excl = []string{}
	}
	return execOne(p.pool.Exec(ctx, `UPDATE schedule SET name=$2, mode=$3, targets=$4, excludes=$5, ports=$6, cron=$7, tz=$8, max_duration_s=$9, enabled=$10,
		next_occurrence=$11, next_job_id=$12, last_job_id=$13, modules=$14 WHERE id=$1`,
		sc.ID, sc.Name, sc.Mode, targets, excl, sc.Ports, sc.Cron, sc.TZ, sc.MaxDurationS, sc.Enabled, sc.NextOccurrence, sc.NextJobID, sc.LastJobID, orEmpty(sc.Modules)))
}

func (p *Postgres) DeleteSchedule(ctx context.Context, id string) error {
	return execOne(p.pool.Exec(ctx, `DELETE FROM schedule WHERE id=$1`, id))
}

func (p *Postgres) GetFinding(ctx context.Context, id string) (*Finding, error) {
	list, err := loadFindings(ctx, p.pool, `SELECT `+findingColsPrefixed("f.")+` FROM finding f WHERE f.id=$1`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return list[0], nil
}

func (p *Postgres) ReviewFinding(ctx context.Context, id, review, by, reason string, at time.Time) error {
	var reviewedAt *time.Time
	if review != "" {
		reviewedAt = &at
	}
	return execOne(p.pool.Exec(ctx, `UPDATE finding SET review=$2, reviewed_by=$3, review_reason=$4, reviewed_at=$5 WHERE id=$1`, id, review, by, reason, reviewedAt))
}

func (p *Postgres) ReviewByDetector(ctx context.Context, siteID, detector, by, reason string, at time.Time) (int, error) {
	if detector == "" {
		return 0, nil
	}
	tag, err := p.pool.Exec(ctx, `UPDATE finding f SET review=$3, reviewed_by=$4, review_reason=$5, reviewed_at=$6
		FROM host h WHERE h.id=f.host_id AND h.site_id=$1 AND f.review='' AND (f.nvt_oid=$2 OR f.template_id=$2 OR 'nuclei:'||f.template_id=$2)`,
		siteID, detector, v1.ReviewFalsePositive, by, reason, at)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (p *Postgres) GetNVT(ctx context.Context, oid string) (*NVT, error) {
	n := &NVT{}
	err := p.pool.QueryRow(ctx, `SELECT oid, name, family, cvss, cves, qod, solution, feed_version FROM nvt WHERE oid=$1`, oid).
		Scan(&n.OID, &n.Name, &n.Family, &n.CVSS, &n.CVEs, &n.QoD, &n.Solution, &n.FeedVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return n, err
}
