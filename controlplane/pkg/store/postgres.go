package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Postgres is the production Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects and applies pending migrations.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) Close() error { p.pool.Close(); return nil }

func (p *Postgres) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		var exists bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, n).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sqlText, err := migrationFS.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES($1)`, n); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) EnsureVendor(ctx context.Context, name string) (*Vendor, error) {
	v := &Vendor{Name: name}
	err := p.pool.QueryRow(ctx, `INSERT INTO vendor(id,name) VALUES($1,$2)
		ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id, tier`, NewID("vnd"), name).Scan(&v.ID, &v.Tier)
	return v, err
}

func (p *Postgres) EnsureSite(ctx context.Context, vendorID, name string, cidrs []string, tz string, maxPPS int) (*Site, error) {
	if tz == "" {
		tz = "UTC"
	}
	if maxPPS == 0 {
		maxPPS = 300
	}
	if cidrs == nil {
		cidrs = []string{}
	}
	var id string
	err := p.pool.QueryRow(ctx, `INSERT INTO site(id,vendor_id,name,allowed_cidrs,tz,max_pps)
		VALUES($1,$2,$3,$4::cidr[],$5,$6)
		ON CONFLICT(vendor_id,name) DO UPDATE SET
		  allowed_cidrs = CASE WHEN cardinality($4::cidr[])>0 THEN $4::cidr[] ELSE site.allowed_cidrs END,
		  tz = $5, max_pps = $6
		RETURNING id`, NewID("site"), vendorID, name, cidrs, tz, maxPPS).Scan(&id)
	if err != nil {
		return nil, err
	}
	return p.GetSite(ctx, id)
}

func (p *Postgres) GetSite(ctx context.Context, id string) (*Site, error) {
	s := &Site{}
	var cidrs, excludes []string
	err := p.pool.QueryRow(ctx, `SELECT id, vendor_id, name, allowed_cidrs::text[], excludes::text[], fragile_ports, max_pps, tz FROM site WHERE id=$1`, id).
		Scan(&s.ID, &s.VendorID, &s.Name, &cidrs, &excludes, &s.FragilePorts, &s.MaxPPS, &s.TZ)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	s.AllowedCIDRs, s.Excludes = cidrs, excludes
	return s, err
}

func (p *Postgres) CreateAppliance(ctx context.Context, siteID string) (*Appliance, error) {
	id := NewID("apl")
	if _, err := p.pool.Exec(ctx, `INSERT INTO appliance(id, site_id) VALUES($1,$2)`, id, siteID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p.GetAppliance(ctx, id)
}

const applianceCols = `id, site_id, status, COALESCE(cert_serial,''), cert_not_after, version, bundle_version,
	last_heartbeat_at, last_heartbeat, skew_s, ifaces, fingerprint, binary_hashes, enrolled_at, created_at`

func scanAppliance(row pgx.Row) (*Appliance, error) {
	a := &Appliance{}
	var hb, ifaces, fp, bh []byte
	err := row.Scan(&a.ID, &a.SiteID, &a.Status, &a.CertSerial, &a.CertNotAfter, &a.Version, &a.BundleVersion,
		&a.LastHeartbeatAt, &hb, &a.SkewS, &ifaces, &fp, &bh, &a.EnrolledAt, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(hb) > 0 {
		a.LastHeartbeat = &v1.Heartbeat{}
		_ = json.Unmarshal(hb, a.LastHeartbeat)
	}
	_ = json.Unmarshal(ifaces, &a.Ifaces)
	if len(fp) > 0 {
		a.Fingerprint = &v1.Fingerprint{}
		_ = json.Unmarshal(fp, a.Fingerprint)
	}
	_ = json.Unmarshal(bh, &a.BinaryHashes)
	return a, nil
}

func (p *Postgres) GetAppliance(ctx context.Context, id string) (*Appliance, error) {
	return scanAppliance(p.pool.QueryRow(ctx, `SELECT `+applianceCols+` FROM appliance WHERE id=$1`, id))
}

func (p *Postgres) GetApplianceBySerial(ctx context.Context, serial string) (*Appliance, error) {
	if serial == "" {
		return nil, ErrNotFound
	}
	return scanAppliance(p.pool.QueryRow(ctx, `SELECT `+applianceCols+` FROM appliance WHERE cert_serial=$1`, serial))
}

func (p *Postgres) ListAppliances(ctx context.Context) ([]*Appliance, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+applianceCols+` FROM appliance ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Appliance
	for rows.Next() {
		a, err := scanAppliance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) SetStatus(ctx context.Context, id, status string) error {
	return execOne(p.pool.Exec(ctx, `UPDATE appliance SET status=$2 WHERE id=$1`, id, status))
}

func (p *Postgres) UpdateCert(ctx context.Context, id, serial string, notAfter time.Time) error {
	return execOne(p.pool.Exec(ctx, `UPDATE appliance SET cert_serial=$2, cert_not_after=$3 WHERE id=$1`, id, serial, notAfter))
}

func (p *Postgres) RecordHeartbeat(ctx context.Context, id string, at time.Time, hb *v1.Heartbeat) error {
	payload, _ := json.Marshal(hb)
	ifaces, _ := json.Marshal(hb.Ifaces)
	bh, _ := json.Marshal(hb.BinarySHA256)
	if bh == nil || string(bh) == "null" {
		bh = []byte("{}")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE appliance SET last_heartbeat_at=$2, last_heartbeat=$3, version=$4, bundle_version=$5,
		ifaces=$6, skew_s=$7, binary_hashes=$8 WHERE id=$1`, id, at, payload, hb.Version, hb.BundleVersion, ifaces, hb.SkewS, bh)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `INSERT INTO heartbeat(appliance_id, at, payload) VALUES($1,$2,$3)`, id, at, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) PutEnrollmentCode(ctx context.Context, c EnrollmentCode) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO enrollment_code(appliance_id, code_hash, expires_at)
		VALUES($1,$2,$3) ON CONFLICT(appliance_id) DO UPDATE SET code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at, used_at=NULL, attempts=0`,
		c.ApplianceID, c.CodeHash, c.ExpiresAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetEnrollmentCodeByHash(ctx context.Context, hash string) (*EnrollmentCode, error) {
	c := &EnrollmentCode{}
	err := p.pool.QueryRow(ctx, `SELECT appliance_id, code_hash, expires_at, used_at, attempts FROM enrollment_code WHERE code_hash=$1`, hash).
		Scan(&c.ApplianceID, &c.CodeHash, &c.ExpiresAt, &c.UsedAt, &c.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (p *Postgres) BumpCodeAttempts(ctx context.Context, hash string) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `UPDATE enrollment_code SET attempts=attempts+1 WHERE code_hash=$1 RETURNING attempts`, hash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

func (p *Postgres) CompleteEnrollment(ctx context.Context, u EnrollUpdate) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE enrollment_code SET used_at=now() WHERE code_hash=$1 AND appliance_id=$2 AND used_at IS NULL`, u.CodeHash, u.ApplianceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	fp, _ := json.Marshal(u.Fingerprint)
	tag, err = tx.Exec(ctx, `UPDATE appliance SET status='enrolled', cert_serial=$2, cert_not_after=$3, version=$4, fingerprint=$5, enrolled_at=now() WHERE id=$1`,
		u.ApplianceID, u.CertSerial, u.CertNotAfter, u.Version, fp)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (p *Postgres) LogEnrollAttempt(ctx context.Context, a EnrollAttempt) error {
	var apl *string
	if a.ApplianceID != "" {
		apl = &a.ApplianceID
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO enroll_attempt(at, source_ip, appliance_id, ok, reason) VALUES($1,$2,$3,$4,$5)`,
		a.At, a.SourceIP, apl, a.OK, a.Reason)
	return err
}

func (p *Postgres) CreateDirective(ctx context.Context, applianceID, typ string, payload map[string]any) (*Directive, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	pl, _ := json.Marshal(payload)
	d := &Directive{ID: NewID("dir"), ApplianceID: applianceID, Type: typ, Payload: payload}
	err := p.pool.QueryRow(ctx, `INSERT INTO directive(id, appliance_id, type, payload) VALUES($1,$2,$3,$4) RETURNING created_at`,
		d.ID, applianceID, typ, pl).Scan(&d.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return nil, ErrNotFound
	}
	return d, err
}

func scanDirectives(rows pgx.Rows) ([]Directive, error) {
	defer rows.Close()
	var out []Directive
	for rows.Next() {
		var d Directive
		var pl []byte
		if err := rows.Scan(&d.ID, &d.ApplianceID, &d.Type, &pl, &d.CreatedAt, &d.DeliveredAt, &d.AckedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(pl, &d.Payload)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (p *Postgres) PendingDirectives(ctx context.Context, applianceID string, markDelivered bool) ([]Directive, error) {
	if markDelivered {
		if _, err := p.pool.Exec(ctx, `UPDATE directive SET delivered_at=now() WHERE appliance_id=$1 AND acked_at IS NULL AND delivered_at IS NULL`, applianceID); err != nil {
			return nil, err
		}
	}
	rows, err := p.pool.Query(ctx, `SELECT id, appliance_id, type, payload, created_at, delivered_at, acked_at FROM directive
		WHERE appliance_id=$1 AND acked_at IS NULL ORDER BY created_at`, applianceID)
	if err != nil {
		return nil, err
	}
	return scanDirectives(rows)
}

func (p *Postgres) AckDirectives(ctx context.Context, applianceID string, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, `UPDATE directive SET acked_at=$3 WHERE appliance_id=$1 AND id = ANY($2) AND acked_at IS NULL`, applianceID, ids, at)
	return err
}

func (p *Postgres) ListDirectives(ctx context.Context, applianceID string) ([]Directive, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, appliance_id, type, payload, created_at, delivered_at, acked_at FROM directive
		WHERE appliance_id=$1 ORDER BY created_at`, applianceID)
	if err != nil {
		return nil, err
	}
	return scanDirectives(rows)
}

func (p *Postgres) Revoke(ctx context.Context, serial, reason string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO revoked_serial(serial, reason) VALUES($1,$2) ON CONFLICT DO NOTHING`, serial, reason)
	return err
}

func (p *Postgres) IsRevoked(ctx context.Context, serial string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM revoked_serial WHERE serial=$1)`, serial).Scan(&ok)
	return ok, err
}

func (p *Postgres) RecordSupportBundle(ctx context.Context, applianceID, objectKey string, bytes int64) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO support_bundle(appliance_id, object_key, bytes) VALUES($1,$2,$3)`, applianceID, objectKey, bytes)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func execOne(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
