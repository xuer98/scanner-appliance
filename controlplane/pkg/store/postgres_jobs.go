package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Phase 2 methods of the Postgres store: sites, jobs, results, hosts,
// findings and the NVT mirror. Correlation runs in-process on the site's
// rows (correlate.go) inside one transaction per ingest.

func (p *Postgres) GetVendor(ctx context.Context, id string) (*Vendor, error) {
	v := &Vendor{}
	err := p.pool.QueryRow(ctx, `SELECT id, name, tier FROM vendor WHERE id=$1`, id).Scan(&v.ID, &v.Name, &v.Tier)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

const siteCols = `id, vendor_id, name, allowed_cidrs::text[], excludes::text[], fragile_ports, max_pps, max_concurrency, tz, unsafe_ok, allow_public, lan_routes,
	fragile_cleared, fragile_hosts, vt_excludes, version, attested_at, attested_by`

func scanSite(row pgx.Row) (*Site, error) {
	s := &Site{}
	var cidrs, excludes []string
	var routes []byte
	err := row.Scan(&s.ID, &s.VendorID, &s.Name, &cidrs, &excludes, &s.FragilePorts, &s.MaxPPS, &s.MaxConcurrency, &s.TZ, &s.UnsafeOK, &s.AllowPublic, &routes,
		&s.FragileCleared, &s.FragileHosts, &s.VTExcludes, &s.Version, &s.AttestedAt, &s.AttestedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	s.AllowedCIDRs, s.Excludes = cidrs, excludes
	if len(routes) > 0 {
		_ = json.Unmarshal(routes, &s.LANRoutes)
	}
	return s, err
}

func (p *Postgres) ListSites(ctx context.Context) ([]*Site, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+siteCols+` FROM site ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Site
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateSite(ctx context.Context, s *Site) error {
	cidrs, excl := s.AllowedCIDRs, s.Excludes
	if cidrs == nil {
		cidrs = []string{}
	}
	if excl == nil {
		excl = []string{}
	}
	fr := s.FragilePorts
	if fr == nil {
		fr = []int{}
	}
	routes := s.LANRoutes
	if routes == nil {
		routes = []v1.LANRoute{}
	}
	rj, _ := json.Marshal(routes)
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return execOne(p.pool.Exec(ctx, `UPDATE site SET allowed_cidrs=$2::cidr[], excludes=$3::cidr[], fragile_ports=$4, max_pps=$5, max_concurrency=$6, tz=$7, unsafe_ok=$8, allow_public=$9, lan_routes=$10,
		fragile_cleared=$11, fragile_hosts=$12, vt_excludes=$13, version=$14, attested_at=$15, attested_by=$16 WHERE id=$1`,
		s.ID, cidrs, excl, fr, s.MaxPPS, s.MaxConcurrency, s.TZ, s.UnsafeOK, s.AllowPublic, rj,
		nonNil(s.FragileCleared), nonNil(s.FragileHosts), nonNil(s.VTExcludes), s.Version, s.AttestedAt, s.AttestedBy))
}

const jobCols = `id, site_id, appliance_id, status, spec, scheduled_for, dispatched_at, started_at, finished_at, progress_pct, phase, reject_reason, batches, stats, created_at, schedule_id`

func scanJob(row pgx.Row) (*Job, error) {
	j := &Job{}
	var spec, stats []byte
	err := row.Scan(&j.ID, &j.SiteID, &j.ApplianceID, &j.Status, &spec, &j.ScheduledFor, &j.DispatchedAt, &j.StartedAt, &j.FinishedAt,
		&j.ProgressPct, &j.Phase, &j.RejectReason, &j.Batches, &stats, &j.CreatedAt, &j.ScheduleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(spec, &j.Spec)
	if len(stats) > 0 {
		j.Stats = &v1.ScanStats{}
		_ = json.Unmarshal(stats, j.Stats)
	}
	return j, nil
}

func (p *Postgres) CreateJob(ctx context.Context, j *Job) error {
	if j.ID == "" {
		j.ID = NewID("job")
	}
	if j.Status == "" {
		j.Status = v1.JobQueued
	}
	spec, _ := json.Marshal(j.Spec)
	var stats []byte
	if j.Stats != nil {
		stats, _ = json.Marshal(j.Stats)
	}
	err := p.pool.QueryRow(ctx, `INSERT INTO job(id, site_id, appliance_id, status, spec, scheduled_for, progress_pct, phase, stats, schedule_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`,
		j.ID, j.SiteID, j.ApplianceID, j.Status, spec, j.ScheduledFor, j.ProgressPct, j.Phase, stats, j.ScheduleID).Scan(&j.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetJob(ctx context.Context, id string) (*Job, error) {
	return scanJob(p.pool.QueryRow(ctx, `SELECT `+jobCols+` FROM job WHERE id=$1`, id))
}

func (p *Postgres) scanJobs(rows pgx.Rows, err error) ([]*Job, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (p *Postgres) ListJobs(ctx context.Context, siteID, applianceID string) ([]*Job, error) {
	return p.scanJobs(p.pool.Query(ctx, `SELECT `+jobCols+` FROM job WHERE ($1='' OR site_id=$1) AND ($2='' OR appliance_id=$2) ORDER BY created_at`, siteID, applianceID))
}

func (p *Postgres) DispatchableJobs(ctx context.Context, applianceID string, now time.Time, lease time.Duration) ([]*Job, error) {
	return p.scanJobs(p.pool.Query(ctx, `SELECT `+jobCols+` FROM job WHERE appliance_id=$1 AND (
		(status='queued' AND (scheduled_for IS NULL OR scheduled_for <= $2)) OR
		(status='dispatched' AND dispatched_at IS NOT NULL AND dispatched_at < $3))
		ORDER BY COALESCE(scheduled_for, created_at), created_at`, applianceID, now, now.Add(-lease)))
}

func (p *Postgres) UpdateJob(ctx context.Context, j *Job) error {
	spec, _ := json.Marshal(j.Spec)
	var stats []byte
	if j.Stats != nil {
		stats, _ = json.Marshal(j.Stats)
	}
	return execOne(p.pool.Exec(ctx, `UPDATE job SET status=$2, spec=$3, scheduled_for=$4, dispatched_at=$5, started_at=$6, finished_at=$7,
		progress_pct=$8, phase=$9, reject_reason=$10, stats=$11 WHERE id=$1`,
		j.ID, j.Status, spec, j.ScheduledFor, j.DispatchedAt, j.StartedAt, j.FinishedAt, j.ProgressPct, j.Phase, j.RejectReason, stats))
}

func (p *Postgres) NoteJobProgress(ctx context.Context, jobID, applianceID, phase string, pct int, at time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE job SET status=$5, phase=$3, progress_pct=$4, started_at=COALESCE(started_at, $6)
		WHERE id=$1 AND appliance_id=$2 AND status IN ($7, $5) AND NOT (status=$5 AND phase=$3 AND progress_pct=$4)`,
		jobID, applianceID, phase, pct, v1.JobRunning, at, v1.JobDispatched)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (p *Postgres) RecordResultBatch(ctx context.Context, rec ResultBatchRec) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var existing string
	err = tx.QueryRow(ctx, `SELECT sha256 FROM result_batch WHERE job_id=$1 AND seq=$2 FOR UPDATE`, rec.JobID, rec.Seq).Scan(&existing)
	switch {
	case err == nil:
		if existing == rec.SHA256 {
			return true, nil
		}
		return false, ErrConflict
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO result_batch(job_id, seq, received_at, object_key, sha256, final, hosts) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		rec.JobID, rec.Seq, rec.ReceivedAt, rec.ObjectKey, rec.SHA256, rec.Final, rec.Hosts); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return false, ErrNotFound
		}
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE job SET batches=batches+1 WHERE id=$1`, rec.JobID); err != nil {
		return false, err
	}
	return false, tx.Commit(ctx)
}

const hostCols = `id, site_id, ip, mac, hostname, source, agent_id, os_guess, ports, notes, agent_os, packages, last_job_id, first_seen, last_seen, cpes`

func scanHost(row pgx.Row) (*Host, error) {
	h := &Host{}
	var os, ports, notes, pkgs []byte
	err := row.Scan(&h.ID, &h.SiteID, &h.IP, &h.MAC, &h.Hostname, &h.Source, &h.AgentID, &os, &ports, &notes, &h.AgentOS, &pkgs, &h.LastJobID, &h.FirstSeen, &h.LastSeen, &h.CPEs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(os) > 0 {
		h.OSGuess = &v1.OSGuess{}
		_ = json.Unmarshal(os, h.OSGuess)
	}
	_ = json.Unmarshal(ports, &h.Ports)
	_ = json.Unmarshal(notes, &h.Notes)
	_ = json.Unmarshal(pkgs, &h.Packages)
	return h, nil
}

const findingCols = `id, host_id, source, state, nvt_oid, name, family, severity, cvss, cve, qod, port, proto, solution, evidence, feed_version, first_seen, last_seen, template_id, review, reviewed_at, reviewed_by, review_reason, status, fixed_at, reopened_at, reopens, scope, external_id`

func scanFinding(row pgx.Row) (*Finding, error) {
	f := &Finding{}
	var ev []byte
	err := row.Scan(&f.ID, &f.HostID, &f.Source, &f.State, &f.NVTOID, &f.Name, &f.Family, &f.Severity, &f.CVSS, &f.CVE, &f.QoD, &f.Port, &f.Proto, &f.Solution, &ev, &f.FeedVersion, &f.FirstSeen, &f.LastSeen, &f.TemplateID, &f.Review, &f.ReviewedAt, &f.ReviewedBy, &f.ReviewReason,
		&f.Status, &f.FixedAt, &f.ReopenedAt, &f.Reopens, &f.Scope, &f.ExternalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ev, &f.Evidence)
	return f, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func loadHosts(ctx context.Context, q querier, sql string, args ...any) ([]*Host, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func loadFindings(ctx context.Context, q querier, sql string, args ...any) ([]*Finding, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// loadSiteIndex locks and loads the site's hosts and findings.
func (p *Postgres) loadSiteIndex(ctx context.Context, tx pgx.Tx, siteID string) (*siteIndex, error) {
	// Serialize ingests per site: correlation reads and rewrites the site's rows.
	var locked string
	var vtExcludes []string
	if err := tx.QueryRow(ctx, `SELECT id, vt_excludes FROM site WHERE id=$1 FOR UPDATE`, siteID).Scan(&locked, &vtExcludes); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	hosts, err := loadHosts(ctx, tx, `SELECT `+hostCols+` FROM host WHERE site_id=$1 ORDER BY ip, id FOR UPDATE`, siteID)
	if err != nil {
		return nil, err
	}
	findings, err := loadFindings(ctx, tx, `SELECT f.`+findingColsPrefixed("f.")+` FROM finding f JOIN host h ON h.id=f.host_id WHERE h.site_id=$1 FOR UPDATE OF f`, siteID)
	if err != nil {
		return nil, err
	}
	ix := newSiteIndex(siteID, hosts, findings)
	ix.setExcludes(vtExcludes)
	return ix, nil
}

func findingColsPrefixed(prefix string) string {
	out := ""
	for i, c := range splitCols(findingCols) {
		if i > 0 {
			out += ", " + prefix
		}
		out += c
	}
	return out
}

func splitCols(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, trimSpace(cur))
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, trimSpace(cur))
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func (p *Postgres) commitIndex(ctx context.Context, tx pgx.Tx, ix *siteIndex) error {
	for _, h := range ix.changed {
		var os []byte
		if h.OSGuess != nil {
			os, _ = json.Marshal(h.OSGuess)
		}
		ports, _ := json.Marshal(nonNilPorts(h.Ports))
		notes, _ := json.Marshal(nonNilStrings(h.Notes))
		pkgs, _ := json.Marshal(nonNilPackages(h.Packages))
		if _, err := tx.Exec(ctx, `INSERT INTO host(`+hostCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (id) DO UPDATE SET ip=EXCLUDED.ip, mac=EXCLUDED.mac, hostname=EXCLUDED.hostname, source=EXCLUDED.source, agent_id=EXCLUDED.agent_id,
			os_guess=EXCLUDED.os_guess, ports=EXCLUDED.ports, notes=EXCLUDED.notes, agent_os=EXCLUDED.agent_os, packages=EXCLUDED.packages,
			last_job_id=EXCLUDED.last_job_id, first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen, cpes=EXCLUDED.cpes`,
			h.ID, h.SiteID, h.IP, h.MAC, h.Hostname, h.Source, h.AgentID, os, ports, notes, h.AgentOS, pkgs, h.LastJobID, h.FirstSeen, h.LastSeen, nonNilStrings(h.CPEs)); err != nil {
			return err
		}
	}
	for _, f := range ix.changedF {
		ev, _ := json.Marshal(f.Evidence)
		cve := f.CVE
		if cve == nil {
			cve = []string{}
		}
		status := f.Status
		if status == "" {
			status = v1.FindingOpen
		}
		if _, err := tx.Exec(ctx, `INSERT INTO finding(`+findingCols+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)
			ON CONFLICT (id) DO UPDATE SET host_id=EXCLUDED.host_id, source=EXCLUDED.source, state=EXCLUDED.state, nvt_oid=EXCLUDED.nvt_oid, name=EXCLUDED.name, family=EXCLUDED.family,
			severity=EXCLUDED.severity, cvss=EXCLUDED.cvss, cve=EXCLUDED.cve, qod=EXCLUDED.qod, port=EXCLUDED.port, proto=EXCLUDED.proto, solution=EXCLUDED.solution,
			evidence=EXCLUDED.evidence, feed_version=EXCLUDED.feed_version, first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen, template_id=EXCLUDED.template_id,
			review=EXCLUDED.review, reviewed_at=EXCLUDED.reviewed_at, reviewed_by=EXCLUDED.reviewed_by, review_reason=EXCLUDED.review_reason,
			status=EXCLUDED.status, fixed_at=EXCLUDED.fixed_at, reopened_at=EXCLUDED.reopened_at, reopens=EXCLUDED.reopens, scope=EXCLUDED.scope, external_id=EXCLUDED.external_id`,
			f.ID, f.HostID, f.Source, f.State, f.NVTOID, f.Name, f.Family, f.Severity, f.CVSS, cve, f.QoD, f.Port, f.Proto, f.Solution, ev, f.FeedVersion, f.FirstSeen, f.LastSeen, f.TemplateID,
			f.Review, f.ReviewedAt, f.ReviewedBy, f.ReviewReason, status, f.FixedAt, f.ReopenedAt, f.Reopens, f.Scope, f.ExternalID); err != nil {
			return err
		}
	}
	// Records folded into another one go last: their findings have moved
	// by now, and what is left of them (job links, findings the other
	// record already had) goes with them by cascade.
	for id := range ix.removed {
		if _, err := tx.Exec(ctx, `DELETE FROM host WHERE id=$1`, id); err != nil {
			return err
		}
	}
	return nil
}

func nonNilPorts(p []v1.Port) []v1.Port {
	if p == nil {
		return []v1.Port{}
	}
	return p
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilPackages(p []v1.AgentPackage) []v1.AgentPackage {
	if p == nil {
		return []v1.AgentPackage{}
	}
	return p
}

func (p *Postgres) IngestHosts(ctx context.Context, siteID, jobID string, hosts []v1.Host, feedVersion string, at time.Time) (IngestSummary, error) {
	return p.IngestScan(ctx, ScanIngest{SiteID: siteID, JobID: jobID, Hosts: hosts, FeedVersion: feedVersion, At: at})
}

func (p *Postgres) IngestScan(ctx context.Context, in ScanIngest) (IngestSummary, error) {
	siteID, jobID, hosts, feedVersion, at := in.SiteID, in.JobID, in.Hosts, in.FeedVersion, in.At
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return IngestSummary{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	ix, err := p.loadSiteIndex(ctx, tx, siteID)
	if err != nil {
		return IngestSummary{}, err
	}
	sum, touched := ix.ingestAppliance(jobID, hosts, feedVersion, at, in.Scope)
	if err := p.commitIndex(ctx, tx, ix); err != nil {
		return IngestSummary{}, err
	}
	if jobID != "" {
		for _, id := range touched {
			if _, err := tx.Exec(ctx, `INSERT INTO job_host(job_id, host_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, jobID, id); err != nil {
				return IngestSummary{}, err
			}
		}
	}
	return sum, tx.Commit(ctx)
}

func (p *Postgres) IngestAgentHosts(ctx context.Context, siteID string, hosts []v1.AgentHost, at time.Time) (IngestSummary, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return IngestSummary{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	ix, err := p.loadSiteIndex(ctx, tx, siteID)
	if err != nil {
		return IngestSummary{}, err
	}
	sum := ix.ingestAgent(hosts, at)
	if err := p.commitIndex(ctx, tx, ix); err != nil {
		return IngestSummary{}, err
	}
	return sum, tx.Commit(ctx)
}

func (p *Postgres) ListHosts(ctx context.Context, siteID string) ([]*Host, error) {
	return loadHosts(ctx, p.pool, `SELECT `+hostCols+` FROM host WHERE site_id=$1 ORDER BY ip, id`, siteID)
}

func (p *Postgres) ListJobHosts(ctx context.Context, jobID string) ([]*Host, error) {
	return loadHosts(ctx, p.pool, `SELECT h.`+hostColsPrefixed("h.")+` FROM host h JOIN job_host jh ON jh.host_id=h.id WHERE jh.job_id=$1 ORDER BY h.ip, h.id`, jobID)
}

func hostColsPrefixed(prefix string) string {
	out := ""
	for i, c := range splitCols(hostCols) {
		if i > 0 {
			out += ", " + prefix
		}
		out += c
	}
	return out
}

func (p *Postgres) GetHost(ctx context.Context, id string) (*Host, error) {
	return scanHost(p.pool.QueryRow(ctx, `SELECT `+hostCols+` FROM host WHERE id=$1`, id))
}

func (p *Postgres) ListFindings(ctx context.Context, siteID, hostID string) ([]*Finding, error) {
	return loadFindings(ctx, p.pool, `SELECT f.`+findingColsPrefixed("f.")+` FROM finding f JOIN host h ON h.id=f.host_id
		WHERE ($1='' OR h.site_id=$1) AND ($2='' OR f.host_id=$2) ORDER BY f.cvss DESC, f.id`, siteID, hostID)
}

func (p *Postgres) UpsertNVTs(ctx context.Context, nvts []NVT) error {
	if len(nvts) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, n := range nvts {
		if n.OID == "" {
			continue
		}
		cves := n.CVEs
		if cves == nil {
			cves = []string{}
		}
		batch.Queue(`INSERT INTO nvt(oid, name, family, cvss, cves, qod, solution, feed_version, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())
			ON CONFLICT (oid) DO UPDATE SET name=EXCLUDED.name, family=EXCLUDED.family, cvss=EXCLUDED.cvss, cves=EXCLUDED.cves, qod=EXCLUDED.qod,
			solution=EXCLUDED.solution, feed_version=EXCLUDED.feed_version, updated_at=now()`,
			n.OID, n.Name, n.Family, n.CVSS, cves, n.QoD, n.Solution, n.FeedVersion)
	}
	res := p.pool.SendBatch(ctx, batch)
	defer res.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := res.Exec(); err != nil {
			return err
		}
	}
	return nil
}
