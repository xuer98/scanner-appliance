// Package store is the persistence boundary for cp-api. Two implementations
// exist: Postgres (production) and an in-memory store (--dev and tests).
package store

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Vendor struct {
	ID   string
	Name string
	Tier int
}

type Site struct {
	ID             string
	VendorID       string
	Name           string
	AllowedCIDRs   []string
	Excludes       []string
	FragilePorts   []int
	MaxPPS         int
	MaxConcurrency int
	TZ             string
	UnsafeOK       bool
	AllowPublic    bool
	LANRoutes      []v1.LANRoute
	// Phase 4 policy (PLAN §10.6, §19, §22): versioned, audited in site_change.
	FragileCleared []string
	FragileHosts   []string
	VTExcludes     []string
	Version        int
	AttestedAt     *time.Time
	AttestedBy     string
}

type Appliance struct {
	ID              string
	SiteID          string
	Status          string
	CertSerial      string
	CertNotAfter    *time.Time
	Version         string
	BundleVersion   string
	LastHeartbeatAt *time.Time
	LastHeartbeat   *v1.Heartbeat
	SkewS           int64
	Ifaces          []v1.Iface
	Fingerprint     *v1.Fingerprint
	BinaryHashes    map[string]string
	EnrolledAt      *time.Time
	CreatedAt       time.Time
	// Phase 3 (PLAN §14): canary group, platform (release selection), the
	// engine's loaded feed version and the last update outcome.
	Canary         bool
	OS             string
	Arch           string
	FeedVersion    string
	UpdateError    string
	RebootRequired bool
	// EngineDownSince is set while heartbeats report the engine not ready
	// (PLAN §8.4 degraded after 15 min); nil when ready.
	EngineDownSince *time.Time
}

type EnrollmentCode struct {
	ApplianceID string
	CodeHash    string
	ExpiresAt   time.Time
	UsedAt      *time.Time
	Attempts    int
}

type Directive struct {
	ID          string
	ApplianceID string
	Type        string
	Payload     map[string]any
	CreatedAt   time.Time
	DeliveredAt *time.Time
	AckedAt     *time.Time
}

type EnrollAttempt struct {
	At          time.Time
	SourceIP    string
	ApplianceID string
	OK          bool
	Reason      string
}

// EnrollUpdate is applied atomically when a code is accepted.
type EnrollUpdate struct {
	ApplianceID  string
	CodeHash     string
	CertSerial   string
	CertNotAfter time.Time
	Version      string
	Fingerprint  v1.Fingerprint
}

// Store is everything the server needs. Methods are safe for concurrent use.
type Store interface {
	// Vendors and sites
	EnsureVendor(ctx context.Context, name string) (*Vendor, error)
	EnsureSite(ctx context.Context, vendorID, name string, cidrs []string, tz string, maxPPS int) (*Site, error)
	GetSite(ctx context.Context, id string) (*Site, error)

	// Appliances
	CreateAppliance(ctx context.Context, siteID string) (*Appliance, error)
	GetAppliance(ctx context.Context, id string) (*Appliance, error)
	GetApplianceBySerial(ctx context.Context, serial string) (*Appliance, error)
	ListAppliances(ctx context.Context) ([]*Appliance, error)
	SetStatus(ctx context.Context, id, status string) error
	UpdateCert(ctx context.Context, id, serial string, notAfter time.Time) error
	RecordHeartbeat(ctx context.Context, id string, at time.Time, hb *v1.Heartbeat) error

	// Enrollment
	PutEnrollmentCode(ctx context.Context, c EnrollmentCode) error
	GetEnrollmentCodeByHash(ctx context.Context, hash string) (*EnrollmentCode, error)
	BumpCodeAttempts(ctx context.Context, hash string) (int, error)
	CompleteEnrollment(ctx context.Context, u EnrollUpdate) error
	LogEnrollAttempt(ctx context.Context, a EnrollAttempt) error

	// Directives
	CreateDirective(ctx context.Context, applianceID, typ string, payload map[string]any) (*Directive, error)
	PendingDirectives(ctx context.Context, applianceID string, markDelivered bool) ([]Directive, error)
	AckDirectives(ctx context.Context, applianceID string, ids []string, at time.Time) error
	ListDirectives(ctx context.Context, applianceID string) ([]Directive, error)

	// Revocation
	Revoke(ctx context.Context, serial, reason string) error
	IsRevoked(ctx context.Context, serial string) (bool, error)

	// Support bundles
	RecordSupportBundle(ctx context.Context, applianceID, objectKey string, bytes int64) error

	// Sites and vendors (scope editor, PLAN §17.4)
	GetVendor(ctx context.Context, id string) (*Vendor, error)
	ListSites(ctx context.Context) ([]*Site, error)
	UpdateSite(ctx context.Context, s *Site) error

	// Jobs (PLAN §11, §17.2)
	CreateJob(ctx context.Context, j *Job) error
	GetJob(ctx context.Context, id string) (*Job, error)
	ListJobs(ctx context.Context, siteID, applianceID string) ([]*Job, error)
	// DispatchableJobs returns queued jobs due at now and dispatched jobs
	// whose lease expired, oldest first.
	DispatchableJobs(ctx context.Context, applianceID string, now time.Time, lease time.Duration) ([]*Job, error)
	UpdateJob(ctx context.Context, j *Job) error

	// Results (PLAN §12)
	// RecordResultBatch is idempotent per (job, seq): the same sha256 again
	// reports duplicate=true; a different sha256 for a seen seq is ErrConflict.
	RecordResultBatch(ctx context.Context, rec ResultBatchRec) (duplicate bool, err error)
	IngestHosts(ctx context.Context, siteID, jobID string, hosts []v1.Host, feedVersion string, at time.Time) (IngestSummary, error)
	IngestAgentHosts(ctx context.Context, siteID string, hosts []v1.AgentHost, at time.Time) (IngestSummary, error)
	ListHosts(ctx context.Context, siteID string) ([]*Host, error)
	ListJobHosts(ctx context.Context, jobID string) ([]*Host, error)
	GetHost(ctx context.Context, id string) (*Host, error)
	ListFindings(ctx context.Context, siteID, hostID string) ([]*Finding, error)
	UpsertNVTs(ctx context.Context, nvts []NVT) error

	// Bundles, releases and rollouts (PLAN §13, §14, §17.1)
	PutBundle(ctx context.Context, b *Bundle) error
	GetBundle(ctx context.Context, version string) (*Bundle, error)
	ListBundles(ctx context.Context) ([]*Bundle, error) // newest first
	SetBundleStatus(ctx context.Context, version, status, reason string) error
	// ConfirmBundle records the first time a canary appliance reported the
	// bundle installed; later calls keep that first time.
	ConfirmBundle(ctx context.Context, version string, at time.Time) error
	// PutBundleFiles records content-addressed files that exist in the
	// object store; HasBundleFiles reports which of the digests are known.
	PutBundleFiles(ctx context.Context, files []BundleFileRec) error
	HasBundleFiles(ctx context.Context, sha256 []string) (map[string]bool, error)
	PutRelease(ctx context.Context, r *Release) error
	GetRelease(ctx context.Context, component, version string) (*Release, error)
	ListReleases(ctx context.Context) ([]*Release, error) // newest first
	SetReleaseStatus(ctx context.Context, component, version, status, reason string) error
	SetApplianceCanary(ctx context.Context, id string, canary bool) error

	// Phase 4 (PLAN §10.6, §16, §17.4, §19, §22)
	RecordSiteChange(ctx context.Context, c *SiteChange) error
	ListSiteChanges(ctx context.Context, siteID string) ([]*SiteChange, error) // newest first
	CreateScopeRequest(ctx context.Context, r *ScopeRequest) error
	GetScopeRequest(ctx context.Context, id string) (*ScopeRequest, error)
	ListScopeRequests(ctx context.Context, siteID, status string) ([]*ScopeRequest, error)
	UpdateScopeRequest(ctx context.Context, r *ScopeRequest) error
	CreateSchedule(ctx context.Context, sc *Schedule) error
	GetSchedule(ctx context.Context, id string) (*Schedule, error)
	ListSchedules(ctx context.Context, siteID string) ([]*Schedule, error)
	UpdateSchedule(ctx context.Context, sc *Schedule) error
	DeleteSchedule(ctx context.Context, id string) error
	GetFinding(ctx context.Context, id string) (*Finding, error)
	ReviewFinding(ctx context.Context, id, review, by, reason string, at time.Time) error
	// ReviewByDetector marks the site's unreviewed findings of one detector
	// (NVT OID or "nuclei:<template>") as false positives; returns the count.
	ReviewByDetector(ctx context.Context, siteID, detector, by, reason string, at time.Time) (int, error)
	GetNVT(ctx context.Context, oid string) (*NVT, error)

	// Phase 5 (PLAN §20 Phase 5, §21): control-plane settings such as the
	// nmap legal sign-off. GetSetting returns ErrNotFound for an absent key.
	GetSetting(ctx context.Context, key string) (string, error)
	PutSetting(ctx context.Context, key, value string) error
	DeleteSetting(ctx context.Context, key string) error

	// Phase 6 (Qualys replacement): scoped ingest (IngestHosts is the
	// unscoped form), the finding lifecycle, external scanner imports,
	// retention bookkeeping and cluster-wide singleton locks.
	IngestScan(ctx context.Context, in ScanIngest) (IngestSummary, error)
	// ResolveFindings marks fixed the open network-scanner findings of the
	// hosts a job observed (excluding hosts the fragile policy kept away
	// from detection) whose scope is covered and that the job did not
	// re-observe (last_seen before the job started). Returns them.
	ResolveFindings(ctx context.Context, siteID, jobID string, scopes []string, before, at time.Time) ([]*Finding, error)
	IngestExternal(ctx context.Context, siteID, scanner string, hosts []v1.ExternalHost, at time.Time) (IngestSummary, error)
	ListResultBatches(ctx context.Context, before time.Time, limit int) ([]ResultBatchRec, error) // unpurged, oldest first
	MarkResultBatchPurged(ctx context.Context, jobID string, seq int) error
	ListSupportBundles(ctx context.Context, before time.Time, limit int) ([]SupportBundleRec, error)
	MarkSupportBundlePurged(ctx context.Context, id int64) error
	// TryLock takes a named lock held until release is called; ok is false
	// when another control-plane instance holds it.
	TryLock(ctx context.Context, name string) (release func(), ok bool, err error)

	Close() error
}

// NewID returns a ULID-like identifier with the given prefix:
// 48-bit ms timestamp + 80 random bits, Crockford base32, 26 chars.
func NewID(prefix string) string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(b[0:8], ms<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	enc := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	return prefix + "_" + enc.EncodeToString(b[:])
}
