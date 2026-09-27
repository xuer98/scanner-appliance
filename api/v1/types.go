// Package v1 holds the wire types shared by applianced and cp-api.
// Every request and response on /v1/* is defined here so both sides
// compile against one definition.
package v1

import (
	"encoding/json"
	"time"
)

// Fingerprint identifies the physical/virtual machine an appliance runs on.
// It is informational: the control plane records it and alerts on change,
// but identity is the client certificate, never the fingerprint.
type Fingerprint struct {
	MachineIDHash string   `json:"machine_id_hash"`
	MACs          []string `json:"macs"`
	CPU           string   `json:"cpu"`
	Hypervisor    string   `json:"hypervisor"`
}

// EnrollRequest is the body of POST /v1/enroll. It is the only endpoint
// that does not require a client certificate.
type EnrollRequest struct {
	Code        string      `json:"code"`
	CSRPEM      string      `json:"csr_pem"`
	Version     string      `json:"version"`
	Fingerprint Fingerprint `json:"fingerprint"`
}

// SiteConfig is what an appliance is allowed to touch (PLAN §11, §17.1).
// It is handed out at enrollment and renewal and refreshed with every
// dispatched job, so the appliance-side guardrails always see the current
// scope.
type SiteConfig struct {
	AllowedCIDRs []string `json:"allowed_cidrs"`
	// Excludes are never scanned even when inside AllowedCIDRs.
	Excludes []string `json:"excludes,omitempty"`
	// FragilePorts: a host with any of these open is kept away from
	// openvas until a human clears it (PLAN §10.6).
	FragilePorts []int  `json:"fragile_ports,omitempty"`
	TZ           string `json:"tz"`
	MaxPPS       int    `json:"max_pps,omitempty"`
	// MaxConcurrency caps openvas max_hosts × max_checks.
	MaxConcurrency int `json:"max_concurrency,omitempty"`
	// UnsafeOK allows safe_checks=false jobs (never for Tier 1 vendors;
	// enforced server-side).
	UnsafeOK bool `json:"unsafe_ok,omitempty"`
	// AllowPublic: the site attests ownership of public ranges listed in
	// AllowedCIDRs; a job must additionally be flagged allow_public.
	AllowPublic bool `json:"allow_public,omitempty"`
	// LANRoutes are extra routes for multi-subnet floors in split-network
	// mode (PLAN §15), written to lan0's networkd unit by the daemon.
	LANRoutes []LANRoute `json:"lan_routes,omitempty"`
}

// LANRoute is one static route reachable through a gateway on lan0's subnet.
type LANRoute struct {
	CIDR string `json:"cidr"`
	Via  string `json:"via"`
}

// EnrollResponse is returned on successful enrollment and renewal.
type EnrollResponse struct {
	ApplianceID   string     `json:"appliance_id"`
	CertPEM       string     `json:"cert_pem"`
	ChainPEM      string     `json:"chain_pem"`
	CPURL         string     `json:"cp_url"`
	PollIntervalS int        `json:"poll_interval_s"`
	Site          SiteConfig `json:"site"`
	// SpoolPubKey is the control plane's spool public key (internal/seal):
	// results are encrypted to it on the appliance before they touch disk
	// (PLAN §9, G6). SpoolKID identifies the key.
	SpoolPubKey string `json:"spool_pubkey,omitempty"`
	SpoolKID    string `json:"spool_kid,omitempty"`
}

// RenewRequest is the body of POST /v1/renew over mTLS.
type RenewRequest struct {
	CSRPEM  string `json:"csr_pem"`
	Version string `json:"version"`
}

// Iface describes one NIC as seen by the daemon.
type Iface struct {
	Name string `json:"name"`
	Role string `json:"role"` // wan | lan | single
	MAC  string `json:"mac"`
	IPv4 string `json:"ipv4"`
}

// JobProgress is the current_job element of the heartbeat.
type JobProgress struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	ProgressPct int    `json:"progress_pct"`
	StartedAt   int64  `json:"started_at"`
}

// Heartbeat is the body of POST /v1/appliances/{id}/heartbeat.
type Heartbeat struct {
	Version           string            `json:"version"`
	BundleVersion     string            `json:"bundle_version"`
	FeedVersion       string            `json:"feed_version"`
	UptimeS           int64             `json:"uptime_s"`
	Load1             float64           `json:"load1"`
	DiskFreeMB        int64             `json:"disk_free_mb"`
	MemFreeMB         int64             `json:"mem_free_mb"`
	Ifaces            []Iface           `json:"ifaces"`
	BinarySHA256      map[string]string `json:"binary_sha256"`
	PendingResults    int               `json:"pending_results"`
	CurrentJob        *JobProgress      `json:"current_job"`
	ClockEpoch        int64             `json:"clock_epoch"`
	AckedDirectiveIDs []string          `json:"acked_directive_ids"`
	// State is the daemon state machine value (idle, scanning, ...).
	State string `json:"state"`
	// StopAll reports whether a stop_all directive is in effect; the control
	// plane withholds jobs while it is (PLAN §11).
	StopAll bool `json:"stop_all"`
	// SkewS is the last measured clock skew against server_epoch.
	SkewS int64 `json:"skew_s"`
	// Engine is the detection-engine health (PLAN v1.1 §20 Phase 1: ospd_up, vt_cache_loaded).
	Engine EngineHealth `json:"engine"`
	// Phase 3 (PLAN §14): the platform the daemon runs on (release
	// selection for update_daemon), the outcome of the last update or
	// bundle apply (empty = ok; the control plane holds a canary rollout
	// on it), and whether the OS wants a reboot after unattended-upgrades.
	OS             string `json:"os,omitempty"`
	Arch           string `json:"arch,omitempty"`
	UpdateError    string `json:"update_error,omitempty"`
	RebootRequired bool   `json:"reboot_required,omitempty"`
}

// EngineHealth reports the embedded openvas stack. Phase 1 only probes it;
// Phase 2 drives scans over the same socket.
type EngineHealth struct {
	OSPDUp         bool   `json:"ospd_up"`
	VTCacheLoaded  bool   `json:"vt_cache_loaded"`
	VTCount        int    `json:"vt_count"`
	FeedVersion    string `json:"feed_version,omitempty"`
	OpenVASVersion string `json:"openvas_version,omitempty"`
	OSPDVersion    string `json:"ospd_version,omitempty"`
	Error          string `json:"error,omitempty"`
}

// Ready reports whether the engine can run an openvas scan right now.
func (e EngineHealth) Ready() bool { return e.OSPDUp && e.VTCacheLoaded }

// Directive types. The set is closed on purpose: there is no arbitrary
// command execution and no file fetch (PLAN §16).
const (
	DirectiveNoop         = "noop"
	DirectiveSetInterval  = "set_interval"
	DirectiveStopAll      = "stop_all"
	DirectiveUpdateDaemon = "update_daemon"
	DirectiveUpdateBundle = "update_bundle"
	DirectiveRenewCert    = "renew_cert"
	DirectiveWipe         = "wipe"
	DirectiveRunJobNow    = "run_job_now"
	// DirectiveReloadVTs makes the daemon wait for ospd to load the feed
	// currently in the plugins directory and report the outcome (Phase 3).
	DirectiveReloadVTs = "reload_vts"
)

// Payload keys shared by update_daemon / update_bundle (PLAN §8.2, §14):
//
//	url          path or URL of the artifact/manifest, relative to cp_url
//	sha256       hex digest of the artifact (daemon) or manifest (bundle)
//	sig          base64 ECDSA signature by the release key (cosign blob format)
//	version      version being rolled out
//	feed_version (bundle) feed version the manifest carries
const (
	PayloadURL         = "url"
	PayloadSHA256      = "sha256"
	PayloadSig         = "sig"
	PayloadVersion     = "version"
	PayloadFeedVersion = "feed_version"
)

// KnownDirectives is the closed allowlist checked on both sides.
var KnownDirectives = map[string]bool{
	DirectiveNoop: true, DirectiveSetInterval: true, DirectiveStopAll: true,
	DirectiveUpdateDaemon: true, DirectiveUpdateBundle: true, DirectiveRenewCert: true,
	DirectiveWipe: true, DirectiveRunJobNow: true, DirectiveReloadVTs: true,
}

// Directive is one control-channel instruction delivered in a heartbeat response.
type Directive struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload,omitempty"`
}

// HeartbeatResponse carries the server clock and pending directives.
type HeartbeatResponse struct {
	ServerEpoch int64       `json:"server_epoch"`
	Directives  []Directive `json:"directives"`
}

// SupportBundleAck is returned after a support bundle upload.
type SupportBundleAck struct {
	ObjectKey string `json:"object_key"`
	Bytes     int64  `json:"bytes"`
}

// WipeRequest tells the control plane the appliance has destroyed its state.
type WipeRequest struct {
	Reason string `json:"reason"`
}

// ErrorResponse is the uniform error body.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// Appliance status values stored on the control plane.
const (
	StatusPending     = "pending"
	StatusEnrolled    = "enrolled"
	StatusRevoked     = "revoked"
	StatusWiped       = "wiped"
	StatusQuarantined = "quarantined"
)

// ---- Jobs (PLAN §11) ----

// Scan modes (PLAN §10.5).
const (
	ModeDiscovery = "discovery"
	ModeInventory = "inventory"
	ModeFull      = "full"
)

// Modules a job may enable (PLAN §10.1). "web" is the Phase 3 add-on.
const (
	ModuleDiscovery = "discovery"
	ModulePortscan  = "portscan"
	ModuleOpenVAS   = "openvas"
	ModuleWeb       = "web"
)

// Port presets for the portscan module; anything else is an explicit
// comma-separated list of ports and ranges (e.g. "22,80,443,8000-8100").
const (
	PortsStandard = "standard" // top ~1000 TCP + enterprise/OT extras
	PortsFull     = "full"     // 1-65535 (Phase 5 option; accepted now)
)

// Job status values (PLAN §17.1).
const (
	JobQueued     = "queued"
	JobDispatched = "dispatched"
	JobRunning    = "running"
	JobDone       = "done"
	JobFailed     = "failed"
	JobRejected   = "rejected"
	JobCancelled  = "cancelled"
)

// OpenVASParams selects the scan config and intensity (PLAN §10.4, §11).
type OpenVASParams struct {
	Config              string `json:"config"` // inventory | full
	MaxHosts            int    `json:"max_hosts"`
	MaxChecks           int    `json:"max_checks"`
	FragilePortsExclude bool   `json:"fragile_ports_exclude"`
}

// WebParams configures the web add-on (httpx fingerprint + nuclei HTTP
// templates, PLAN §10.2). Nil when the web module is not enabled.
type WebParams struct {
	MinSeverity string   `json:"min_severity"`
	ExcludeTags []string `json:"exclude_tags"`
}

// DefaultWebParams is what PLAN §11 prescribes when the module is enabled.
func DefaultWebParams() *WebParams {
	return &WebParams{MinSeverity: SeverityMedium, ExcludeTags: []string{"dos", "fuzz", "intrusive"}}
}

// KnownSeverities is the closed severity set.
var KnownSeverities = map[string]bool{SeverityCritical: true, SeverityHigh: true, SeverityMedium: true, SeverityLow: true, SeverityInfo: true}

// SeverityRank orders severities (info=0 … critical=4); unknown is -1.
func SeverityRank(s string) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return -1
}

// Window is when a job may run: a cron expression marks the start of each
// window, MaxDurationS its length. An empty Cron means "any time".
type Window struct {
	Cron         string `json:"cron"`
	TZ           string `json:"tz"`
	MaxDurationS int    `json:"max_duration_s"`
}

// Rate limits the probing.
type Rate struct {
	PPS             int `json:"pps"`
	PerHostParallel int `json:"per_host_parallel"`
}

// JobSpec is the signed job document (PLAN §11). It is issued by the
// control plane at dispatch time and verified on the appliance against the
// issuing CA chain it received at enrollment.
type JobSpec struct {
	JobID       string         `json:"job_id"`
	SiteID      string         `json:"site_id"`
	ApplianceID string         `json:"appliance_id"`
	Mode        string         `json:"mode"`
	Targets     []string       `json:"targets"`
	Excludes    []string       `json:"excludes"`
	Ports       string         `json:"ports"`
	Modules     []string       `json:"modules"`
	OpenVAS     *OpenVASParams `json:"openvas"`
	Web         *WebParams     `json:"web"`
	Window      *Window        `json:"window"`
	Rate        Rate           `json:"rate"`
	SafeChecks  bool           `json:"safe_checks"`
	AllowPublic bool           `json:"allow_public"`
	Iface       string         `json:"iface"`
	IssuedAt    int64          `json:"issued_at"`
	Sig         string         `json:"sig"`
}

// JobsResponse is the body of GET /v1/appliances/{id}/jobs when a job is
// dispatched (204 otherwise). Site is the current scope so the appliance
// re-checks the job against fresh limits.
type JobsResponse struct {
	Job         JobSpec    `json:"job"`
	Site        SiteConfig `json:"site"`
	ServerEpoch int64      `json:"server_epoch"`
}

// JobStatusRequest is the body of POST /v1/jobs/{job}/status.
type JobStatusRequest struct {
	Status      string `json:"status"` // running | rejected | failed | done
	Phase       string `json:"phase,omitempty"`
	ProgressPct int    `json:"progress_pct"`
	Reason      string `json:"reason,omitempty"`
	// Check names the failing guardrail when Status is rejected.
	Check string `json:"check,omitempty"`
}

// ---- Results (PLAN §12.1) ----

// Severity buckets derived from the CVSS base score.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// SeverityFor maps a CVSS base score to a bucket (NVD v3 ranges).
func SeverityFor(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return SeverityCritical
	case cvss >= 7.0:
		return SeverityHigh
	case cvss >= 4.0:
		return SeverityMedium
	case cvss > 0:
		return SeverityLow
	}
	return SeverityInfo
}

// OSGuess is the operating-system estimate for a host.
type OSGuess struct {
	Family     string  `json:"family"`
	Name       string  `json:"name,omitempty"`
	CPE        string  `json:"cpe,omitempty"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

// Port is one open port with whatever the engines learned about it.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	CPE     string `json:"cpe,omitempty"`
	Source  string `json:"source"`
	// Web is the httpx fingerprint when the web add-on probed the port.
	Web *WebInfo `json:"web,omitempty"`
}

// WebInfo is what httpx learned about an HTTP(S) service.
type WebInfo struct {
	URL    string   `json:"url"`
	Status int      `json:"status,omitempty"`
	Title  string   `json:"title,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"tech,omitempty"`
}

// Finding is one detected issue on a host.
type Finding struct {
	Source   string   `json:"source"` // openvas | nuclei
	NVTOID   string   `json:"nvt_oid,omitempty"`
	ID       string   `json:"id,omitempty"` // nuclei template id (Phase 3)
	Name     string   `json:"name"`
	Family   string   `json:"family,omitempty"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	CVE      []string `json:"cve"`
	QoD      int      `json:"qod"`
	Port     int      `json:"port,omitempty"`
	Proto    string   `json:"proto,omitempty"`
	Evidence string   `json:"evidence"`
	Solution string   `json:"solution,omitempty"`
}

// Host is one scanned host.
type Host struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	OSGuess  *OSGuess  `json:"os_guess,omitempty"`
	Ports    []Port    `json:"ports"`
	Findings []Finding `json:"findings"`
	// Notes carry policy decisions such as "fragile:9100" (excluded from
	// openvas because a fragile-device port was open).
	Notes []string `json:"notes,omitempty"`
}

// ScanStats summarizes a completed job.
type ScanStats struct {
	HostsAlive      int              `json:"hosts_alive"`
	HostsScanned    int              `json:"hosts_scanned"`
	FragileExcluded int              `json:"fragile_excluded"`
	OpenPorts       int              `json:"open_ports"`
	Findings        int              `json:"findings"`
	DurationS       int64            `json:"duration_s"`
	PhaseDurationS  map[string]int64 `json:"phase_duration_s,omitempty"`
	Rejected        []string         `json:"rejected"`
	// Warnings are non-fatal conditions such as a skipped web phase
	// because httpx/nuclei or templates were missing.
	Warnings []string `json:"warnings,omitempty"`
}

// ResultBatch is one uploaded chunk of a job's normalized results. Chunks
// are sequenced per job; the chunk with Final=true carries Stats.
type ResultBatch struct {
	JobID       string     `json:"job_id"`
	ApplianceID string     `json:"appliance_id"`
	SiteID      string     `json:"site_id"`
	FeedVersion string     `json:"feed_version"`
	StartedAt   int64      `json:"started_at"`
	FinishedAt  int64      `json:"finished_at,omitempty"`
	Seq         int        `json:"seq"`
	Final       bool       `json:"final"`
	Hosts       []Host     `json:"hosts"`
	Stats       *ScanStats `json:"stats,omitempty"`
}

// Result upload headers (POST /v1/jobs/{job}/results). The body is a sealed
// envelope (internal/seal) whose plaintext is a ResultBatch.
const (
	HeaderResultSeq    = "X-Result-Seq"
	HeaderResultSHA256 = "X-Result-SHA256"
	HeaderResultFinal  = "X-Result-Final"
	ContentTypeSealed  = "application/vnd.tprm.sealed+json"
)

// ResultAck acknowledges one chunk.
type ResultAck struct {
	Seq       int  `json:"seq"`
	Duplicate bool `json:"duplicate"`
	Hosts     int  `json:"hosts"`
	Complete  bool `json:"complete"`
}

// ---- Admin API types (/admin/*, portal SSO or bearer token) ----

type AdminCreateApplianceRequest struct {
	Vendor         string   `json:"vendor"`
	Site           string   `json:"site"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	TZ             string   `json:"tz,omitempty"`
	MaxPPS         int      `json:"max_pps,omitempty"`
	MaxConcurrency int      `json:"max_concurrency,omitempty"`
}

type AdminCreateApplianceResponse struct {
	ApplianceID string    `json:"appliance_id"`
	SiteID      string    `json:"site_id"`
	Code        string    `json:"code"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type AdminApplianceView struct {
	ApplianceID     string       `json:"appliance_id"`
	SiteID          string       `json:"site_id"`
	Status          string       `json:"status"`
	Online          bool         `json:"online"`
	Version         string       `json:"version"`
	BundleVersion   string       `json:"bundle_version"`
	FeedVersion     string       `json:"feed_version"`
	CertSerial      string       `json:"cert_serial,omitempty"`
	CertNotAfter    *time.Time   `json:"cert_not_after,omitempty"`
	LastHeartbeatAt *time.Time   `json:"last_heartbeat_at"`
	LastHeartbeat   *Heartbeat   `json:"last_heartbeat,omitempty"`
	SkewS           int64        `json:"skew_s"`
	Ifaces          []Iface      `json:"ifaces"`
	Fingerprint     *Fingerprint `json:"fingerprint,omitempty"`
	// Phase 3: canary group membership and the last update outcome.
	Canary      bool   `json:"canary"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
	UpdateError string `json:"update_error,omitempty"`
}

// AdminApplianceUpdate patches mutable appliance attributes.
type AdminApplianceUpdate struct {
	Canary *bool `json:"canary,omitempty"`
}

type AdminDirectiveRequest struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload,omitempty"`
}

type AdminDirectiveView struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Payload     map[string]any `json:"payload,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	DeliveredAt *time.Time     `json:"delivered_at"`
	AckedAt     *time.Time     `json:"acked_at"`
}

// AdminSiteView / AdminSiteUpdate: scope editor (PLAN §17.4). Vendor-owner
// approval of CIDR changes is a portal concern (Phase 4).
type AdminSiteView struct {
	ID         string     `json:"id"`
	VendorID   string     `json:"vendor_id"`
	VendorName string     `json:"vendor_name"`
	VendorTier int        `json:"vendor_tier"`
	Name       string     `json:"name"`
	Config     SiteConfig `json:"config"`
}

type AdminSiteUpdate struct {
	AllowedCIDRs   *[]string   `json:"allowed_cidrs,omitempty"`
	Excludes       *[]string   `json:"excludes,omitempty"`
	FragilePorts   *[]int      `json:"fragile_ports,omitempty"`
	TZ             *string     `json:"tz,omitempty"`
	MaxPPS         *int        `json:"max_pps,omitempty"`
	MaxConcurrency *int        `json:"max_concurrency,omitempty"`
	UnsafeOK       *bool       `json:"unsafe_ok,omitempty"`
	AllowPublic    *bool       `json:"allow_public,omitempty"`
	LANRoutes      *[]LANRoute `json:"lan_routes,omitempty"`
}

// ---- Phase 3: bundles, releases and rollouts (PLAN §13, §14, §17.1) ----

// Rollout states shared by bundles and releases.
const (
	RolloutCanary   = "canary"   // delivered to canary appliances only
	RolloutReleased = "released" // delivered to every appliance
	RolloutHeld     = "held"     // a canary reported a failure; not delivered further
	RolloutRetired  = "retired"  // superseded; never delivered again
)

// AdminPublishBundleRequest publishes a signed manifest whose files were
// uploaded beforehand (PUT /admin/bundles/files/{sha256}).
type AdminPublishBundleRequest struct {
	Manifest json.RawMessage `json:"manifest"`
	Sig      string          `json:"sig"`
	// CanaryHours is how long the bundle stays with the canary group before
	// general release; 0 uses the server default.
	CanaryHours float64 `json:"canary_hours,omitempty"`
}

// AdminBundleView describes one published bundle.
type AdminBundleView struct {
	Version     string     `json:"version"`
	FeedVersion string     `json:"feed_version"`
	Files       int        `json:"files"`
	Bytes       int64      `json:"bytes"`
	SHA256      string     `json:"sha256"`
	Status      string     `json:"status"`
	HeldReason  string     `json:"held_reason,omitempty"`
	PublishedAt time.Time  `json:"published_at"`
	CanaryUntil *time.Time `json:"canary_until,omitempty"`
	// Appliances on this bundle / total enrolled, for the rollout view.
	Installed int `json:"installed"`
	Fleet     int `json:"fleet"`
}

// AdminMissingFilesRequest asks which content-addressed files the server
// lacks so the publisher uploads only the delta.
type AdminMissingFilesRequest struct {
	SHA256 []string `json:"sha256"`
}

type AdminMissingFilesResponse struct {
	Missing []string `json:"missing"`
}

// Release upload headers (PUT /admin/releases/{component}/{version}); the
// body is the artifact.
const (
	HeaderReleaseSHA256 = "X-Release-SHA256"
	HeaderReleaseSig    = "X-Release-Sig"
	HeaderCanaryHours   = "X-Canary-Hours"
)

// AdminReleaseView describes one published daemon release.
type AdminReleaseView struct {
	Component   string     `json:"component"` // applianced-<os>-<arch>
	Version     string     `json:"version"`
	SHA256      string     `json:"sha256"`
	Bytes       int64      `json:"bytes"`
	Status      string     `json:"status"`
	HeldReason  string     `json:"held_reason,omitempty"`
	PublishedAt time.Time  `json:"published_at"`
	CanaryUntil *time.Time `json:"canary_until,omitempty"`
	Installed   int        `json:"installed"`
	Fleet       int        `json:"fleet"`
}

// AdminRolloutRequest changes a bundle's or release's rollout state
// (release now, hold, retire).
type AdminRolloutRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ReleaseComponent names the daemon artifact for a platform.
func ReleaseComponent(os, arch string) string { return "applianced-" + os + "-" + arch }

// AdminJobRequest schedules a job for one appliance. Omitted fields take
// the mode's defaults (api/v1 DefaultsFor).
type AdminJobRequest struct {
	ApplianceID  string         `json:"appliance_id"`
	Mode         string         `json:"mode"`
	Targets      []string       `json:"targets"`
	Excludes     []string       `json:"excludes,omitempty"`
	Ports        string         `json:"ports,omitempty"`
	Modules      []string       `json:"modules,omitempty"`
	OpenVAS      *OpenVASParams `json:"openvas,omitempty"`
	Window       *Window        `json:"window,omitempty"`
	Rate         *Rate          `json:"rate,omitempty"`
	SafeChecks   *bool          `json:"safe_checks,omitempty"`
	AllowPublic  bool           `json:"allow_public,omitempty"`
	Iface        string         `json:"iface,omitempty"`
	ScheduledFor *time.Time     `json:"scheduled_for,omitempty"`
}

type AdminJobView struct {
	ID           string     `json:"id"`
	SiteID       string     `json:"site_id"`
	ApplianceID  string     `json:"appliance_id"`
	Status       string     `json:"status"`
	Spec         JobSpec    `json:"spec"`
	ScheduledFor *time.Time `json:"scheduled_for,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ProgressPct  int        `json:"progress_pct"`
	Phase        string     `json:"phase,omitempty"`
	RejectReason string     `json:"reject_reason,omitempty"`
	Batches      int        `json:"batches"`
	Stats        *ScanStats `json:"stats,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Evidence is one observation backing a finding (PLAN §12.3: a finding
// confirmed by both the agent and the appliance carries two entries).
type Evidence struct {
	Source string    `json:"source"` // agent | openvas | nuclei
	JobID  string    `json:"job_id,omitempty"`
	At     time.Time `json:"at"`
	QoD    int       `json:"qod,omitempty"`
	Detail string    `json:"detail"`
}

// Finding lifecycle states (PLAN §12.3).
const (
	FindingConfirmed       = "confirmed"
	FindingNetworkObserved = "network_observed"
	FindingSuspected       = "suspected"
)

// Host source values (PLAN §12.2).
const (
	SourceAgent     = "agent"
	SourceAppliance = "appliance"
	SourceBoth      = "both"
)

type AdminFindingView struct {
	ID          string     `json:"id"`
	HostID      string     `json:"host_id"`
	Source      string     `json:"source"` // agent | openvas | nuclei | both
	State       string     `json:"state"`
	NVTOID      string     `json:"nvt_oid,omitempty"`
	TemplateID  string     `json:"template_id,omitempty"` // nuclei (web add-on)
	Name        string     `json:"name"`
	Family      string     `json:"family,omitempty"`
	Severity    string     `json:"severity"`
	CVSS        float64    `json:"cvss"`
	CVE         []string   `json:"cve"`
	QoD         int        `json:"qod"`
	Port        int        `json:"port,omitempty"`
	Proto       string     `json:"proto,omitempty"`
	Solution    string     `json:"solution,omitempty"`
	Evidence    []Evidence `json:"evidence"`
	FeedVersion string     `json:"feed_version,omitempty"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
}

type AdminHostView struct {
	ID        string             `json:"id"`
	SiteID    string             `json:"site_id"`
	IP        string             `json:"ip"`
	MAC       string             `json:"mac,omitempty"`
	Hostname  string             `json:"hostname,omitempty"`
	Source    string             `json:"source"` // agent | appliance | both
	AgentID   string             `json:"agent_id,omitempty"`
	OSGuess   *OSGuess           `json:"os_guess,omitempty"`
	Ports     []Port             `json:"ports"`
	Findings  []AdminFindingView `json:"findings"`
	Notes     []string           `json:"notes,omitempty"`
	LastJobID string             `json:"last_job_id,omitempty"`
	FirstSeen time.Time          `json:"first_seen"`
	LastSeen  time.Time          `json:"last_seen"`
}

// AgentHost is what the agent track (Wazuh) knows about a host; ingested
// via POST /admin/sites/{id}/agent-inventory so appliance results can be
// correlated (PLAN §12.3). Packages are kept opaque: the agent inventory
// always wins for package data and the appliance never overrides it.
type AgentHost struct {
	AgentID  string         `json:"agent_id"`
	Hostname string         `json:"hostname"`
	IP       string         `json:"ip,omitempty"`
	MACs     []string       `json:"macs,omitempty"`
	OS       string         `json:"os,omitempty"`
	Packages []AgentPackage `json:"packages,omitempty"`
	Findings []AgentFinding `json:"findings,omitempty"`
}

type AgentPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type AgentFinding struct {
	CVE      string  `json:"cve"`
	Package  string  `json:"package,omitempty"`
	Severity string  `json:"severity,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	Detail   string  `json:"detail,omitempty"`
}

type AdminAgentInventoryRequest struct {
	Hosts []AgentHost `json:"hosts"`
}

type AdminAgentInventoryResponse struct {
	Hosts   int `json:"hosts"`
	Merged  int `json:"merged"`
	Created int `json:"created"`
}
