// Package v1 holds the wire types shared by applianced and cp-api.
// Every request and response on /v1/* is defined here so both sides
// compile against one definition.
package v1

import (
	"encoding/json"
	"strings"
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
	// Phase 4 fragile-device policy (PLAN §10.6): hosts a human cleared for
	// openvas although a fragile port is open, and hosts always kept away
	// from openvas whatever their ports. VTExcludes are NVT OIDs or nuclei
	// template ids whose findings are suppressed on this site (false
	// positives codified during the pilot). Version increments on every
	// policy or scope change so results can be tied to the policy in force.
	FragileCleared []string `json:"fragile_cleared,omitempty"`
	FragileHosts   []string `json:"fragile_hosts,omitempty"`
	VTExcludes     []string `json:"vt_excludes,omitempty"`
	Version        int      `json:"version,omitempty"`
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
	// Tools lists the engine helpers present on the appliance (naabu,
	// httpx, nuclei, nmap); the portal shows which add-ons a build carries.
	Tools []string `json:"tools,omitempty"`
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
	// ModuleFingerprint (Phase 5, PLAN §10.2 "Later"): an nmap -sV / -O pass
	// over the open ports after detection. nmap is NPSL-licensed, so the
	// control plane refuses the module until the legal sign-off is recorded
	// (AdminSignoffRequest) and the appliance skips it when nmap is absent.
	ModuleFingerprint = "fingerprint"
	// ModuleUDP adds UDP tests to the openvas phase. It is never part of a
	// mode's defaults: openvas has no UDP port scanner of its own, so the
	// only way to run its UDP tests is to let each of them probe its
	// well-known port on every host, whether or not anything listens. That
	// is slower and reaches ports no port scan pinned, so a job has to ask
	// for it. Hosts without an open TCP port are tested too in such a job.
	ModuleUDP = "udp"
	// ModuleDefaultLogins lets the web phase run its default-login checks:
	// the nuclei templates that sign in with default user names and
	// passwords, several pairs per product and hundreds of requests per
	// web server. Like udp it is never part of a mode's defaults, so a job
	// has to ask for them, and without the module the web phase leaves
	// them out. It does not govern openvas: the feed's "Default Accounts"
	// family is part of both scan configs (internal/scanconfig) and tries
	// the known default password of specific products in every scan.
	ModuleDefaultLogins = "default_logins"
)

// TagDefaultLogin is the nuclei template tag of the checks that
// ModuleDefaultLogins gates.
const TagDefaultLogin = "default-login"

// Families of the web add-on's findings. A finding of a default-login
// check has its own family, which is also how the control plane knows
// that only a job with ModuleDefaultLogins can see it again.
const (
	FamilyWeb             = "Web application (nuclei)"
	FamilyWebDefaultLogin = "Default login (nuclei)"
)

// NoteUDPTested is the host note the appliance sets when the UDP tests ran
// against the host. Without it the control plane keeps the UDP ports it
// already knows, because the scan could not have seen them.
const NoteUDPTested = "openvas:udp"

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

// FingerprintParams configures the nmap pass (Phase 5): service/version
// detection on the TCP ports the port scan found (--version-intensity
// Intensity, 0..9) and, with OSDetection, TCP/IP stack OS fingerprinting.
// No NSE scripts are ever run. Nil when the module is off.
type FingerprintParams struct {
	OSDetection bool `json:"os_detection"`
	Intensity   int  `json:"intensity"`
}

// DefaultFingerprintParams: OS detection on, a middling probe intensity
// (nmap's own default is 7; fragile hosts never reach this phase anyway).
func DefaultFingerprintParams() *FingerprintParams {
	return &FingerprintParams{OSDetection: true, Intensity: 5}
}

// MaxFingerprintIntensity is nmap's upper bound for --version-intensity.
const MaxFingerprintIntensity = 9

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
	// Phase 5 (omitted when unused so older appliances re-encode the same
	// signed bytes): the nmap pass parameters, and the number of live hosts
	// the control plane expects inside Targets (from the site inventory;
	// 0 = unknown, the guardrails then count addresses). The full-range
	// port option is budgeted against it (internal/guard CheckDuration).
	Fingerprint   *FingerprintParams `json:"fingerprint,omitempty"`
	ExpectedHosts int                `json:"expected_hosts,omitempty"`
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
	// CPEs is every CPE the engines tied to this port, CPE included. One
	// service often has several: the feed registers nginx as nginx:nginx
	// and as f5:nginx. Empty when at most CPE is known.
	CPEs   []string `json:"cpes,omitempty"`
	Source string   `json:"source"`
	// Web is the httpx fingerprint when the web add-on probed the port.
	Web *WebInfo `json:"web,omitempty"`
}

// AllCPEs lists every CPE known for the port: CPEs when present, else CPE
// alone (older results carry only that).
func (p Port) AllCPEs() []string {
	if len(p.CPEs) > 0 {
		return p.CPEs
	}
	if p.CPE != "" {
		return []string{p.CPE}
	}
	return nil
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
	// CPEs is the engine's product inventory for the host: every CPE it
	// registered, whether it tied the product to a port, to a path or to
	// the host as a whole. Operating-system candidates are part of it; the
	// engine's pick among them is OSGuess.
	CPEs []string `json:"cpes,omitempty"`
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
	// Suppressed counts findings dropped by the site's VT exclusions.
	Suppressed int `json:"suppressed,omitempty"`
	// Fingerprinted counts hosts the nmap pass covered (Phase 5).
	Fingerprinted int `json:"fingerprinted,omitempty"`
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
	// Phase 4: derived health for the portal (PLAN §8.4): online, stale (no
	// heartbeat for 3 intervals), silent (24 h, alerted), degraded (engine
	// not ready for 15 min), never (no heartbeat yet).
	Health          string     `json:"health"`
	EngineDownSince *time.Time `json:"engine_down_since,omitempty"`
	// Phase 5: engine helpers the appliance reported (engine.tools).
	Tools []string `json:"tools,omitempty"`
}

// Appliance health values.
const (
	HealthOnline   = "online"
	HealthStale    = "stale"
	HealthSilent   = "silent"
	HealthDegraded = "degraded"
	HealthNever    = "never"
)

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
	// Phase 4: scope attestation by the vendor owner (PLAN §19.2) and the
	// number of scope requests awaiting approval.
	AttestedAt     *time.Time `json:"attested_at,omitempty"`
	AttestedBy     string     `json:"attested_by,omitempty"`
	PendingScope   int        `json:"pending_scope_requests"`
	AttestionStale bool       `json:"attestation_stale"`
}

// ---- Phase 4: pilot operations (PLAN §10.6, §16, §17.4, §19, §22) ----

// Roles carried by admin bearer tokens. The vendor owner is the only role
// that can approve a scope change or attest the scope (PLAN §16).
const (
	RoleOperator    = "operator"
	RoleVendorOwner = "vendor-owner"
)

// AdminScopeRequest asks for a change of the site's allowed CIDRs.
type AdminScopeRequest struct {
	AllowedCIDRs []string `json:"allowed_cidrs"`
	Reason       string   `json:"reason"`
}

type AdminScopeRequestView struct {
	ID           string     `json:"id"`
	SiteID       string     `json:"site_id"`
	Status       string     `json:"status"` // pending | approved | rejected
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	Reason       string     `json:"reason"`
	RequestedAt  time.Time  `json:"requested_at"`
	RequestedBy  string     `json:"requested_by"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	Decision     string     `json:"decision,omitempty"`
}

// Scope request states.
const (
	ScopePending  = "pending"
	ScopeApproved = "approved"
	ScopeRejected = "rejected"
)

// AdminDecision carries the reason for an approval/rejection.
type AdminDecision struct {
	Reason string `json:"reason,omitempty"`
}

// AdminSiteChangeView is one audit-log entry (versioned policy, PLAN §10.6).
type AdminSiteChangeView struct {
	ID      string    `json:"id"`
	SiteID  string    `json:"site_id"`
	Version int       `json:"version"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Kind    string    `json:"kind"` // scope | policy | exclusion | attest | fragile
	Field   string    `json:"field"`
	Old     string    `json:"old,omitempty"`
	New     string    `json:"new,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// AdminFragileRequest changes the fragile-device policy for one host.
type AdminFragileRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action"` // clear | unclear | mark | unmark
	Reason string `json:"reason"`
}

// AdminFragileHostView is one host under the fragile-device policy.
type AdminFragileHostView struct {
	IP           string `json:"ip"`
	Hostname     string `json:"hostname,omitempty"`
	FragilePorts []int  `json:"fragile_ports"`
	Excluded     bool   `json:"excluded"` // kept away from openvas by the policy in force
	Reason       string `json:"reason"`   // "port 9100", "policy", "cleared"
	Cleared      bool   `json:"cleared"`
	Marked       bool   `json:"marked"`
	LastSeen     string `json:"last_seen,omitempty"`
}

type AdminFragileView struct {
	SiteID       string                 `json:"site_id"`
	Version      int                    `json:"version"`
	FragilePorts []int                  `json:"fragile_ports"`
	Cleared      []string               `json:"cleared"`
	Marked       []string               `json:"marked"`
	Hosts        []AdminFragileHostView `json:"hosts"`
}

// AdminExclusionRequest adds a VT exclusion (NVT OID or nuclei template id).
type AdminExclusionRequest struct {
	VT     string `json:"vt"`
	Reason string `json:"reason"`
}

// AdminTuningReport is the false-positive review of PLAN §20 Phase 4.
type AdminTuningReport struct {
	SiteID            string              `json:"site_id"`
	Findings          int                 `json:"findings"`
	Reviewed          int                 `json:"reviewed"`
	FalsePositives    int                 `json:"false_positives"`
	Accepted          int                 `json:"accepted"`
	FalsePositiveRate float64             `json:"false_positive_rate"`
	Suspected         int                 `json:"suspected"`
	BySeverity        map[string]int      `json:"by_severity"`
	ByDetector        []AdminDetectorStat `json:"by_detector"`
	Exclusions        []string            `json:"exclusions"`
}

type AdminDetectorStat struct {
	Detector       string `json:"detector"` // NVT OID or nuclei:<template>
	Name           string `json:"name"`
	Findings       int    `json:"findings"`
	FalsePositives int    `json:"false_positives"`
	Suspected      int    `json:"suspected"`
	Excluded       bool   `json:"excluded"`
}

// AdminScheduleRequest creates or updates a recurring scan (PLAN §17.4 job
// calendar). The control plane creates one job per occurrence.
type AdminScheduleRequest struct {
	ApplianceID  string   `json:"appliance_id"`
	Name         string   `json:"name"`
	Mode         string   `json:"mode"`
	Targets      []string `json:"targets"`
	Excludes     []string `json:"excludes,omitempty"`
	Ports        string   `json:"ports,omitempty"`
	Cron         string   `json:"cron"`
	TZ           string   `json:"tz,omitempty"`
	MaxDurationS int      `json:"max_duration_s,omitempty"`
	Enabled      *bool    `json:"enabled,omitempty"`
	// Modules overrides the mode's default module set (Phase 5: e.g. an
	// inventory schedule with the fingerprint pass); empty = mode default.
	Modules []string `json:"modules,omitempty"`
}

type AdminScheduleView struct {
	ID             string     `json:"id"`
	SiteID         string     `json:"site_id"`
	ApplianceID    string     `json:"appliance_id"`
	Name           string     `json:"name"`
	Mode           string     `json:"mode"`
	Targets        []string   `json:"targets"`
	Excludes       []string   `json:"excludes"`
	Ports          string     `json:"ports"`
	Modules        []string   `json:"modules"`
	Cron           string     `json:"cron"`
	TZ             string     `json:"tz"`
	MaxDurationS   int        `json:"max_duration_s"`
	Enabled        bool       `json:"enabled"`
	NextOccurrence *time.Time `json:"next_occurrence,omitempty"`
	NextJobID      string     `json:"next_job_id,omitempty"`
	LastJobID      string     `json:"last_job_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// AdminCalendarEntry is one row of the site's job calendar: a past or
// current job, or a computed future occurrence of a schedule.
type AdminCalendarEntry struct {
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"` // job | occurrence
	ScheduleID   string    `json:"schedule_id,omitempty"`
	ScheduleName string    `json:"schedule_name,omitempty"`
	JobID        string    `json:"job_id,omitempty"`
	Mode         string    `json:"mode"`
	Status       string    `json:"status,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
	Targets      []string  `json:"targets"`
}

// AdminCoverage is the coverage input to the vendor score (PLAN §12.3,
// §8.4): 0-100 with the reasons behind it.
type AdminCoverage struct {
	SiteID     string            `json:"site_id,omitempty"`
	VendorID   string            `json:"vendor_id,omitempty"`
	Score      int               `json:"score"`
	Appliance  CoverageAppliance `json:"appliance"`
	Freshness  CoverageFreshness `json:"freshness"`
	Hosts      CoverageHosts     `json:"hosts"`
	Findings   CoverageFindings  `json:"findings"`
	Attested   *time.Time        `json:"attested_at,omitempty"`
	Reasons    []string          `json:"reasons"`
	Sites      []AdminCoverage   `json:"sites,omitempty"` // vendor roll-up
	ComputedAt time.Time         `json:"computed_at"`
	Weights    map[string]int    `json:"weights"`
	Components map[string]int    `json:"components"`
	Meta       map[string]any    `json:"-"`
}

type CoverageAppliance struct {
	Count    int    `json:"count"`
	Health   string `json:"health"` // best health among the site's appliances
	Online   int    `json:"online"`
	Degraded int    `json:"degraded"`
	Silent   int    `json:"silent"`
}

type CoverageFreshness struct {
	LastDiscovery *time.Time `json:"last_discovery,omitempty"`
	LastInventory *time.Time `json:"last_inventory,omitempty"`
	LastFull      *time.Time `json:"last_full,omitempty"`
	InventoryAgeH float64    `json:"inventory_age_h"`
	Overdue       bool       `json:"overdue"`
}

type CoverageHosts struct {
	Total         int     `json:"total"`
	ApplianceSeen int     `json:"appliance_seen"`
	AgentSeen     int     `json:"agent_seen"`
	Both          int     `json:"both"`
	Agentless     int     `json:"agentless"`
	AgentFraction float64 `json:"agent_fraction"`
}

type CoverageFindings struct {
	Open             int            `json:"open"`
	NetworkReachable int            `json:"network_reachable"`
	Suspected        int            `json:"suspected"`
	FalsePositives   int            `json:"false_positives"`
	BySeverity       map[string]int `json:"by_severity"`
}

// AdminAlert is one condition the portal should surface (PLAN §8.4 "alert
// at 24 h silent" and friends).
type AdminAlert struct {
	Kind        string     `json:"kind"` // silent | stale | degraded | update_error | rollout_held | scope_pending | scan_overdue | attestation_stale
	Severity    string     `json:"severity"`
	SiteID      string     `json:"site_id,omitempty"`
	ApplianceID string     `json:"appliance_id,omitempty"`
	Subject     string     `json:"subject"`
	Detail      string     `json:"detail"`
	Since       *time.Time `json:"since,omitempty"`
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

// AdminPublishBundleResponse answers a publish. 201 carries the new bundle.
// 200 with Unchanged set means nothing was published: the newest bundle,
// the one described, already carries exactly these files, and a second
// name for them would only make every appliance fetch the file list again.
type AdminPublishBundleResponse struct {
	AdminBundleView
	Unchanged bool `json:"unchanged,omitempty"`
}

// AdminBundleView describes one published bundle.
type AdminBundleView struct {
	Version     string `json:"version"`
	FeedVersion string `json:"feed_version"`
	Files       int    `json:"files"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	// ContentSHA256 names the set of files, whatever the bundle is called:
	// equal for two bundles that install the same bytes at the same paths.
	ContentSHA256 string     `json:"content_sha256,omitempty"`
	Status        string     `json:"status"`
	HeldReason    string     `json:"held_reason,omitempty"`
	PublishedAt   time.Time  `json:"published_at"`
	CanaryUntil   *time.Time `json:"canary_until,omitempty"`
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
	// Fingerprint (Phase 5) enables the nmap pass with these parameters;
	// after the legal sign-off full-mode jobs include it by default.
	Fingerprint *FingerprintParams `json:"fingerprint,omitempty"`
	// UDP adds the udp module to the job's modules (see ModuleUDP).
	UDP bool `json:"udp,omitempty"`
	// DefaultLogins adds the default_logins module (see ModuleDefaultLogins).
	DefaultLogins bool `json:"default_logins,omitempty"`
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
	ScheduleID   string     `json:"schedule_id,omitempty"`
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

	// Review states set by a human (Phase 4, PLAN §22): orthogonal to the
	// detection state above. "" means unreviewed.
	ReviewFalsePositive = "false_positive"
	ReviewAccepted      = "accepted"

	// ExposureMultiplier weights network-reachable findings in the vendor
	// score (PLAN §12.3).
	ExposureMultiplier = 1.5
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
	// Phase 4: human review and scoring hints for the portal.
	Review             string     `json:"review,omitempty"`
	ReviewedAt         *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy         string     `json:"reviewed_by,omitempty"`
	ReviewReason       string     `json:"review_reason,omitempty"`
	NetworkReachable   bool       `json:"network_reachable"`
	ExposureMultiplier float64    `json:"exposure_multiplier"`
	// Phase 6: lifecycle (open until a covering rescan no longer observes
	// it, then fixed; reopened when it returns), the scan scope that can
	// resolve it, the external scanner's id (Qualys QID) and SLA ageing.
	Status     string     `json:"status"`
	FixedAt    *time.Time `json:"fixed_at,omitempty"`
	ReopenedAt *time.Time `json:"reopened_at,omitempty"`
	Reopens    int        `json:"reopens,omitempty"`
	Scope      string     `json:"scope,omitempty"`
	ExternalID string     `json:"external_id,omitempty"`
	DaysOpen   int        `json:"days_open"`
	SLADays    int        `json:"sla_days,omitempty"`
	Overdue    bool       `json:"overdue"`
}

// AdminFindingDetail is the portal's finding page: the finding, its host
// and the mirrored VT metadata (PLAN §17.4).
type AdminFindingDetail struct {
	Finding AdminFindingView `json:"finding"`
	Host    AdminHostView    `json:"host"`
	NVT     *AdminNVTView    `json:"nvt,omitempty"`
}

type AdminNVTView struct {
	OID         string   `json:"oid"`
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	CVSS        float64  `json:"cvss"`
	CVEs        []string `json:"cves"`
	QoD         int      `json:"qod"`
	Solution    string   `json:"solution,omitempty"`
	FeedVersion string   `json:"feed_version"`
}

// AdminFindingReview marks a finding as a false positive or accepted risk
// (or reopens it with an empty review). Codify adds the detector id (NVT
// OID / nuclei template) to the site's VT exclusions.
type AdminFindingReview struct {
	Review string `json:"review"`
	Reason string `json:"reason"`
	Codify bool   `json:"codify,omitempty"`
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
	CPEs      []string           `json:"cpes,omitempty"`
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

// ---- Phase 5: depth (PLAN §20 Phase 5, §21) ----

// SignoffNmap is the only tool sign-off the control plane records: nmap is
// NPSL-licensed and is shipped and run only after legal review (PLAN §21).
const SignoffNmap = "nmap"

// AdminSignoffRequest records (PUT) the legal sign-off for a tool.
type AdminSignoffRequest struct {
	Reference string `json:"reference"` // ticket or contract reference of the review
	Note      string `json:"note,omitempty"`
}

// AdminSignoffView is the recorded sign-off; Approved is false when none
// exists (the fingerprint module is then refused).
type AdminSignoffView struct {
	Tool      string     `json:"tool"`
	Approved  bool       `json:"approved"`
	Reference string     `json:"reference,omitempty"`
	Note      string     `json:"note,omitempty"`
	By        string     `json:"by,omitempty"`
	At        *time.Time `json:"at,omitempty"`
}

// AdminOnboardingView tracks a site through the PLAN §19.2 flow so the
// portal can show what is left before a site counts as onboarded.
type AdminOnboardingView struct {
	SiteID   string           `json:"site_id"`
	Complete bool             `json:"complete"`
	Steps    []OnboardingStep `json:"steps"`
	Next     string           `json:"next,omitempty"`
}

// OnboardingStep is one item of the checklist.
type OnboardingStep struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Done   bool   `json:"done"`
	Detail string `json:"detail,omitempty"`
}

// AdminFeedGapReport is the data behind the Enterprise Feed evaluation
// (docs/ENTERPRISE-FEED.md): how much of what the appliances see is an
// enterprise product the community feed covers thinly, and how many open
// ports carry no identification at all.
type AdminFeedGapReport struct {
	SiteID            string              `json:"site_id,omitempty"`
	Hosts             int                 `json:"hosts"`
	OpenPorts         int                 `json:"open_ports"`
	IdentifiedPorts   int                 `json:"identified_ports"`
	UnidentifiedPorts int                 `json:"unidentified_ports"`
	EnterpriseHosts   int                 `json:"enterprise_hosts"`
	HostsNoFindings   int                 `json:"hosts_without_findings"`
	Enterprise        []AdminFeedGapEntry `json:"enterprise"`
	Recommendation    string              `json:"recommendation"`
	ComputedAt        time.Time           `json:"computed_at"`
}

// AdminFeedGapEntry aggregates one enterprise vendor.
type AdminFeedGapEntry struct {
	Vendor   string   `json:"vendor"`
	Hosts    int      `json:"hosts"`
	Ports    int      `json:"ports"`
	Findings int      `json:"findings"`
	Examples []string `json:"examples"`
}

// ---- Phase 6: Qualys replacement (finding lifecycle, external scanners,
// summaries and exports, webhooks, operations) ----

// Finding lifecycle status. A finding is open from first observation; a
// later scan whose scope covers it that observes the host without it marks
// it fixed; an observation after that reopens it (Qualys: Active / Fixed /
// Re-Opened).
const (
	FindingOpen  = "open"
	FindingFixed = "fixed"
)

// Scopes name the kind of scan that can resolve a finding: the openvas
// config that first detected it, the web add-on, or an external scanner.
const (
	ScopeInventory = "inventory"
	ScopeFull      = "full"
	ScopeWeb       = "web"
	// ScopeWebLogins is the scope of a finding of a default-login check:
	// only a job with ModuleDefaultLogins runs that check again.
	ScopeWebLogins = "web+logins"
)

// UDPScope is the scope of a finding that only a job with the udp module
// and that openvas config is known to see, so only such a job may resolve
// it. It holds for a finding on a UDP port, for one on a host that has no
// open TCP port, and for one that rests on something UDP revealed, such as
// a product version read over SNMP.
func UDPScope(config string) string { return config + udpScopeSuffix }

// SplitScope undoes UDPScope: the openvas config and whether the udp module
// is needed.
func SplitScope(scope string) (config string, udp bool) {
	return strings.CutSuffix(scope, udpScopeSuffix)
}

const udpScopeSuffix = "+udp"

// SourceExternal marks a host only an external scanner has seen.
const SourceExternal = "external"

// ExternalScanRequest imports findings from a scanner outside the
// appliance (Qualys during the migration) as a third evidence source,
// correlated with appliance and agent findings by CVE.
type ExternalScanRequest struct {
	Scanner   string         `json:"scanner"` // e.g. "qualys"
	ScannedAt *time.Time     `json:"scanned_at,omitempty"`
	Hosts     []ExternalHost `json:"hosts"`
}

type ExternalHost struct {
	IP       string            `json:"ip"`
	Hostname string            `json:"hostname,omitempty"`
	OS       string            `json:"os,omitempty"`
	Findings []ExternalFinding `json:"findings"`
}

type ExternalFinding struct {
	ID        string     `json:"id"` // the scanner's detection id (Qualys QID)
	Name      string     `json:"name"`
	Type      string     `json:"type,omitempty"` // confirmed | potential | info
	Severity  string     `json:"severity"`
	CVSS      float64    `json:"cvss,omitempty"`
	CVE       []string   `json:"cve"`
	Port      int        `json:"port,omitempty"`
	Proto     string     `json:"proto,omitempty"`
	Status    string     `json:"status,omitempty"` // new | active | fixed | reopened
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Evidence  string     `json:"evidence,omitempty"`
	Solution  string     `json:"solution,omitempty"`
}

type ExternalScanResponse struct {
	Scanner      string `json:"scanner"`
	Hosts        int    `json:"hosts"`
	HostsCreated int    `json:"hosts_created"`
	HostsMerged  int    `json:"hosts_merged"`
	Findings     int    `json:"findings"`
	FindingsNew  int    `json:"findings_new"`
	Fixed        int    `json:"findings_fixed"`
	Skipped      int    `json:"skipped"`
}

// AdminParityReport compares an external scanner with the appliance on
// one site over host×CVE pairs seen since Since (docs/MIGRATION.md).
type AdminParityReport struct {
	SiteID        string                  `json:"site_id"`
	Scanner       string                  `json:"scanner"`
	Since         time.Time               `json:"since"`
	MinSeverity   string                  `json:"min_severity"`
	Hosts         ParityHosts             `json:"hosts"`
	CVEs          ParityCounts            `json:"cves"`
	BySeverity    map[string]ParityCounts `json:"by_severity"`
	NoCVE         map[string]int          `json:"findings_without_cve"`
	ExternalOnly  []ParityItem            `json:"external_only"`
	ApplianceOnly []ParityItem            `json:"appliance_only"`
	DetectionRate float64                 `json:"detection_rate"` // both / (both + external only)
	Verdict       string                  `json:"verdict"`
	ComputedAt    time.Time               `json:"computed_at"`
}

type ParityHosts struct {
	External      int      `json:"external"`
	Appliance     int      `json:"appliance"`
	Both          int      `json:"both"`
	ExternalOnly  []string `json:"external_only"`
	ApplianceOnly []string `json:"appliance_only"`
}

type ParityCounts struct {
	Both          int `json:"both"`
	ExternalOnly  int `json:"external_only"`
	ApplianceOnly int `json:"appliance_only"`
}

type ParityItem struct {
	CVE        string `json:"cve"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Hosts      int    `json:"hosts"`
	Detector   string `json:"detector,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

// AdminSummary is the vulnerability summary a report starts from: open
// findings by severity, SLA ageing, recent movement, risk points and the
// top open findings; the vendor form rolls its sites up.
type AdminSummary struct {
	SiteID         string           `json:"site_id,omitempty"`
	VendorID       string           `json:"vendor_id,omitempty"`
	Name           string           `json:"name,omitempty"`
	Hosts          SummaryHosts     `json:"hosts"`
	Open           map[string]int   `json:"open"`
	Overdue        map[string]int   `json:"overdue"`
	NewLast30      int              `json:"new_last_30d"`
	FixedLast30    int              `json:"fixed_last_30d"`
	ReopenedLast30 int              `json:"reopened_last_30d"`
	MeanAgeDays    float64          `json:"mean_age_days"`
	OldestDays     int              `json:"oldest_days"`
	RiskPoints     int              `json:"risk_points"`
	Coverage       int              `json:"coverage_score"`
	SLADays        map[string]int   `json:"sla_days"`
	Top            []SummaryFinding `json:"top"`
	LastInventory  *time.Time       `json:"last_inventory,omitempty"`
	LastFull       *time.Time       `json:"last_full,omitempty"`
	Sites          []AdminSummary   `json:"sites,omitempty"`
	ComputedAt     time.Time        `json:"computed_at"`
}

type SummaryHosts struct {
	Total            int `json:"total"`
	NetworkVisible   int `json:"network_visible"`
	WithOpenFindings int `json:"with_open_findings"`
}

type SummaryFinding struct {
	ID       string   `json:"id"`
	HostID   string   `json:"host_id"`
	HostIP   string   `json:"host_ip"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	CVE      []string `json:"cve"`
	DaysOpen int      `json:"days_open"`
	Overdue  bool     `json:"overdue"`
}

// AdminTrendPoint is one week of the finding trend.
type AdminTrendPoint struct {
	WeekStart      time.Time      `json:"week_start"`
	Open           int            `json:"open"`
	New            int            `json:"new"`
	Fixed          int            `json:"fixed"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
}

// Webhooks: signed outbound events for ticketing and chat integrations.
type AdminWebhookRequest struct {
	URL     string   `json:"url"`
	Secret  string   `json:"secret,omitempty"`
	Events  []string `json:"events"` // exact names or prefixes ending in "*"; empty = all
	Enabled *bool    `json:"enabled,omitempty"`
}

type AdminWebhookView struct {
	ID           string                `json:"id"`
	URL          string                `json:"url"`
	Events       []string              `json:"events"`
	Enabled      bool                  `json:"enabled"`
	HasSecret    bool                  `json:"has_secret"`
	CreatedAt    time.Time             `json:"created_at"`
	LastDelivery *AdminWebhookDelivery `json:"last_delivery,omitempty"`
}

type AdminWebhookDelivery struct {
	ID       string    `json:"id"`
	Event    string    `json:"event"`
	At       time.Time `json:"at"`
	Status   int       `json:"status"`
	Attempts int       `json:"attempts"`
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
}

// WebhookEvent is the body a webhook receives.
type WebhookEvent struct {
	ID          string    `json:"id"`
	Event       string    `json:"event"`
	At          time.Time `json:"at"`
	SiteID      string    `json:"site_id,omitempty"`
	ApplianceID string    `json:"appliance_id,omitempty"`
	JobID       string    `json:"job_id,omitempty"`
	Data        any       `json:"data"`
}

// AdminRetentionResult reports one retention pass.
type AdminRetentionResult struct {
	DryRun         bool      `json:"dry_run"`
	Before         time.Time `json:"before"`
	RawBatches     int       `json:"raw_result_batches"`
	SupportBundles int       `json:"support_bundles"`
	Errors         int       `json:"errors"`
}
