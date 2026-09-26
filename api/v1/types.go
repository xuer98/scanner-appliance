// Package v1 holds the wire types shared by applianced and cp-api.
// Every request and response on /v1/* is defined here so both sides
// compile against one definition.
package v1

import "time"

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

// SiteConfig is what an appliance is allowed to touch.
type SiteConfig struct {
	AllowedCIDRs []string `json:"allowed_cidrs"`
	TZ           string   `json:"tz"`
	MaxPPS       int      `json:"max_pps,omitempty"`
}

// EnrollResponse is returned on successful enrollment and renewal.
type EnrollResponse struct {
	ApplianceID   string     `json:"appliance_id"`
	CertPEM       string     `json:"cert_pem"`
	ChainPEM      string     `json:"chain_pem"`
	CPURL         string     `json:"cp_url"`
	PollIntervalS int        `json:"poll_interval_s"`
	Site          SiteConfig `json:"site"`
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

// Heartbeat is the body of POST /v1/appliances/{id}/heartbeat.
type Heartbeat struct {
	Version           string            `json:"version"`
	BundleVersion     string            `json:"bundle_version"`
	UptimeS           int64             `json:"uptime_s"`
	Load1             float64           `json:"load1"`
	DiskFreeMB        int64             `json:"disk_free_mb"`
	Ifaces            []Iface           `json:"ifaces"`
	BinarySHA256      map[string]string `json:"binary_sha256"`
	PendingResults    int               `json:"pending_results"`
	CurrentJobID      *string           `json:"current_job_id"`
	ClockEpoch        int64             `json:"clock_epoch"`
	AckedDirectiveIDs []string          `json:"acked_directive_ids"`
	// State is the daemon state machine value (idle, scanning, ...).
	State string `json:"state"`
	// SkewS is the last measured clock skew against server_epoch.
	SkewS int64 `json:"skew_s"`
	// Engine is the detection-engine health (PLAN v1.1 §20 Phase 1: ospd_up, vt_cache_loaded).
	Engine EngineHealth `json:"engine"`
}

// EngineHealth reports the embedded openvas stack. Phase 1 only probes it;
// Phase 2 drives scans over the same socket.
type EngineHealth struct {
	OSPDUp         bool   `json:"ospd_up"`
	VTCacheLoaded  bool   `json:"vt_cache_loaded"`
	VTCount        int    `json:"vt_count"`
	OpenVASVersion string `json:"openvas_version,omitempty"`
	OSPDVersion    string `json:"ospd_version,omitempty"`
	Error          string `json:"error,omitempty"`
}

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
)

// KnownDirectives is the closed allowlist checked on both sides.
var KnownDirectives = map[string]bool{
	DirectiveNoop: true, DirectiveSetInterval: true, DirectiveStopAll: true,
	DirectiveUpdateDaemon: true, DirectiveUpdateBundle: true, DirectiveRenewCert: true,
	DirectiveWipe: true, DirectiveRunJobNow: true,
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

// Admin API types (/admin/*, portal SSO or bearer token).

type AdminCreateApplianceRequest struct {
	Vendor       string   `json:"vendor"`
	Site         string   `json:"site"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
	TZ           string   `json:"tz,omitempty"`
	MaxPPS       int      `json:"max_pps,omitempty"`
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
	CertSerial      string       `json:"cert_serial,omitempty"`
	CertNotAfter    *time.Time   `json:"cert_not_after,omitempty"`
	LastHeartbeatAt *time.Time   `json:"last_heartbeat_at"`
	LastHeartbeat   *Heartbeat   `json:"last_heartbeat,omitempty"`
	SkewS           int64        `json:"skew_s"`
	Ifaces          []Iface      `json:"ifaces"`
	Fingerprint     *Fingerprint `json:"fingerprint,omitempty"`
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
