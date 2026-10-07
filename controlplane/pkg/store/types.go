package store

import (
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Job is one scheduled scan (PLAN §17.1).
type Job struct {
	ID           string
	SiteID       string
	ApplianceID  string
	Status       string
	Spec         v1.JobSpec
	ScheduledFor *time.Time
	DispatchedAt *time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
	ProgressPct  int
	Phase        string
	RejectReason string
	Batches      int
	Stats        *v1.ScanStats
	CreatedAt    time.Time
	ScheduleID   string // set when created by a schedule (Phase 4)
}

// Terminal reports whether the job can no longer change.
func (j *Job) Terminal() bool {
	switch j.Status {
	case v1.JobDone, v1.JobFailed, v1.JobRejected, v1.JobCancelled:
		return true
	}
	return false
}

// ResultBatchRec is one received chunk.
type ResultBatchRec struct {
	JobID      string
	Seq        int
	ReceivedAt time.Time
	ObjectKey  string
	SHA256     string
	Final      bool
	Hosts      int
	Purged     bool // raw object deleted by retention (Phase 6)
}

// SupportBundleRec is one uploaded support bundle.
type SupportBundleRec struct {
	ID          int64
	ApplianceID string
	At          time.Time
	ObjectKey   string
	Bytes       int64
	Purged      bool
}

// ScanIngest is one result chunk with the scope of the job that produced
// it (the openvas config name; findings inherit it as their lifecycle
// scope).
type ScanIngest struct {
	SiteID      string
	JobID       string
	Hosts       []v1.Host
	FeedVersion string
	At          time.Time
	Scope       string
}

// FindingRef is a compact finding reference for events.
type FindingRef struct {
	ID       string   `json:"id"`
	HostID   string   `json:"host_id"`
	HostIP   string   `json:"host_ip"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	CVE      []string `json:"cve"`
	Detector string   `json:"detector,omitempty"`
}

// Host is the shared host model (PLAN §12.2): one row per physical host
// per site, fed by the appliance, the agent track, or both.
type Host struct {
	ID       string
	SiteID   string
	IP       string
	MAC      string
	Hostname string
	Source   string // agent | appliance | both
	AgentID  string
	OSGuess  *v1.OSGuess
	Ports    []v1.Port
	Notes    []string
	// CPEs is the appliance's product inventory for the host (v1.Host.CPEs).
	CPEs      []string
	AgentOS   string
	Packages  []v1.AgentPackage
	LastJobID string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Finding is one issue on a host with its evidence trail.
type Finding struct {
	ID          string
	HostID      string
	Source      string // agent | openvas | nuclei | both
	State       string // confirmed | network_observed | suspected
	NVTOID      string
	TemplateID  string // nuclei template id (web add-on)
	Name        string
	Family      string
	Severity    string
	CVSS        float64
	CVE         []string
	QoD         int
	Port        int
	Proto       string
	Solution    string
	Evidence    []v1.Evidence
	FeedVersion string
	FirstSeen   time.Time
	LastSeen    time.Time
	// Human review (Phase 4): "" | false_positive | accepted.
	Review       string
	ReviewedAt   *time.Time
	ReviewedBy   string
	ReviewReason string
	// Lifecycle (Phase 6): open | fixed, the scope that can resolve it
	// (inventory | full | web | <scanner>), and the external scanner's id.
	Status     string
	FixedAt    *time.Time
	ReopenedAt *time.Time
	Reopens    int
	Scope      string
	ExternalID string
}

// IsOpen reports whether the finding is open (an empty status is open:
// rows that predate the lifecycle columns).
func (f *Finding) IsOpen() bool { return f.Status == "" || f.Status == v1.FindingOpen }

// NetworkScanner reports whether the finding's source is one of the
// appliance's own scanners, the only sources the lifecycle resolves.
func (f *Finding) NetworkScanner() bool { return f.Source == "openvas" || f.Source == "nuclei" }

// Detector is the finding's detector identity for exclusions and tuning.
func (f *Finding) Detector() string { return findingIdent(f.NVTOID, f.TemplateID) }

// NVT mirrors VT metadata for portal display (PLAN §17.1).
type NVT struct {
	OID         string
	Name        string
	Family      string
	CVSS        float64
	CVEs        []string
	QoD         int
	Solution    string
	FeedVersion string
}

// IngestSummary reports what an ingest changed.
type IngestSummary struct {
	Hosts      int
	Created    int
	Merged     int
	Findings   int
	Suppressed int
	// Absorbed counts host records folded into another one because they
	// described the same address and had no identity of their own.
	Absorbed int
	// Phase 6: findings created by this ingest (NewBySeverity counts all,
	// New lists the high and critical ones, capped), findings an external
	// import marked fixed, and rows skipped as informational.
	NewFindings   int
	NewBySeverity map[string]int
	New           []FindingRef
	Fixed         int
	Skipped       int
}

// Config renders the site as the appliance sees it.
func (s *Site) Config() v1.SiteConfig {
	c := v1.SiteConfig{AllowedCIDRs: append([]string{}, s.AllowedCIDRs...), Excludes: append([]string{}, s.Excludes...),
		FragilePorts: append([]int{}, s.FragilePorts...), TZ: s.TZ, MaxPPS: s.MaxPPS, MaxConcurrency: s.MaxConcurrency,
		UnsafeOK: s.UnsafeOK, AllowPublic: s.AllowPublic, LANRoutes: append([]v1.LANRoute{}, s.LANRoutes...),
		FragileCleared: append([]string{}, s.FragileCleared...), FragileHosts: append([]string{}, s.FragileHosts...),
		VTExcludes: append([]string{}, s.VTExcludes...), Version: s.Version}
	if c.AllowedCIDRs == nil {
		c.AllowedCIDRs = []string{}
	}
	if len(c.LANRoutes) == 0 {
		c.LANRoutes = nil
	}
	for _, p := range []*[]string{&c.FragileCleared, &c.FragileHosts, &c.VTExcludes} {
		if len(*p) == 0 {
			*p = nil
		}
	}
	return c
}

// IngestSummary Suppressed counts findings that arrived despite a site
// exclusion and were stored as reviewed false positives.
