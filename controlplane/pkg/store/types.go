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
}

// Host is the shared host model (PLAN §12.2): one row per physical host
// per site, fed by the appliance, the agent track, or both.
type Host struct {
	ID        string
	SiteID    string
	IP        string
	MAC       string
	Hostname  string
	Source    string // agent | appliance | both
	AgentID   string
	OSGuess   *v1.OSGuess
	Ports     []v1.Port
	Notes     []string
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
}

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
	Hosts    int
	Created  int
	Merged   int
	Findings int
}

// Config renders the site as the appliance sees it.
func (s *Site) Config() v1.SiteConfig {
	c := v1.SiteConfig{AllowedCIDRs: append([]string{}, s.AllowedCIDRs...), Excludes: append([]string{}, s.Excludes...),
		FragilePorts: append([]int{}, s.FragilePorts...), TZ: s.TZ, MaxPPS: s.MaxPPS, MaxConcurrency: s.MaxConcurrency,
		UnsafeOK: s.UnsafeOK, AllowPublic: s.AllowPublic}
	if c.AllowedCIDRs == nil {
		c.AllowedCIDRs = []string{}
	}
	return c
}
