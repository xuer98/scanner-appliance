package store

import "time"

// Phase 4 records (PLAN §10.6 versioned policy, §16 scope approval, §17.4
// job calendar, §22 false-positive lifecycle).

// SiteChange is one audit-log entry; Version is the site policy version
// after the change.
type SiteChange struct {
	ID      string
	SiteID  string
	Version int
	At      time.Time
	Actor   string
	Kind    string // scope | policy | exclusion | attest | fragile
	Field   string
	Old     string
	New     string
	Reason  string
}

// ScopeRequest is a pending change of allowed_cidrs awaiting the vendor
// owner's approval.
type ScopeRequest struct {
	ID           string
	SiteID       string
	Status       string
	AllowedCIDRs []string
	Reason       string
	RequestedAt  time.Time
	RequestedBy  string
	DecidedAt    *time.Time
	DecidedBy    string
	Decision     string
}

// Schedule is a recurring scan; the scheduler creates one job per
// occurrence and remembers the one it created last.
type Schedule struct {
	ID             string
	SiteID         string
	ApplianceID    string
	Name           string
	Mode           string
	Targets        []string
	Excludes       []string
	Ports          string
	Modules        []string // Phase 5: explicit module set; empty = mode default
	Cron           string
	TZ             string
	MaxDurationS   int
	Enabled        bool
	NextOccurrence *time.Time
	NextJobID      string
	LastJobID      string
	CreatedAt      time.Time
}
