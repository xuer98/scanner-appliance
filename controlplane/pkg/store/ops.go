package store

import "time"

// Bundle is one published signature bundle (PLAN §13, §17.1).
type Bundle struct {
	Version     string
	FeedVersion string
	ObjectKey   string // manifest object
	SHA256      string // of the manifest bytes
	Sig         string
	Files       int
	Bytes       int64
	Status      string // v1.RolloutCanary | RolloutReleased | RolloutHeld | RolloutRetired
	HeldReason  string
	PublishedAt time.Time
	CanaryUntil *time.Time
	// ConfirmedAt is when a canary appliance first reported the bundle
	// installed. It has to be remembered: with one bundle a day the canaries
	// run a newer one by the time the canary period of this one ends.
	ConfirmedAt *time.Time
}

// BundleFileRec is one content-addressed file in the object store.
type BundleFileRec struct {
	SHA256    string
	Size      int64
	ObjectKey string
}

// Release is one daemon artifact (PLAN §14). Component is
// applianced-<os>-<arch>.
type Release struct {
	Component   string
	Version     string
	ObjectKey   string
	SHA256      string
	Sig         string
	Bytes       int64
	Status      string
	HeldReason  string
	PublishedAt time.Time
	CanaryUntil *time.Time
}
