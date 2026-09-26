package nvt

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

// Meta is the normalized metadata for one OID.
type Meta struct {
	OID      string   `json:"oid"`
	Name     string   `json:"name"`
	Family   string   `json:"family"`
	CVSS     float64  `json:"cvss"`
	CVEs     []string `json:"cves"`
	QoD      int      `json:"qod"`
	QoDType  string   `json:"qod_type"`
	Solution string   `json:"solution,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	// Missing marks an OID the feed does not know (cached so it is not
	// re-fetched every scan).
	Missing bool `json:"missing,omitempty"`
}

// Source fetches one VT (the OSP client in production).
type Source interface {
	GetVT(ctx context.Context, oid string) (*osp.VT, error)
}

// Cache is a per-feed-version map persisted as JSON under Dir.
type Cache struct {
	Dir    string
	Source Source
	Log    *slog.Logger

	mu      sync.Mutex
	version string
	entries map[string]*Meta
	dirty   bool
}

// New returns a cache rooted at dir (created on first save).
func New(dir string, src Source, log *slog.Logger) *Cache {
	if log == nil {
		log = slog.Default()
	}
	return &Cache{Dir: dir, Source: src, Log: log, entries: map[string]*Meta{}}
}

func (c *Cache) path(version string) string {
	return filepath.Join(c.Dir, "nvt-"+sanitize(version)+".json")
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '.' || ch == '-' || ch == '_' {
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// load switches the in-memory map to the given feed version.
func (c *Cache) load(version string) {
	if c.version == version {
		return
	}
	c.version = version
	c.entries = map[string]*Meta{}
	c.dirty = false
	b, err := os.ReadFile(c.path(version))
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &c.entries)
}

// Lookup returns metadata for every OID, fetching misses from the source.
// Unknown OIDs get a Missing entry. Fetch errors abort (the caller retries
// the whole job phase); already-cached entries are still returned.
func (c *Cache) Lookup(ctx context.Context, feedVersion string, oids []string) (map[string]*Meta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load(feedVersion)
	out := make(map[string]*Meta, len(oids))
	var firstErr error
	for _, oid := range oids {
		if m, ok := c.entries[oid]; ok {
			out[oid] = m
			continue
		}
		if c.Source == nil {
			firstErr = errors.New("nvt: no metadata source")
			continue
		}
		vt, err := c.Source.GetVT(ctx, oid)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		m := &Meta{OID: oid, Missing: true}
		if vt != nil {
			m = &Meta{OID: oid, Name: vt.Name, Family: vt.Family, CVEs: vt.CVEs, QoD: vt.QoD, QoDType: vt.QoDType,
				Solution: vt.Solution, Summary: vt.Summary, CVSS: Score(vt.CVSSv3Vector, vt.CVSSv2Vector, vt.CVSSBase)}
			if m.CVEs == nil {
				m.CVEs = []string{}
			}
		}
		c.entries[oid] = m
		c.dirty = true
		out[oid] = m
	}
	if c.dirty {
		if err := c.save(); err != nil {
			c.Log.Warn("nvt cache save", "err", err)
		}
	}
	return out, firstErr
}

func (c *Cache) save() error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	tmp := c.path(c.version) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	c.dirty = false
	return os.Rename(tmp, c.path(c.version))
}

// Len reports cached entries (tests).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// UniqueOIDs de-duplicates and sorts.
func UniqueOIDs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
