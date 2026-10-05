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

// BulkSource is a Source that can also return many VTs from one pass over
// the feed; an OID the feed does not carry is absent from the map. On
// error the map holds what was read before it.
type BulkSource interface {
	GetVTs(ctx context.Context, oids []string) (map[string]*osp.VT, error)
}

// bulkMin is the number of uncached OIDs from which one pass over the feed
// is cheaper than single lookups. Measured on ospd-openvas 22.10 with the
// 95,000-test community feed: about 4.7 s per single lookup, because ospd
// walks the whole feed in redis for each, against about 34 s for the pass.
const bulkMin = 8

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

// Lookup returns metadata for every OID, fetching misses from the source:
// one at a time for a few, in one pass over the feed from bulkMin on when
// the source can do that. Unknown OIDs get a Missing entry. Fetch errors
// are returned after the rest is done (the caller logs and carries on with
// partial metadata); already-cached entries are still returned.
func (c *Cache) Lookup(ctx context.Context, feedVersion string, oids []string) (map[string]*Meta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load(feedVersion)
	out := make(map[string]*Meta, len(oids))
	var misses []string
	asked := map[string]bool{}
	for _, oid := range oids {
		if m, ok := c.entries[oid]; ok {
			out[oid] = m
		} else if !asked[oid] {
			asked[oid] = true
			misses = append(misses, oid)
		}
	}
	var firstErr error
	bulk, canBulk := c.Source.(BulkSource)
	switch {
	case len(misses) == 0:
	case c.Source == nil:
		firstErr = errors.New("nvt: no metadata source")
	case canBulk && len(misses) >= bulkMin:
		vts, err := bulk.GetVTs(ctx, misses)
		firstErr = err
		for _, oid := range misses {
			vt, found := vts[oid]
			if !found && err != nil {
				continue // a pass that broke off says nothing about this OID
			}
			out[oid] = c.put(oid, vt)
		}
	default:
		for _, oid := range misses {
			vt, err := c.Source.GetVT(ctx, oid)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			out[oid] = c.put(oid, vt)
		}
	}
	if c.dirty {
		if err := c.save(); err != nil {
			c.Log.Warn("nvt cache save", "err", err)
		}
	}
	return out, firstErr
}

// put caches one fetched VT; nil is an OID the feed does not know.
func (c *Cache) put(oid string, vt *osp.VT) *Meta {
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
	return m
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
