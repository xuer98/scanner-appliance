package store

import (
	"context"
	"sort"
	"strconv"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func (m *Memory) ensurePhase6() {
	if m.locks == nil {
		m.locks = map[string]bool{}
	}
}

func (m *Memory) ResolveFindings(_ context.Context, siteID, jobID string, scopes []string, before, at time.Time) ([]*Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	set := resolveScopes(scopes)
	var out []*Finding
	for hostID := range m.jobHosts[jobID] {
		h, ok := m.hosts[hostID]
		if !ok || h.SiteID != siteID || fragileKeptAway(h.Notes) {
			continue
		}
		for _, f := range m.findings {
			if f.HostID != hostID || !f.IsOpen() || !f.NetworkScanner() || !set[f.Scope] || !f.LastSeen.Before(before) {
				continue
			}
			f.Status = v1.FindingFixed
			t := at
			f.FixedAt = &t
			out = append(out, copyFinding(f))
		}
	}
	sortFindings(out)
	return out, nil
}

func (m *Memory) IngestExternal(_ context.Context, siteID, scanner string, hosts []v1.ExternalHost, at time.Time) (IngestSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	if _, ok := m.sites[siteID]; !ok {
		return IngestSummary{}, ErrNotFound
	}
	ix := m.siteIndex(siteID)
	sum := ix.ingestExternal(scanner, hosts, at)
	m.commit(ix)
	return sum, nil
}

func (m *Memory) ListResultBatches(_ context.Context, before time.Time, limit int) ([]ResultBatchRec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	var out []ResultBatchRec
	for _, b := range m.batches {
		if !b.Purged && b.ReceivedAt.Before(before) {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.Before(out[j].ReceivedAt)
		}
		return out[i].JobID+"/"+fmtInt(out[i].Seq) < out[j].JobID+"/"+fmtInt(out[j].Seq)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func fmtInt(i int) string { return strconv.Itoa(i) }

func (m *Memory) MarkResultBatchPurged(_ context.Context, jobID string, seq int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	key := jobID + "/" + fmtInt(seq)
	b, ok := m.batches[key]
	if !ok {
		return ErrNotFound
	}
	b.Purged = true
	return nil
}

func (m *Memory) ListSupportBundles(_ context.Context, before time.Time, limit int) ([]SupportBundleRec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SupportBundleRec
	for _, b := range m.supportLogs {
		if !b.Purged && b.At.Before(before) {
			out = append(out, *b)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) MarkSupportBundlePurged(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.supportLogs {
		if b.ID == id {
			b.Purged = true
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) TryLock(_ context.Context, name string) (func(), bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase6()
	if m.locks[name] {
		return nil, false, nil
	}
	m.locks[name] = true
	return func() {
		m.mu.Lock()
		delete(m.locks, name)
		m.mu.Unlock()
	}, true, nil
}
