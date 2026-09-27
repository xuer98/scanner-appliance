package store

import (
	"context"
	"sort"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func (m *Memory) ensurePhase4() {
	if m.siteChanges == nil {
		m.siteChanges = map[string]*SiteChange{}
		m.scopeRequests = map[string]*ScopeRequest{}
		m.schedules = map[string]*Schedule{}
	}
}

func (m *Memory) RecordSiteChange(_ context.Context, c *SiteChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.sites[c.SiteID]; !ok {
		return ErrNotFound
	}
	if c.ID == "" {
		c.ID = NewID("chg")
	}
	cp := *c
	m.siteChanges[c.ID] = &cp
	return nil
}

func (m *Memory) ListSiteChanges(_ context.Context, siteID string) ([]*SiteChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	var out []*SiteChange
	for _, c := range m.siteChanges {
		if c.SiteID == siteID {
			cp := *c
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (m *Memory) CreateScopeRequest(_ context.Context, r *ScopeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.sites[r.SiteID]; !ok {
		return ErrNotFound
	}
	if r.ID == "" {
		r.ID = NewID("scr")
	}
	cp := *r
	m.scopeRequests[r.ID] = &cp
	return nil
}

func (m *Memory) GetScopeRequest(_ context.Context, id string) (*ScopeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	r, ok := m.scopeRequests[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (m *Memory) ListScopeRequests(_ context.Context, siteID, status string) ([]*ScopeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	var out []*ScopeRequest
	for _, r := range m.scopeRequests {
		if (siteID == "" || r.SiteID == siteID) && (status == "" || r.Status == status) {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out, nil
}

func (m *Memory) UpdateScopeRequest(_ context.Context, r *ScopeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.scopeRequests[r.ID]; !ok {
		return ErrNotFound
	}
	cp := *r
	m.scopeRequests[r.ID] = &cp
	return nil
}

func (m *Memory) CreateSchedule(_ context.Context, sc *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.sites[sc.SiteID]; !ok {
		return ErrNotFound
	}
	if _, ok := m.appliances[sc.ApplianceID]; !ok {
		return ErrNotFound
	}
	if sc.ID == "" {
		sc.ID = NewID("sch")
	}
	if sc.CreatedAt.IsZero() {
		sc.CreatedAt = time.Now()
	}
	cp := *sc
	m.schedules[sc.ID] = &cp
	return nil
}

func (m *Memory) GetSchedule(_ context.Context, id string) (*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	sc, ok := m.schedules[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *sc
	return &cp, nil
}

func (m *Memory) ListSchedules(_ context.Context, siteID string) ([]*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	var out []*Schedule
	for _, sc := range m.schedules {
		if siteID == "" || sc.SiteID == siteID {
			cp := *sc
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (m *Memory) UpdateSchedule(_ context.Context, sc *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.schedules[sc.ID]; !ok {
		return ErrNotFound
	}
	cp := *sc
	m.schedules[sc.ID] = &cp
	return nil
}

func (m *Memory) DeleteSchedule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase4()
	if _, ok := m.schedules[id]; !ok {
		return ErrNotFound
	}
	delete(m.schedules, id)
	return nil
}

func (m *Memory) GetFinding(_ context.Context, id string) (*Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	f, ok := m.findings[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyFinding(f), nil
}

func (m *Memory) ReviewFinding(_ context.Context, id, review, by, reason string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	f, ok := m.findings[id]
	if !ok {
		return ErrNotFound
	}
	setReview(f, review, by, reason, at)
	return nil
}

func setReview(f *Finding, review, by, reason string, at time.Time) {
	f.Review, f.ReviewedBy, f.ReviewReason = review, by, reason
	if review == "" {
		f.ReviewedAt = nil
		return
	}
	t := at
	f.ReviewedAt = &t
}

func (m *Memory) ReviewByDetector(_ context.Context, siteID, detector, by, reason string, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase2()
	n := 0
	for _, f := range m.findings {
		h, ok := m.hosts[f.HostID]
		if !ok || h.SiteID != siteID || f.Review != "" || !detectorMatches(f, detector) {
			continue
		}
		setReview(f, v1.ReviewFalsePositive, by, reason, at)
		n++
	}
	return n, nil
}

func detectorMatches(f *Finding, detector string) bool {
	if detector == "" {
		return false
	}
	return f.NVTOID == detector || f.TemplateID == detector || "nuclei:"+f.TemplateID == detector
}

func (m *Memory) GetNVT(_ context.Context, oid string) (*NVT, error) {
	if n := m.NVT(oid); n != nil {
		return n, nil
	}
	return nil, ErrNotFound
}
