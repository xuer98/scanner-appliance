package store

import (
	"context"
	"sort"
	"sync"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Memory is the in-memory Store used by --dev and tests.
type Memory struct {
	mu          sync.Mutex
	vendors     map[string]*Vendor
	sites       map[string]*Site
	appliances  map[string]*Appliance
	codes       map[string]*EnrollmentCode // by hash
	directives  map[string]*Directive
	revoked     map[string]string
	attempts    []EnrollAttempt
	heartbeats  map[string][]v1.Heartbeat
	supportLogs []string
}

func NewMemory() *Memory {
	return &Memory{
		vendors: map[string]*Vendor{}, sites: map[string]*Site{}, appliances: map[string]*Appliance{},
		codes: map[string]*EnrollmentCode{}, directives: map[string]*Directive{}, revoked: map[string]string{},
		heartbeats: map[string][]v1.Heartbeat{},
	}
}

func (m *Memory) Close() error { return nil }

func (m *Memory) EnsureVendor(_ context.Context, name string) (*Vendor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.vendors {
		if v.Name == name {
			return v, nil
		}
	}
	v := &Vendor{ID: NewID("vnd"), Name: name, Tier: 3}
	m.vendors[v.ID] = v
	return v, nil
}

func (m *Memory) EnsureSite(_ context.Context, vendorID, name string, cidrs []string, tz string, maxPPS int) (*Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.vendors[vendorID]; !ok {
		return nil, ErrNotFound
	}
	for _, s := range m.sites {
		if s.VendorID == vendorID && s.Name == name {
			if len(cidrs) > 0 {
				s.AllowedCIDRs = cidrs
			}
			if tz != "" {
				s.TZ = tz
			}
			if maxPPS > 0 {
				s.MaxPPS = maxPPS
			}
			return s, nil
		}
	}
	if tz == "" {
		tz = "UTC"
	}
	if maxPPS == 0 {
		maxPPS = 300
	}
	s := &Site{ID: NewID("site"), VendorID: vendorID, Name: name, AllowedCIDRs: cidrs, TZ: tz, MaxPPS: maxPPS,
		FragilePorts: []int{9100, 515, 631, 161, 502, 44818}}
	m.sites[s.ID] = s
	return s, nil
}

func (m *Memory) GetSite(_ context.Context, id string) (*Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sites[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *s
	return &c, nil
}

func (m *Memory) CreateAppliance(_ context.Context, siteID string) (*Appliance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sites[siteID]; !ok {
		return nil, ErrNotFound
	}
	a := &Appliance{ID: NewID("apl"), SiteID: siteID, Status: v1.StatusPending, CreatedAt: time.Now(), BinaryHashes: map[string]string{}}
	m.appliances[a.ID] = a
	c := *a
	return &c, nil
}

func (m *Memory) GetAppliance(_ context.Context, id string) (*Appliance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appliances[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *a
	return &c, nil
}

func (m *Memory) GetApplianceBySerial(_ context.Context, serial string) (*Appliance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.appliances {
		if a.CertSerial == serial && serial != "" {
			c := *a
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListAppliances(_ context.Context) ([]*Appliance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Appliance, 0, len(m.appliances))
	for _, a := range m.appliances {
		c := *a
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) SetStatus(_ context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appliances[id]
	if !ok {
		return ErrNotFound
	}
	a.Status = status
	return nil
}

func (m *Memory) UpdateCert(_ context.Context, id, serial string, notAfter time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appliances[id]
	if !ok {
		return ErrNotFound
	}
	a.CertSerial = serial
	a.CertNotAfter = &notAfter
	return nil
}

func (m *Memory) RecordHeartbeat(_ context.Context, id string, at time.Time, hb *v1.Heartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appliances[id]
	if !ok {
		return ErrNotFound
	}
	t := at
	a.LastHeartbeatAt = &t
	cp := *hb
	a.LastHeartbeat = &cp
	a.Version = hb.Version
	a.BundleVersion = hb.BundleVersion
	a.Ifaces = hb.Ifaces
	a.SkewS = hb.SkewS
	if hb.BinarySHA256 != nil {
		a.BinaryHashes = hb.BinarySHA256
	}
	m.heartbeats[id] = append(m.heartbeats[id], cp)
	if len(m.heartbeats[id]) > 1000 {
		m.heartbeats[id] = m.heartbeats[id][len(m.heartbeats[id])-1000:]
	}
	return nil
}

func (m *Memory) PutEnrollmentCode(_ context.Context, c EnrollmentCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appliances[c.ApplianceID]; !ok {
		return ErrNotFound
	}
	// One live code per appliance: drop any previous.
	for h, old := range m.codes {
		if old.ApplianceID == c.ApplianceID {
			delete(m.codes, h)
		}
	}
	cc := c
	m.codes[c.CodeHash] = &cc
	return nil
}

func (m *Memory) GetEnrollmentCodeByHash(_ context.Context, hash string) (*EnrollmentCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[hash]
	if !ok {
		return nil, ErrNotFound
	}
	cc := *c
	return &cc, nil
}

func (m *Memory) BumpCodeAttempts(_ context.Context, hash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[hash]
	if !ok {
		return 0, ErrNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (m *Memory) CompleteEnrollment(_ context.Context, u EnrollUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[u.CodeHash]
	if !ok || c.ApplianceID != u.ApplianceID {
		return ErrNotFound
	}
	if c.UsedAt != nil {
		return ErrConflict
	}
	a, ok := m.appliances[u.ApplianceID]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	c.UsedAt = &now
	a.Status = v1.StatusEnrolled
	a.CertSerial = u.CertSerial
	na := u.CertNotAfter
	a.CertNotAfter = &na
	a.Version = u.Version
	fp := u.Fingerprint
	a.Fingerprint = &fp
	a.EnrolledAt = &now
	return nil
}

func (m *Memory) LogEnrollAttempt(_ context.Context, a EnrollAttempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts = append(m.attempts, a)
	return nil
}

func (m *Memory) CreateDirective(_ context.Context, applianceID, typ string, payload map[string]any) (*Directive, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appliances[applianceID]; !ok {
		return nil, ErrNotFound
	}
	if payload == nil {
		payload = map[string]any{}
	}
	d := &Directive{ID: NewID("dir"), ApplianceID: applianceID, Type: typ, Payload: payload, CreatedAt: time.Now()}
	m.directives[d.ID] = d
	c := *d
	return &c, nil
}

func (m *Memory) PendingDirectives(_ context.Context, applianceID string, markDelivered bool) ([]Directive, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Directive
	now := time.Now()
	for _, d := range m.directives {
		if d.ApplianceID == applianceID && d.AckedAt == nil {
			if markDelivered && d.DeliveredAt == nil {
				t := now
				d.DeliveredAt = &t
			}
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) AckDirectives(_ context.Context, applianceID string, ids []string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if d, ok := m.directives[id]; ok && d.ApplianceID == applianceID && d.AckedAt == nil {
			t := at
			d.AckedAt = &t
		}
	}
	return nil
}

func (m *Memory) ListDirectives(_ context.Context, applianceID string) ([]Directive, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Directive
	for _, d := range m.directives {
		if d.ApplianceID == applianceID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) Revoke(_ context.Context, serial, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[serial] = reason
	return nil
}

func (m *Memory) IsRevoked(_ context.Context, serial string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[serial]
	return ok, nil
}

func (m *Memory) RecordSupportBundle(_ context.Context, applianceID, objectKey string, _ int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appliances[applianceID]; !ok {
		return ErrNotFound
	}
	m.supportLogs = append(m.supportLogs, objectKey)
	return nil
}
