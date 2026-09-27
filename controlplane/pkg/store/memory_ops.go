package store

import (
	"context"
	"sort"
)

func (m *Memory) ensurePhase3() {
	if m.bundles == nil {
		m.bundles = map[string]*Bundle{}
		m.bundleFiles = map[string]BundleFileRec{}
		m.releases = map[string]*Release{}
	}
}

func releaseKey(component, version string) string { return component + "@" + version }

func (m *Memory) PutBundle(_ context.Context, b *Bundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	c := *b
	m.bundles[b.Version] = &c
	return nil
}

func (m *Memory) GetBundle(_ context.Context, version string) (*Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	b, ok := m.bundles[version]
	if !ok {
		return nil, ErrNotFound
	}
	c := *b
	return &c, nil
}

func (m *Memory) ListBundles(_ context.Context) ([]*Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	out := make([]*Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		c := *b
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].PublishedAt.Equal(out[j].PublishedAt) {
			return out[i].PublishedAt.After(out[j].PublishedAt)
		}
		return out[i].Version > out[j].Version
	})
	return out, nil
}

func (m *Memory) SetBundleStatus(_ context.Context, version, status, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	b, ok := m.bundles[version]
	if !ok {
		return ErrNotFound
	}
	b.Status, b.HeldReason = status, reason
	return nil
}

func (m *Memory) PutBundleFiles(_ context.Context, files []BundleFileRec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	for _, f := range files {
		m.bundleFiles[f.SHA256] = f
	}
	return nil
}

func (m *Memory) HasBundleFiles(_ context.Context, sha256 []string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	out := make(map[string]bool, len(sha256))
	for _, s := range sha256 {
		_, ok := m.bundleFiles[s]
		out[s] = ok
	}
	return out, nil
}

func (m *Memory) PutRelease(_ context.Context, r *Release) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	c := *r
	m.releases[releaseKey(r.Component, r.Version)] = &c
	return nil
}

func (m *Memory) GetRelease(_ context.Context, component, version string) (*Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	r, ok := m.releases[releaseKey(component, version)]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *Memory) ListReleases(_ context.Context) ([]*Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	out := make([]*Release, 0, len(m.releases))
	for _, r := range m.releases {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].PublishedAt.Equal(out[j].PublishedAt) {
			return out[i].PublishedAt.After(out[j].PublishedAt)
		}
		return releaseKey(out[i].Component, out[i].Version) > releaseKey(out[j].Component, out[j].Version)
	})
	return out, nil
}

func (m *Memory) SetReleaseStatus(_ context.Context, component, version, status, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase3()
	r, ok := m.releases[releaseKey(component, version)]
	if !ok {
		return ErrNotFound
	}
	r.Status, r.HeldReason = status, reason
	return nil
}

func (m *Memory) SetApplianceCanary(_ context.Context, id string, canary bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appliances[id]
	if !ok {
		return ErrNotFound
	}
	a.Canary = canary
	return nil
}
