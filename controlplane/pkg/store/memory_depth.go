package store

import "context"

func (m *Memory) ensurePhase5() {
	if m.settings == nil {
		m.settings = map[string]string{}
	}
}

func (m *Memory) GetSetting(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase5()
	v, ok := m.settings[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (m *Memory) PutSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase5()
	m.settings[key] = value
	return nil
}

func (m *Memory) DeleteSetting(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurePhase5()
	if _, ok := m.settings[key]; !ok {
		return ErrNotFound
	}
	delete(m.settings, key)
	return nil
}
