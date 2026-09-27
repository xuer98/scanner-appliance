package store

import (
	"context"
	"testing"
	"time"
)

// UpdateJobStatusForTest sets a job's terminal status and finish time; it
// exists for tests that need scan history without running an appliance.
func (m *Memory) UpdateJobStatusForTest(t testing.TB, id, status string, finishedAt time.Time) {
	t.Helper()
	j, err := m.GetJob(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	j.Status = status
	j.FinishedAt = &finishedAt
	if err := m.UpdateJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
}
