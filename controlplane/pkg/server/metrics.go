package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Metrics (Phase 6): Prometheus text exposition without a client library.
// Counters live in the process; gauges are computed from the store at
// scrape time and cached briefly.
type Metrics struct {
	heartbeats    atomic.Int64
	resultChunks  atomic.Int64
	findingsNew   atomic.Int64
	findingsFixed atomic.Int64
	jobsDone      atomic.Int64
	jobsFailed    atomic.Int64
	webhookOK     atomic.Int64
	webhookFail   atomic.Int64
	started       time.Time

	mu      sync.Mutex
	cached  string
	cacheAt time.Time
}

func newMetrics(now time.Time) *Metrics { return &Metrics{started: now} }

// metricsCacheTTL bounds how often a scrape recomputes the store gauges.
const metricsCacheTTL = 30 * time.Second

func (s *Server) renderMetrics(ctx context.Context) string {
	m := s.metrics
	now := s.cfg.Now()
	m.mu.Lock()
	if m.cached != "" && now.Sub(m.cacheAt) < metricsCacheTTL {
		out := m.cached
		m.mu.Unlock()
		return out
	}
	m.mu.Unlock()

	var b strings.Builder
	line := func(name, help, typ string, rows map[string]int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		keys := make([]string, 0, len(rows))
		for k := range rows {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(&b, "%s %d\n", name, rows[k])
			} else {
				fmt.Fprintf(&b, "%s{%s} %d\n", name, k, rows[k])
			}
		}
	}
	line("cp_build_info", "control plane version", "gauge", map[string]int64{fmt.Sprintf("version=%q", s.cfg.Version): 1})
	line("cp_uptime_seconds", "seconds since start", "gauge", map[string]int64{"": int64(now.Sub(m.started) / time.Second)})
	line("cp_heartbeats_total", "heartbeats received", "counter", map[string]int64{"": m.heartbeats.Load()})
	line("cp_result_chunks_total", "result chunks ingested", "counter", map[string]int64{"": m.resultChunks.Load()})
	line("cp_findings_new_total", "findings created", "counter", map[string]int64{"": m.findingsNew.Load()})
	line("cp_findings_fixed_total", "findings marked fixed", "counter", map[string]int64{"": m.findingsFixed.Load()})
	line("cp_jobs_finished_total", "jobs that reached a terminal state", "counter", map[string]int64{`status="done"`: m.jobsDone.Load(), `status="failed"`: m.jobsFailed.Load()})
	line("cp_webhook_deliveries_total", "webhook deliveries", "counter", map[string]int64{`result="ok"`: m.webhookOK.Load(), `result="failed"`: m.webhookFail.Load()})

	health := map[string]int64{}
	for _, h := range []string{v1.HealthOnline, v1.HealthStale, v1.HealthSilent, v1.HealthDegraded, v1.HealthNever} {
		health[fmt.Sprintf("health=%q", h)] = 0
	}
	if apls, err := s.cfg.Store.ListAppliances(ctx); err == nil {
		for _, a := range apls {
			if a.Status != v1.StatusEnrolled {
				continue
			}
			health[fmt.Sprintf("health=%q", s.health(a, now))]++
		}
	}
	line("cp_appliances", "enrolled appliances by health", "gauge", health)

	open := map[string]int64{}
	for _, sev := range []string{v1.SeverityCritical, v1.SeverityHigh, v1.SeverityMedium, v1.SeverityLow, v1.SeverityInfo} {
		open[fmt.Sprintf("severity=%q", sev)] = 0
	}
	overdue := int64(0)
	if findings, err := s.cfg.Store.ListFindings(ctx, "", ""); err == nil {
		for _, f := range findings {
			if !f.IsOpen() || f.Review == v1.ReviewFalsePositive {
				continue
			}
			open[fmt.Sprintf("severity=%q", f.Severity)]++
			if s.overdue(f, 0, now) {
				overdue++
			}
		}
	}
	line("cp_findings_open", "open findings by severity (false positives excluded)", "gauge", open)
	line("cp_findings_overdue", "open findings past their SLA", "gauge", map[string]int64{"": overdue})

	jobs := map[string]int64{}
	for _, st := range []string{v1.JobQueued, v1.JobDispatched, v1.JobRunning, v1.JobDone, v1.JobFailed, v1.JobRejected, v1.JobCancelled} {
		jobs[fmt.Sprintf("status=%q", st)] = 0
	}
	if list, err := s.cfg.Store.ListJobs(ctx, "", ""); err == nil {
		for _, j := range list {
			jobs[fmt.Sprintf("status=%q", j.Status)]++
		}
	}
	line("cp_jobs", "jobs by status", "gauge", jobs)
	if s.events != nil {
		s.events.mu.Lock()
		dropped := s.events.dropped
		queued := int64(len(s.events.queue))
		s.events.mu.Unlock()
		line("cp_webhook_queue", "webhook deliveries waiting", "gauge", map[string]int64{"": queued})
		line("cp_webhook_dropped_total", "webhook events dropped on a full queue", "counter", map[string]int64{"": dropped})
	}
	out := b.String()
	m.mu.Lock()
	m.cached, m.cacheAt = out, now
	m.mu.Unlock()
	return out
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(s.renderMetrics(r.Context())))
}

// MetricsHandler serves /metrics without authentication for a private
// scrape listener (--metrics-addr); the same data is on /admin/metrics
// behind the admin token.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}
