package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

// Webhooks (Phase 6): signed outbound events so ticketing and chat get
// fed without polling the admin API. Hooks live in the settings table
// (key "webhooks"); deliveries are HTTP POSTs with an HMAC-SHA256
// signature over "<timestamp>.<body>" and a bounded retry, served by a
// worker that a lost delivery never blocks the request path on.

// Event names.
const (
	EventJobCompleted   = "job.completed"
	EventJobFailed      = "job.failed"
	EventFindingNew     = "finding.new"
	EventFindingsFixed  = "findings.fixed"
	EventAlertRaised    = "alert.raised"
	EventAlertCleared   = "alert.cleared"
	EventScopeRequested = "scope.requested"
	EventSignoffChanged = "signoff.changed"
	EventRolloutHeld    = "rollout.held"
	EventImportDone     = "import.completed"
	EventWebhookTest    = "webhook.test"
)

const (
	webhooksKey        = "webhooks"
	webhookQueueSize   = 4096
	webhookMaxHooks    = 50
	webhookDeliveryLog = 50
)

type webhookRec struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret,omitempty"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type delivery struct {
	hook webhookRec
	ev   v1.WebhookEvent
}

// Dispatcher fans events out to matching hooks.
type Dispatcher struct {
	store   store.Store
	log     logger
	client  *http.Client
	now     func() time.Time
	backoff []time.Duration
	metrics *Metrics

	mu         sync.Mutex
	queue      chan delivery
	cache      []webhookRec
	cacheAt    time.Time
	deliveries map[string][]v1.AdminWebhookDelivery
	dropped    int64
}

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

func newDispatcher(st store.Store, log logger, now func() time.Time, backoff []time.Duration, m *Metrics) *Dispatcher {
	if len(backoff) == 0 {
		backoff = []time.Duration{0, 10 * time.Second, 60 * time.Second}
	}
	return &Dispatcher{store: st, log: log, client: &http.Client{Timeout: 15 * time.Second}, now: now, backoff: backoff, metrics: m,
		queue: make(chan delivery, webhookQueueSize), deliveries: map[string][]v1.AdminWebhookDelivery{}}
}

// Run delivers queued events until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case dl := <-d.queue:
			d.deliver(ctx, dl.hook, dl.ev)
		}
	}
}

func (d *Dispatcher) hooks(ctx context.Context) []webhookRec {
	d.mu.Lock()
	if d.cache != nil && d.now().Sub(d.cacheAt) < 30*time.Second {
		out := d.cache
		d.mu.Unlock()
		return out
	}
	d.mu.Unlock()
	list, err := d.load(ctx)
	if err != nil {
		d.log.Warn("webhooks: load", "err", err)
		return nil
	}
	d.mu.Lock()
	d.cache, d.cacheAt = list, d.now()
	d.mu.Unlock()
	return list
}

func (d *Dispatcher) load(ctx context.Context) ([]webhookRec, error) {
	v, err := d.store.GetSetting(ctx, webhooksKey)
	if errors.Is(err, store.ErrNotFound) {
		return []webhookRec{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []webhookRec
	if err := json.Unmarshal([]byte(v), &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (d *Dispatcher) save(ctx context.Context, list []webhookRec) error {
	b, _ := json.Marshal(list)
	if err := d.store.PutSetting(ctx, webhooksKey, string(b)); err != nil {
		return err
	}
	d.mu.Lock()
	d.cache, d.cacheAt = list, d.now()
	d.mu.Unlock()
	return nil
}

// matches reports whether a hook subscribes to an event: exact names,
// "prefix.*" patterns, or an empty list for everything.
func matches(patterns []string, event string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		switch {
		case p == "*" || p == event:
			return true
		case strings.HasSuffix(p, "*") && strings.HasPrefix(event, strings.TrimSuffix(p, "*")):
			return true
		}
	}
	return false
}

// Emit queues an event for every enabled hook that subscribes to it.
func (d *Dispatcher) Emit(ctx context.Context, ev v1.WebhookEvent) {
	if d == nil {
		return
	}
	if ev.ID == "" {
		ev.ID = store.NewID("evt")
	}
	if ev.At.IsZero() {
		ev.At = d.now()
	}
	for _, h := range d.hooks(ctx) {
		if !h.Enabled || !matches(h.Events, ev.Event) {
			continue
		}
		select {
		case d.queue <- delivery{hook: h, ev: ev}:
		default:
			d.mu.Lock()
			d.dropped++
			d.mu.Unlock()
			d.log.Warn("webhook queue full; event dropped", "hook", h.ID, "event", ev.Event)
		}
	}
}

// sign returns the signature header value for a body at a timestamp.
func sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(ts, 10) + ",sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature checks a received signature; receivers can use
// it (tests do). tolerance bounds the timestamp age.
func VerifyWebhookSignature(secret, header string, body []byte, now time.Time, tolerance time.Duration) bool {
	var ts int64
	var sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts, _ = strconv.ParseInt(v, 10, 64)
		case "sha256":
			sig = v
		}
	}
	if ts == 0 || sig == "" {
		return false
	}
	if tolerance > 0 {
		age := now.Sub(time.Unix(ts, 0))
		if age < -tolerance || age > tolerance {
			return false
		}
	}
	want := sign(secret, ts, body)
	return hmac.Equal([]byte(want), []byte("t="+strconv.FormatInt(ts, 10)+",sha256="+sig))
}

// deliver posts one event with the configured retries and records the outcome.
func (d *Dispatcher) deliver(ctx context.Context, h webhookRec, ev v1.WebhookEvent) v1.AdminWebhookDelivery {
	return d.deliverWith(ctx, h, ev, d.backoff)
}

// deliverWith posts one event with the given attempt schedule (a wait
// before each attempt; the first is normally 0).
func (d *Dispatcher) deliverWith(ctx context.Context, h webhookRec, ev v1.WebhookEvent, backoff []time.Duration) v1.AdminWebhookDelivery {
	body, _ := json.Marshal(ev)
	rec := v1.AdminWebhookDelivery{ID: ev.ID, Event: ev.Event, At: d.now()}
	for i, wait := range backoff {
		if wait > 0 {
			select {
			case <-ctx.Done():
				rec.Error = "shutdown"
				break
			case <-time.After(wait):
			}
		}
		rec.Attempts = i + 1
		status, err := d.post(ctx, h, ev, body)
		rec.Status = status
		if err == nil && status >= 200 && status < 300 {
			rec.OK, rec.Error = true, ""
			break
		}
		if err != nil {
			rec.Error = err.Error()
		} else {
			rec.Error = "http " + strconv.Itoa(status)
		}
		if status >= 400 && status < 500 && status != 408 && status != 429 {
			break // the receiver rejected it; retrying will not help
		}
		if ctx.Err() != nil {
			break
		}
	}
	d.record(h.ID, rec)
	if d.metrics != nil {
		if rec.OK {
			d.metrics.webhookOK.Add(1)
		} else {
			d.metrics.webhookFail.Add(1)
		}
	}
	if !rec.OK {
		d.log.Warn("webhook delivery failed", "hook", h.ID, "event", ev.Event, "status", rec.Status, "err", rec.Error, "attempts", rec.Attempts)
	}
	return rec
}

func (d *Dispatcher) post(ctx context.Context, h webhookRec, ev v1.WebhookEvent, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	ts := d.now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanner-appliance-cp/webhooks")
	req.Header.Set("X-Webhook-Id", ev.ID)
	req.Header.Set("X-Webhook-Event", ev.Event)
	req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(ts, 10))
	if h.Secret != "" {
		req.Header.Set("X-Webhook-Signature", sign(h.Secret, ts, body))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

func (d *Dispatcher) record(hookID string, rec v1.AdminWebhookDelivery) {
	d.mu.Lock()
	defer d.mu.Unlock()
	list := append(d.deliveries[hookID], rec)
	if len(list) > webhookDeliveryLog {
		list = list[len(list)-webhookDeliveryLog:]
	}
	d.deliveries[hookID] = list
}

func (d *Dispatcher) last(hookID string) *v1.AdminWebhookDelivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	list := d.deliveries[hookID]
	if len(list) == 0 {
		return nil
	}
	rec := list[len(list)-1]
	return &rec
}

// Drain delivers everything queued synchronously (tests).
func (d *Dispatcher) Drain(ctx context.Context) {
	for {
		select {
		case dl := <-d.queue:
			d.deliver(ctx, dl.hook, dl.ev)
		default:
			return
		}
	}
}

func hookView(h webhookRec, last *v1.AdminWebhookDelivery) v1.AdminWebhookView {
	v := v1.AdminWebhookView{ID: h.ID, URL: h.URL, Events: h.Events, Enabled: h.Enabled, HasSecret: h.Secret != "", CreatedAt: h.CreatedAt, LastDelivery: last}
	if v.Events == nil {
		v.Events = []string{}
	}
	return v
}

// ---- admin API ----

func (s *Server) adminListWebhooks(w http.ResponseWriter, r *http.Request) {
	list, err := s.events.load(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminWebhookView, 0, len(list))
	for _, h := range list {
		out = append(out, hookView(h, s.events.last(h.ID)))
	}
	writeJSON(w, http.StatusOK, out)
}

func validWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("url must be an absolute http(s) URL")
	}
	return nil
}

func (s *Server) adminCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminWebhookRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if err := validWebhookURL(req.URL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_url")
		return
	}
	if len(req.Secret) > 256 || len(req.Events) > 64 {
		writeErr(w, http.StatusBadRequest, "secret up to 256 chars, up to 64 event patterns", "bad_request")
		return
	}
	list, err := s.events.load(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if len(list) >= webhookMaxHooks {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d webhooks", webhookMaxHooks), "too_many")
		return
	}
	h := webhookRec{ID: store.NewID("whk"), URL: strings.TrimSpace(req.URL), Secret: req.Secret, Events: dedupe(req.Events), Enabled: true, CreatedAt: s.cfg.Now()}
	if req.Enabled != nil {
		h.Enabled = *req.Enabled
	}
	if h.Events == nil {
		h.Events = []string{}
	}
	list = append(list, h)
	if err := s.events.save(r.Context(), list); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("webhook created", "id", h.ID, "url", h.URL, "events", h.Events, "by", s.actor(r))
	writeJSON(w, http.StatusCreated, hookView(h, nil))
}

func (s *Server) adminDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	list, err := s.events.load(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	id := r.PathValue("id")
	kept := list[:0]
	found := false
	for _, h := range list {
		if h.ID == id {
			found = true
			continue
		}
		kept = append(kept, h)
	}
	if !found {
		writeErr(w, http.StatusNotFound, "no such webhook", "not_found")
		return
	}
	if err := s.events.save(r.Context(), kept); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminTestWebhook delivers a test event synchronously, in a single
// attempt so the caller gets an answer at once, and reports it.
func (s *Server) adminTestWebhook(w http.ResponseWriter, r *http.Request) {
	list, err := s.events.load(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	for _, h := range list {
		if h.ID != r.PathValue("id") {
			continue
		}
		ev := v1.WebhookEvent{ID: store.NewID("evt"), Event: EventWebhookTest, At: s.cfg.Now(), Data: map[string]any{"hook": h.ID, "product": s.cfg.Product}}
		rec := s.events.deliverWith(r.Context(), h, ev, []time.Duration{0})
		writeJSON(w, http.StatusOK, rec)
		return
	}
	writeErr(w, http.StatusNotFound, "no such webhook", "not_found")
}

func (s *Server) adminWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	s.events.mu.Lock()
	list := append([]v1.AdminWebhookDelivery{}, s.events.deliveries[r.PathValue("id")]...)
	s.events.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
	writeJSON(w, http.StatusOK, list)
}

// emit is the server-side convenience.
func (s *Server) emit(ctx context.Context, event string, siteID, applianceID, jobID string, data any) {
	if s.events == nil {
		return
	}
	s.events.Emit(ctx, v1.WebhookEvent{Event: event, At: s.cfg.Now(), SiteID: siteID, ApplianceID: applianceID, JobID: jobID, Data: data})
}
