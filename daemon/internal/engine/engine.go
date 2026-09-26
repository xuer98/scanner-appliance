package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// Phase names reported in progress and stats.
const (
	PhaseDiscovery = "discovery"
	PhasePortscan  = "portscan"
	PhaseOpenVAS   = "openvas"
	PhaseFinalize  = "finalize"
)

// ErrStopped is returned when the job context is cancelled (stop_all).
var ErrStopped = errors.New("scan stopped")

// ErrTimeout is returned when the job exceeded max_duration_s.
var ErrTimeout = errors.New("scan exceeded max_duration_s")

// DefaultFragilePorts applies when the site does not list its own (PLAN §10.6).
var DefaultFragilePorts = []int{9100, 515, 631, 161, 502, 44818}

// Progress is what the heartbeat shows while a job runs.
type Progress struct {
	Phase        string
	Pct          int
	HostsAlive   int
	HostsScanned int
}

// Sink receives result chunks and progress.
type Sink interface {
	Emit(ctx context.Context, b v1.ResultBatch) error
	Progress(p Progress)
}

// Engine runs jobs. Zero values are filled by init().
type Engine struct {
	NaabuPath   string
	OSP         *osp.Client
	NVT         *nvt.Cache
	Log         *slog.Logger
	Now         func() time.Time
	ApplianceID string
	// PollInterval between get_scans calls (30 s in production, PLAN §10.3).
	PollInterval time.Duration
	// ChunkHosts per result batch.
	ChunkHosts int
	// MaxResultsPerPoll caps one get_scans response.
	MaxResultsPerPoll int
	// ScanType overrides naabu's scan type ("s" SYN, "c" connect); empty
	// lets naabu choose (SYN when it has NET_RAW).
	ScanType string
	// IfaceExists is overridable in tests.
	IfaceExists func(string) bool
}

func (e *Engine) init() {
	if e.Log == nil {
		e.Log = slog.Default()
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.PollInterval == 0 {
		e.PollInterval = 30 * time.Second
	}
	if e.ChunkHosts == 0 {
		e.ChunkHosts = 50
	}
	if e.MaxResultsPerPoll == 0 {
		e.MaxResultsPerPoll = 2000
	}
}

type run struct {
	e     *Engine
	spec  v1.JobSpec
	site  v1.SiteConfig
	sink  Sink
	start time.Time
	stats *v1.ScanStats
	hosts map[string]*hostAgg
	order []string
	seq   int
	feed  string
	log   *slog.Logger
}

// Run executes the job's phases and returns the stats. Partial results
// are emitted before returning an error where possible.
func (e *Engine) Run(ctx context.Context, spec v1.JobSpec, site v1.SiteConfig, sink Sink) (*v1.ScanStats, error) {
	e.init()
	r := &run{e: e, spec: spec, site: site, sink: sink, start: e.Now(), hosts: map[string]*hostAgg{},
		stats: &v1.ScanStats{Rejected: []string{}, PhaseDurationS: map[string]int64{}}, log: e.Log.With("job", spec.JobID)}
	if e.OSP != nil && spec.HasModule(v1.ModuleOpenVAS) {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		r.feed, _ = e.OSP.FeedVersion(fctx)
		cancel()
	}
	err := r.phases(ctx)
	r.stats.DurationS = int64(e.Now().Sub(r.start) / time.Second)
	return r.stats, err
}

func (r *run) excluded(ip string) bool {
	return guard.Contains(r.spec.Excludes, ip) || guard.Contains(r.site.Excludes, ip)
}

func (r *run) host(ip string) *hostAgg {
	h, ok := r.hosts[ip]
	if !ok {
		h = newHostAgg(ip)
		r.hosts[ip] = h
		r.order = append(r.order, ip)
	}
	return h
}

func (r *run) progress(phase string, pct int) {
	r.sink.Progress(Progress{Phase: phase, Pct: pct, HostsAlive: r.stats.HostsAlive, HostsScanned: r.stats.HostsScanned})
}

func (r *run) timed(phase string, f func() error) error {
	t := r.e.Now()
	err := f()
	r.stats.PhaseDurationS[phase] = int64(r.e.Now().Sub(t) / time.Second)
	return err
}

func (r *run) phases(ctx context.Context) error {
	spec := r.spec
	discovered := false
	if spec.HasModule(v1.ModuleDiscovery) {
		r.progress(PhaseDiscovery, 0)
		if err := r.timed(PhaseDiscovery, func() error { return r.discovery(ctx) }); err != nil {
			return r.abort(ctx, err)
		}
		discovered = true
		r.progress(PhaseDiscovery, 100)
	}
	if spec.HasModule(v1.ModulePortscan) {
		r.progress(PhasePortscan, 0)
		if err := r.timed(PhasePortscan, func() error { return r.portscan(ctx, discovered) }); err != nil {
			return r.abort(ctx, err)
		}
		r.progress(PhasePortscan, 100)
		if spec.HasModule(v1.ModuleOpenVAS) && len(r.order) > 0 {
			// Interim chunk: hosts and open ports are worth having even if
			// the openvas phase later fails.
			if err := r.emitAll(ctx, false, nil); err != nil {
				return err
			}
		}
	}
	var meta map[string]*nvt.Meta
	if spec.HasModule(v1.ModuleOpenVAS) {
		r.progress(PhaseOpenVAS, 0)
		var err error
		err = r.timed(PhaseOpenVAS, func() error {
			meta, err = r.openvas(ctx)
			return err
		})
		if err != nil {
			return r.abort(ctx, err)
		}
		r.progress(PhaseOpenVAS, 100)
	}
	r.progress(PhaseFinalize, 0)
	return r.emitAll(ctx, true, meta)
}

// abort maps context errors and emits whatever was gathered as a
// non-final chunk so the control plane keeps partial results.
func (r *run) abort(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		err = ErrTimeout
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		err = ErrStopped
	}
	if len(r.order) > 0 {
		ectx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if eerr := r.emitAll(ectx, false, nil); eerr != nil {
			r.log.Warn("partial results not spooled", "err", eerr)
		}
		cancel()
	}
	return err
}

// discoveryArgs / portscanArgs: naabu 2.3 needs -wn to honour explicit probe
// flags in -sn mode, and its -json output is empty there (plain IP lines are
// parsed instead); the port scan uses -json.
var (
	discoveryArgs = []string{"-sn", "-wn", "-pe", "-arp", "-ps", "22,80,443"}
	portscanArgs  = []string{"-json"}
)

func (r *run) discovery(ctx context.Context) error {
	args := append(r.e.naabuArgs(r.spec, r.site, r.spec.Targets), discoveryArgs...)
	out, err := r.e.runNaabu(ctx, PhaseDiscovery, args)
	if err != nil {
		return err
	}
	for _, ip := range out.Order {
		if r.excluded(ip) {
			continue
		}
		r.host(ip)
	}
	r.stats.HostsAlive = len(r.order)
	r.log.Info("discovery", "alive", r.stats.HostsAlive)
	return nil
}

func (r *run) portscan(ctx context.Context, discovered bool) error {
	targets := r.spec.Targets
	if discovered {
		if len(r.order) == 0 {
			r.log.Info("portscan skipped: no live hosts")
			return nil
		}
		targets = append([]string{}, r.order...)
	}
	pa, err := portArgs(r.spec.Ports)
	if err != nil {
		return err
	}
	args := append(r.e.naabuArgs(r.spec, r.site, targets), portscanArgs...)
	args = append(args, pa...)
	if discovered {
		args = append(args, "-Pn")
	}
	out, err := r.e.runNaabu(ctx, PhasePortscan, args)
	if err != nil {
		return err
	}
	for _, ip := range out.Order {
		if r.excluded(ip) {
			continue
		}
		h := r.host(ip)
		for p, proto := range out.Hosts[ip] {
			h.addPort(p, proto, "naabu")
			r.stats.OpenPorts++
		}
	}
	if !discovered {
		r.stats.HostsAlive = len(r.order)
	}
	r.log.Info("portscan", "hosts", len(r.order), "open_ports", r.stats.OpenPorts)
	return nil
}

func fragilePort(h *hostAgg, fragile []int) int {
	for _, p := range h.ports {
		for _, f := range fragile {
			if p.Port == f {
				return f
			}
		}
	}
	return 0
}

// openvas runs the detection phase and returns the NVT metadata for the
// OIDs that appeared.
func (r *run) openvas(ctx context.Context) (map[string]*nvt.Meta, error) {
	if r.e.OSP == nil {
		return nil, errors.New("openvas: no OSP client configured")
	}
	cfg, err := ConfigFor(r.spec.OpenVAS.Config)
	if err != nil {
		return nil, err
	}
	fragile := r.site.FragilePorts
	if len(fragile) == 0 {
		fragile = DefaultFragilePorts
	}
	var scanHosts []string
	tcp := map[int]bool{}
	for _, ip := range r.order {
		h := r.hosts[ip]
		if len(h.ports) == 0 {
			h.notes = append(h.notes, "openvas:skipped-no-open-ports")
			continue
		}
		if r.spec.OpenVAS.FragilePortsExclude {
			if fp := fragilePort(h, fragile); fp != 0 {
				h.notes = append(h.notes, "fragile:"+strconv.Itoa(fp))
				r.stats.FragileExcluded++
				continue
			}
		}
		scanHosts = append(scanHosts, ip)
		for _, p := range h.ports {
			if p.Proto == "tcp" {
				tcp[p.Port] = true
			}
		}
	}
	if len(scanHosts) == 0 {
		r.log.Info("openvas skipped: no eligible hosts")
		return nil, nil
	}
	params := map[string]string{}
	for k, v := range cfg.Params {
		params[k] = v
	}
	params["safe_checks"] = "1"
	if !r.spec.SafeChecks && r.site.UnsafeOK {
		params["safe_checks"] = "0"
	}
	params["max_hosts"] = strconv.Itoa(r.spec.OpenVAS.MaxHosts)
	params["max_checks"] = strconv.Itoa(r.spec.OpenVAS.MaxChecks)
	var excludes []string
	excludes = append(excludes, r.spec.Excludes...)
	excludes = append(excludes, r.site.Excludes...)
	target := osp.Target{Hosts: scanHosts, Ports: openvasPortList(tcp, cfg.UDPPorts), ExcludeHosts: excludes, AliveTest: osp.AliveTestConsiderAlive}
	scanID, err := r.e.OSP.StartScan(ctx, target, params, osp.VTSelection{Families: cfg.Families})
	if err != nil {
		return nil, fmt.Errorf("openvas start_scan: %w", err)
	}
	r.stats.HostsScanned = len(scanHosts)
	r.log.Info("openvas scan started", "scan_id", scanID, "hosts", len(scanHosts), "ports", target.Ports, "config", cfg.Name)

	failures := 0
	for {
		sc, err := r.e.OSP.GetScan(ctx, scanID, true, r.e.MaxResultsPerPoll)
		if err != nil {
			if ctx.Err() != nil {
				r.stopScan(scanID)
				return nil, ctx.Err()
			}
			failures++
			r.log.Warn("get_scans failed", "err", err, "failures", failures)
			if failures >= 5 {
				r.stopScan(scanID)
				return nil, fmt.Errorf("openvas get_scans: %w", err)
			}
			if !sleepCtx(ctx, r.e.PollInterval) {
				r.stopScan(scanID)
				return nil, ctx.Err()
			}
			continue
		}
		failures = 0
		for _, res := range sc.Results {
			if res.Host == "" || r.excluded(res.Host) {
				continue
			}
			h := r.host(res.Host)
			h.scanned = true
			h.absorb(res)
		}
		r.progress(PhaseOpenVAS, sc.Progress)
		if sc.Done() {
			r.deleteScan(scanID)
			if sc.Status != osp.ScanFinished {
				return nil, fmt.Errorf("openvas scan %s", sc.Status)
			}
			break
		}
		if len(sc.Results) >= r.e.MaxResultsPerPoll {
			continue // drain without waiting
		}
		if !sleepCtx(ctx, r.e.PollInterval) {
			r.stopScan(scanID)
			return nil, ctx.Err()
		}
	}

	var oids []string
	for _, h := range r.hosts {
		for _, a := range h.alarms {
			oids = append(oids, a.TestID)
		}
		for _, l := range h.logs {
			oids = append(oids, l.TestID)
		}
	}
	meta := map[string]*nvt.Meta{}
	if r.e.NVT != nil && len(oids) > 0 {
		mctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		m, err := r.e.NVT.Lookup(mctx, r.feed, nvt.UniqueOIDs(oids))
		cancel()
		if err != nil {
			r.log.Warn("nvt metadata incomplete", "err", err)
		}
		if m != nil {
			meta = m
		}
	}
	return meta, nil
}

// stopScan issues stop_scan with a fresh context (the job's is dead) and
// deletes the scan once ospd reports it stopped.
func (r *run) stopScan(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.e.OSP.StopScan(ctx, id); err != nil {
		r.log.Warn("stop_scan failed", "scan_id", id, "err", err)
		return
	}
	r.log.Warn("openvas scan stopped", "scan_id", id)
	for i := 0; i < 10; i++ {
		sc, err := r.e.OSP.GetScan(ctx, id, false, 1)
		if err != nil || sc.Done() {
			break
		}
		if !sleepCtx(ctx, time.Second) {
			return
		}
	}
	r.deleteScan(id)
}

func (r *run) deleteScan(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := r.e.OSP.DeleteScan(ctx, id); err != nil {
		r.log.Debug("delete_scan", "scan_id", id, "err", err)
	}
}

// emitAll finalizes every host and emits chunks; the last one is final
// when requested and carries the stats.
func (r *run) emitAll(ctx context.Context, final bool, meta map[string]*nvt.Meta) error {
	if meta == nil {
		meta = map[string]*nvt.Meta{}
	}
	ips := append([]string{}, r.order...)
	sort.Strings(ips)
	hosts := make([]v1.Host, 0, len(ips))
	for _, ip := range ips {
		hosts = append(hosts, r.hosts[ip].finalize(meta))
	}
	if final {
		r.stats.Findings = 0
		for _, h := range hosts {
			r.stats.Findings += len(h.Findings)
		}
	}
	if len(hosts) == 0 {
		return r.emit(ctx, final, []v1.Host{})
	}
	for i := 0; i < len(hosts); i += r.e.ChunkHosts {
		j := i + r.e.ChunkHosts
		if j > len(hosts) {
			j = len(hosts)
		}
		if err := r.emit(ctx, final && j == len(hosts), hosts[i:j]); err != nil {
			return err
		}
	}
	return nil
}

func (r *run) emit(ctx context.Context, final bool, hosts []v1.Host) error {
	r.seq++
	b := v1.ResultBatch{JobID: r.spec.JobID, ApplianceID: r.e.ApplianceID, SiteID: r.spec.SiteID, FeedVersion: r.feed,
		StartedAt: r.start.Unix(), Seq: r.seq, Final: final, Hosts: hosts}
	if final {
		b.FinishedAt = r.e.Now().Unix()
		r.stats.DurationS = int64(r.e.Now().Sub(r.start) / time.Second)
		b.Stats = r.stats
	}
	return r.sink.Emit(ctx, b)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
