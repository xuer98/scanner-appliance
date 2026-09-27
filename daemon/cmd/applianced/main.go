// applianced is the scanner appliance daemon (PLAN §3, §9).
//
//	applianced run                         daemon: seed → enroll → heartbeat + job loop
//	applianced tty                         console on tty1 (getty@tty1 override)
//	applianced enroll --code CODE [--cp-url URL]
//	applianced status                      print /run/appliance/status.json
//	applianced version
//
// Build-time variables (ldflags -X main.<name>=...):
//
//	version       release version
//	defaultCPURL  the single egress FQDN (PLAN G3)
//
// Runtime environment (all optional):
//
//	APPLIANCE_OSPD_SOCKET       ospd-openvas socket (default /run/ospd/ospd.sock)
//	APPLIANCE_NAABU             naabu binary (default /opt/engine/naabu, then $PATH)
//	APPLIANCE_SUPERVISE_ENGINE  "1": start redis + ospd-openvas as children (container)
//	APPLIANCE_SCAN_TYPE         naabu scan type: "s" SYN (raw sockets / Npcap) or "c" connect; empty lets naabu choose
//	APPLIANCE_PLUGINS_DIR       openvas VT feed directory updated by bundles (default /var/lib/openvas/plugins on Linux)
//	APPLIANCE_RELEASE_KEY       extra release signing public key PEM (dev/staging; production embeds release-pub.pem)
//
// Platforms: the appliance is the Linux image/container. The daemon also
// builds and runs on Windows (state under %ProgramData%\TPRM Appliance,
// naabu.exe in engine\ beside applianced.exe); without ospd-openvas only
// discovery/portscan jobs run there (daemon/internal/platform).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // scan windows are evaluated in the site's timezone

	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/enroll"
	"github.com/tprm/scanner-appliance/daemon/internal/fingerprint"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/netcfg"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/pki"
	"github.com/tprm/scanner-appliance/daemon/internal/platform"
	"github.com/tprm/scanner-appliance/daemon/internal/seed"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/tty"
	"github.com/tprm/scanner-appliance/daemon/internal/update"
)

var (
	version      = "dev"
	defaultCPURL = "https://appliance.tprm.example.com"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "tty":
		err = console(os.Args[2:])
	case "enroll":
		err = enrollCmd(os.Args[2:])
	case "status":
		err = statusCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: applianced <run|tty|enroll|status|version> [flags]")
}

func commonFlags(fs *flag.FlagSet) (dir, runDir *string) {
	dir = fs.String("state-dir", envOr("APPLIANCE_STATE_DIR", state.DefaultDir), "state directory")
	runDir = fs.String("run-dir", envOr("APPLIANCE_RUN_DIR", state.DefaultRunDir), "runtime directory")
	return
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir, runDir := commonFlags(fs)
	seedFile := fs.String("seed-file", os.Getenv("APPLIANCE_SEED_FILE"), "read seed from this YAML instead of OVF/volume/env")
	logLevel := fs.String("log-level", envOr("APPLIANCE_LOG_LEVEL", "info"), "debug|info|warn")
	ospSock := fs.String("ospd-socket", envOr("APPLIANCE_OSPD_SOCKET", osp.DefaultSocket), "ospd-openvas Unix socket")
	naabuPath := fs.String("naabu", os.Getenv("APPLIANCE_NAABU"), "naabu binary (default /opt/engine/naabu or $PATH)")
	supervise := fs.Bool("supervise-engine", os.Getenv("APPLIANCE_SUPERVISE_ENGINE") == "1", "start redis + ospd-openvas as child processes (no systemd)")
	scanType := fs.String("scan-type", os.Getenv("APPLIANCE_SCAN_TYPE"), "naabu scan type: s (SYN, needs raw sockets / Npcap) or c (connect); empty lets naabu choose")
	pluginsDir := fs.String("plugins-dir", envOr("APPLIANCE_PLUGINS_DIR", platform.PluginsDir()), "openvas VT feed directory that signature bundles update (empty: keep bundled feeds under the state dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanType != "" && *scanType != "s" && *scanType != "c" {
		return fmt.Errorf("--scan-type must be s or c, got %q", *scanType)
	}
	log := newLogger(*logLevel)
	log.Info("applianced starting", "version", version, "state_dir", *dir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *supervise {
		sup := osp.DefaultSupervisor(log)
		sup.OSPDSock = *ospSock
		if sup.Available() {
			log.Info("supervising redis-openvas and ospd-openvas")
			go sup.Run(ctx)
		} else {
			log.Warn("engine supervision requested but redis/ospd-openvas are not installed")
		}
	}

	roots, err := pki.Pool()
	if err != nil {
		return err
	}
	st := state.New(*dir, *runDir)
	s, err := st.Load()
	if err != nil {
		return err
	}
	if s.EnrollURL == "" {
		s.EnrollURL = envOr("APPLIANCE_CP_URL", defaultCPURL)
	}

	// Seed resolution happens once; after enrollment later boots ignore it (PLAN §5).
	if !s.SeedConsumed && s.ApplianceID == "" {
		r := seed.Default()
		r.SeedFile = *seedFile
		sd, err := r.Resolve(ctx)
		if err != nil {
			log.Warn("seed resolution failed; console can still enroll", "err", err)
		} else if !sd.Empty() {
			log.Info("seed found", "source", sd.Source, "has_code", sd.Code != "")
			applySeed(ctx, log, s, sd)
		} else {
			log.Info("no seed; waiting for the console")
		}
	}
	if err := st.Save(s); err != nil {
		return err
	}
	if *naabuPath == "" {
		*naabuPath = findNaabu()
	}
	if *naabuPath == "" {
		log.Warn("naabu not found; discovery/portscan jobs will fail until it is installed")
	}
	upd := &update.Manager{StateDir: st.Dir, PluginsDir: *pluginsDir, Keys: pki.ReleaseKeys(), OSP: osp.New(*ospSock), Log: log,
		Version: version, Container: fingerprint.Hypervisor() == "container"}
	if len(upd.Keys) == 0 {
		log.Warn("no release signing key (release-pub.pem); update_bundle / update_daemon will be refused")
	}
	eng := &engine.Engine{NaabuPath: *naabuPath, OSP: osp.New(*ospSock), Log: log, ScanType: *scanType,
		NVT:       nvt.New(filepath.Join(st.Dir, "nvt-cache"), osp.New(*ospSock), log),
		BundleDir: filepath.Join(st.Dir, "bundle"), HTTPXPath: findEngineTool("httpx"), NucleiPath: findEngineTool("nuclei"), Split: s.Split,
		NmapPath: findEngineTool("nmap")}
	if eng.NmapPath != "" {
		log.Info("nmap present: the fingerprint pass is available to jobs that carry it", "path", eng.NmapPath)
	}
	runner := &jobs.Runner{Store: st, Engine: eng, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")}, Roots: roots, Log: log}
	loop := &heartbeat.Loop{Store: st, Roots: roots, Version: version, Log: log, OSPSocket: *ospSock, Jobs: runner, Update: upd,
		ToolPaths: map[string]string{"naabu": *naabuPath, "httpx": eng.HTTPXPath, "nuclei": eng.NucleiPath, "nmap": eng.NmapPath}}
	loop.Run(ctx)
	runner.StopAll("daemon shutting down")
	runner.Wait()
	if loop.RestartRequested() {
		log.Warn("exiting so the service supervisor starts the binary now in place")
		return nil
	}
	log.Info("applianced stopped")
	return nil
}

// findEngineTool looks for an optional engine binary (httpx, nuclei,
// nmap) in the engine directory, then $PATH; "" when absent.
func findEngineTool(name string) string { return heartbeat.FindTool(name) }

// findNaabu prefers the image's engine directory (engine\ beside the
// executable on Windows), then $PATH.
func findNaabu() string { return heartbeat.FindTool("naabu") }

func applySeed(ctx context.Context, log *slog.Logger, s *state.State, sd *seed.Seed) {
	if sd.CPURL != "" {
		s.EnrollURL = strings.TrimRight(sd.CPURL, "/")
	}
	if sd.Proxy != "" {
		s.Proxy = sd.Proxy
	}
	s.Split = s.Split || sd.Split
	if sd.Network.WAN0 != nil || sd.Network.LAN0 != nil {
		s.Network = sd.Network
		if err := netcfg.Apply(ctx, s.Network); err != nil {
			log.Warn("seed network config rejected", "err", err)
		} else {
			log.Info("seed network config applied")
		}
	}
	if sd.Code != "" {
		s.PendingCode = sd.Code
	} else {
		s.SeedConsumed = true
	}
}

func console(args []string) error {
	fs := flag.NewFlagSet("tty", flag.ContinueOnError)
	dir, runDir := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	roots, err := pki.Pool()
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := &tty.Console{In: os.Stdin, Out: os.Stdout, Store: state.New(*dir, *runDir), Roots: roots, Version: version, Clear: true}
	for {
		err := c.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		// EOF or read error on the tty: getty restarts us, but be patient in case it doesn't.
		fmt.Fprintln(os.Stderr, "console input closed:", err)
		time.Sleep(2 * time.Second)
		c = &tty.Console{In: os.Stdin, Out: os.Stdout, Store: c.Store, Roots: roots, Version: version, Clear: true}
	}
}

func enrollCmd(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	dir, runDir := commonFlags(fs)
	code := fs.String("code", os.Getenv("APPLIANCE_CODE"), "enrollment code")
	cpURL := fs.String("cp-url", envOr("APPLIANCE_CP_URL", defaultCPURL), "enroll listener URL")
	proxy := fs.String("proxy", os.Getenv("APPLIANCE_PROXY"), "proxy host:port or user:pass@host:port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	roots, err := pki.Pool()
	if err != nil {
		return err
	}
	st := state.New(*dir, *runDir)
	s, _ := st.Load()
	if *proxy != "" {
		s.Proxy = *proxy
		_ = st.Save(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := enroll.Enroll(ctx, st, enroll.Options{EnrollURL: *cpURL, Code: *code, Proxy: s.Proxy, Version: version, Roots: roots})
	if err != nil {
		return err
	}
	_ = st.Touch("reload")
	fmt.Printf("enrolled: %s\ncp_url: %s\nallowed_cidrs: %s\n", resp.ApplianceID, resp.CPURL, strings.Join(resp.Site.AllowedCIDRs, ","))
	return nil
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir, runDir := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := state.New(*dir, *runDir).ReadStatus()
	if err != nil {
		return fmt.Errorf("daemon status unavailable: %w", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	default:
		l = slog.LevelInfo
	}
	// journald captures stderr; plain text reads better than JSON in `journalctl`.
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
