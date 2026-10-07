// cp-api is the appliance control plane (PLAN §17).
//
//	cp-api ca init --dir /pki [--org "TPRM"]
//	cp-api serve  --db postgres://... | --dev
//	cp-api admin create-appliance --vendor V --site S --cidrs 10.0.0.0/8[,..]
//	cp-api admin get <appliance_id>
//	cp-api admin directive <appliance_id> <type> [json payload]
//	cp-api admin directives <appliance_id>
//	cp-api admin revoke <appliance_id> [reason]
//	cp-api admin create-job --appliance ID --mode discovery|inventory|full --targets a/b[,..] [--cron "0 22 * * 6"] [--now]
//	cp-api admin jobs [--appliance ID] [--site ID] | job ID | cancel-job ID | run-now ID | job-hosts ID
//	cp-api admin sites | site ID | site-update ID [--cidrs ..] [--excludes ..] [--fragile-ports ..] [--max-pps N] [--max-concurrency N] [--unsafe-ok B] [--allow-public B]
//	cp-api admin hosts SITE | findings SITE | agent-inventory SITE inventory.json
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/server"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/qualys"
	"github.com/tprm/scanner-appliance/internal/seal"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "ca":
		err = caCmd(os.Args[2:])
	case "admin":
		err = adminCmd(os.Args[2:])
	case "bundle":
		err = bundleCmd(os.Args[2:])
	case "feed":
		err = feedCmd(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, `usage: cp-api <serve|ca init|admin ...|version>
  serve --db URL | --dev   --pki-dir DIR --enroll-addr :8443 --mtls-addr :9443 --public-url URL [--self-issue]
  ca init --dir DIR [--org NAME]
  admin create-appliance --vendor V --site S [--cidrs a/b,c/d] [--tz TZ]
  admin get|directives|revoke ID ; admin directive ID TYPE [JSON]
  admin create-job --appliance ID --mode discovery|inventory|full --targets a/b[,..] [--excludes ..] [--ports standard|full|list]
                   [--cron "0 22 * * 6" --tz TZ --max-duration S] [--pps N] [--max-hosts N --max-checks N] [--now]
                   [--udp]   (also run the engine's UDP tests: off by default, slower, probes well-known UDP ports on every host; in a schedule add "udp" to --modules)
  admin jobs [--appliance ID] [--site ID] | job ID | cancel-job ID | run-now ID | job-hosts ID
  admin sites | site ID | site-update ID [--cidrs ..] [--excludes ..] [--fragile-ports ..] [--max-pps N] [--max-concurrency N] [--unsafe-ok B] [--allow-public B]
  admin hosts SITE | findings SITE | agent-inventory SITE FILE.json
  admin site-update ID --lan-routes 10.31.0.0/16@10.30.5.1[,..]|none      (split-network floors, PLAN §15)
  feed sync --dest DIR [--source rsync://…] [--gpg-keyring FILE]          (mirror the Greenbone Community Feed)
  bundle build --out DIR --feed DIR [--nuclei-templates DIR] [--version V] --key release-key.pem
  admin publish-bundle --dir DIR [--canary-hours H] | bundles | rollout bundle VERSION canary|released|held|retired [--reason R]
  admin publish-release --file BIN --component applianced-linux-amd64 --version V --key release-key.pem [--canary-hours H]
  admin releases | rollout release COMPONENT VERSION STATUS | set-canary ID true|false
  ca release-key --dir DIR                                                 (create the release signing key pair if missing)
  Phase 4 (pilot):  admin scope-request SITE --cidrs .. --reason R | scope-requests SITE | approve|reject SITE RID --owner-token T | attest SITE --owner-token T
                    admin changes SITE | fragile SITE | fragile-set SITE --ip IP --action clear|unclear|mark|unmark --reason R
                    admin exclusions SITE | exclude SITE VT --reason R | unexclude SITE VT | tuning SITE | review FINDING --review false_positive|accepted|none --reason R [--codify]
                    admin finding ID | host ID | coverage SITE | vendor-coverage VENDOR | alerts | calendar SITE [--days N]
                    admin create-schedule --appliance ID --mode M --targets .. --cron ".." [--tz ..] | schedules [--site-id S] | schedule ID | schedule-update ID [..] | delete-schedule ID
                    admin transparency                                     (the vendor-facing page as JSON; HTML at GET /transparency on both listeners)
  Phase 5 (depth):  admin signoff [nmap] [--reference LEGAL-123 --note ".." --actor A | --revoke]   (nmap fingerprinting needs this first, PLAN §21)
                    admin create-job ... [--ports full] [--fingerprint [--fingerprint-intensity N] [--no-os-detection]] [--modules discovery,portscan,fingerprint]
                    admin create-schedule ... [--modules ..] | schedule-update ID [--modules ..|default]
                    admin onboarding SITE                                  (PLAN §19.2 checklist) | feed-gaps [--site-id S]  (Enterprise Feed evaluation data)
  Phase 6 (Qualys replacement, docs/MIGRATION.md):
                    admin import-qualys SITE EXPORT.csv|.xml [--kb kb.xml] [--scanned-at T]   (external findings, correlated by CVE)
                    admin parity SITE [--scanner qualys --days-back 60 --min-severity medium]  (host×CVE detection rate and the gaps)
                    admin summary SITE | vendor-summary VENDOR | trend SITE [--weeks N] | sla   (open by severity, SLA ageing, risk points, top findings)
                    admin export SITE findings|hosts [--status-filter open|fixed|all] [--out f.csv] | vendor-export VENDOR [--out f.csv]
                    admin webhook add --url-hook URL [--secret S] [--events finding.*,job.failed] | list | delete ID | test ID | deliveries ID
                    admin retention [--dry-run] | metrics
  serve flags (Phase 6): --s3-endpoint/--s3-bucket/--s3-region/--s3-prefix/--s3-path-style (+ CP_S3_ACCESS_KEY/CP_S3_SECRET_KEY),
                    --retention-days 90 --support-retention-days 180 --sla critical=15,high=30,medium=90,low=180 --metrics-addr 127.0.0.1:9100
  admin flags: --url https://host:9443 (env CP_URL) --token T (env CP_ADMIN_TOKEN) --ca root.pem (env CP_ROOT_CA)`)
}

func caCmd(args []string) error {
	if len(args) < 1 || (args[0] != "init" && args[0] != "release-key") {
		return errors.New("usage: cp-api ca init --dir DIR [--org NAME] | cp-api ca release-key --dir DIR")
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "pki", "output directory")
	org := fs.String("org", "TPRM", "organization name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "release-key" {
		if _, err := ensureReleaseKeys(*dir, true, slog.Default()); err != nil {
			return err
		}
		fmt.Printf("%s/release-key.pem signs bundles and releases; embed %s/release-pub.pem into applianced (daemon/internal/pki/release-pub.pem)\n", *dir, *dir)
		return nil
	}
	if err := ca.Init(*dir, *org); err != nil {
		return err
	}
	if _, err := ensureSpoolKey(*dir, true, slog.Default()); err != nil {
		return err
	}
	if _, err := ensureReleaseKeys(*dir, true, slog.Default()); err != nil {
		return err
	}
	fmt.Printf("wrote %s/{root.pem,root-key.pem,intermediate.pem,intermediate-key.pem,spool-key.pem,release-key.pem,release-pub.pem}\n", *dir)
	fmt.Println("move root-key.pem offline; embed root.pem into applianced (daemon/internal/pki/roots.pem)")
	fmt.Println("spool-key.pem decrypts uploaded results; back it up with the intermediate key")
	fmt.Println("release-key.pem signs bundles and daemon releases (cosign blob format); embed release-pub.pem into applianced (daemon/internal/pki/release-pub.pem)")
	return nil
}

// ensureSpoolKey loads pki-dir/spool-key.pem, creating it when allowed.
func ensureSpoolKey(pkiDir string, create bool, log *slog.Logger) (*server.SpoolKey, error) {
	path := filepath.Join(pkiDir, "spool-key.pem")
	if k, err := seal.LoadPrivate(path); err == nil {
		return &server.SpoolKey{Key: k}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("spool key: %w", err)
	}
	if !create {
		return nil, fmt.Errorf("%s missing: run `cp-api ca init` (or --dev)", path)
	}
	k, err := seal.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := seal.SavePrivate(path, k); err != nil {
		return nil, err
	}
	log.Info("generated spool key", "path", path)
	return &server.SpoolKey{Key: k}, nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dbURL := fs.String("db", os.Getenv("DATABASE_URL"), "postgres URL")
	dev := fs.Bool("dev", false, "in-memory store, auto server cert, default admin token")
	pkiDir := fs.String("pki-dir", envOr("CP_PKI_DIR", "pki"), "directory with root.pem, intermediate.pem, intermediate-key.pem")
	enrollAddr := fs.String("enroll-addr", envOr("CP_ENROLL_ADDR", ":8443"), "enroll listener (TLS, no client cert)")
	mtlsAddr := fs.String("mtls-addr", envOr("CP_MTLS_ADDR", ":9443"), "mTLS listener")
	publicURL := fs.String("public-url", os.Getenv("CP_PUBLIC_URL"), "URL appliances use after enrollment")
	serverCert := fs.String("server-cert", os.Getenv("CP_SERVER_CERT"), "server TLS cert PEM (chain)")
	serverKey := fs.String("server-key", os.Getenv("CP_SERVER_KEY"), "server TLS key PEM")
	selfIssue := fs.Bool("self-issue", os.Getenv("CP_SELF_ISSUE") == "1", "issue the server TLS certificate and spool key from the pki dir when missing (dev/staging stacks; production supplies --server-cert/--server-key)")
	adminToken := fs.String("admin-token", os.Getenv("CP_ADMIN_TOKEN"), "bearer token for /admin")
	objDir := fs.String("object-dir", envOr("CP_OBJECT_DIR", "objects"), "local object store directory")
	aptDir := fs.String("apt-dir", os.Getenv("CP_APT_DIR"), "directory served as the apt security mirror under /apt/ (mTLS); empty disables")
	ownerToken := fs.String("owner-token", os.Getenv("CP_OWNER_TOKEN"), "bearer token of the vendor-owner role (approves scope changes, attests the scope)")
	product := fs.String("product", envOr("CP_PRODUCT", "TPRM scanner appliance"), "product name on the transparency page")
	contact := fs.String("contact", os.Getenv("CP_CONTACT"), "contact shown on the transparency page")
	canaryHours := fs.Float64("canary-hours", envFloat("CP_CANARY_HOURS", 48), "hours a bundle/release stays with the canary group before general release")
	logLevel := fs.String("log-level", envOr("CP_LOG_LEVEL", "info"), "debug|info|warn")
	// Phase 6: S3-compatible object store, retention, SLA, metrics listener.
	s3Endpoint := fs.String("s3-endpoint", os.Getenv("CP_S3_ENDPOINT"), "S3-compatible endpoint (https://s3.<region>.amazonaws.com, http://minio:9000); empty = --object-dir")
	s3Bucket := fs.String("s3-bucket", os.Getenv("CP_S3_BUCKET"), "S3 bucket")
	s3Region := fs.String("s3-region", envOr("CP_S3_REGION", "us-east-1"), "S3 region for signing")
	s3Prefix := fs.String("s3-prefix", os.Getenv("CP_S3_PREFIX"), "key prefix inside the bucket")
	s3PathStyle := fs.Bool("s3-path-style", os.Getenv("CP_S3_PATH_STYLE") == "1", "path-style addressing (MinIO, Ceph)")
	retentionDays := fs.Int("retention-days", envInt("CP_RETENTION_DAYS", 90), "days raw result chunks stay in the object store (findings are kept)")
	supportDays := fs.Int("support-retention-days", envInt("CP_SUPPORT_RETENTION_DAYS", 180), "days support bundles stay in the object store")
	slaSpec := fs.String("sla", os.Getenv("CP_SLA"), "SLA days per severity, e.g. critical=15,high=30,medium=90,low=180 (Tier 3-4 doubled)")
	metricsAddr := fs.String("metrics-addr", os.Getenv("CP_METRICS_ADDR"), "plain-HTTP /metrics listener for a private scrape network (e.g. 127.0.0.1:9100); empty = only /admin/metrics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*logLevel)
	sla, err := parseSLA(*slaSpec)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *dev {
		if _, err := os.Stat(filepath.Join(*pkiDir, "root.pem")); err != nil {
			log.Info("dev: initializing CA", "dir", *pkiDir)
			if err := ca.Init(*pkiDir, "TPRM Dev"); err != nil {
				return err
			}
		}
		if *adminToken == "" {
			*adminToken = "dev"
			log.Warn("dev: admin token is 'dev'")
		}
		if *ownerToken == "" {
			*ownerToken = "owner"
			log.Warn("dev: vendor-owner token is 'owner'")
		}
	}
	issuer, err := ca.Load(*pkiDir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	var st store.Store
	if *dev && *dbURL == "" {
		st = store.NewMemory()
		log.Warn("dev: using in-memory store; nothing persists")
	} else {
		if *dbURL == "" {
			return errors.New("--db or DATABASE_URL required (or --dev)")
		}
		st, err = store.OpenPostgres(ctx, *dbURL)
		if err != nil {
			return err
		}
		log.Info("postgres connected, migrations applied")
	}
	defer st.Close()

	if *publicURL == "" {
		host, _ := os.Hostname()
		_, port, _ := net.SplitHostPort(*mtlsAddr)
		*publicURL = "https://" + host + ":" + port
		log.Warn("--public-url not set; guessing", "url", *publicURL)
	}

	cert, err := loadOrIssueServerCert(issuer, *serverCert, *serverKey, *pkiDir, *publicURL, *dev || *selfIssue, log)
	if err != nil {
		return err
	}
	spoolKey, err := ensureSpoolKey(*pkiDir, *dev || *selfIssue, log)
	if err != nil {
		return err
	}
	releaseKeys, err := ensureReleaseKeys(*pkiDir, *dev || *selfIssue, log)
	if err != nil {
		return err
	}
	if len(releaseKeys) == 0 {
		log.Warn("no release signing key (pki-dir/release-pub.pem): bundle and release publishing is disabled")
	}
	if *adminToken == "" {
		log.Warn("no admin token: /admin is disabled")
	}

	var objects server.ObjectStore = server.DirObjects{Root: *objDir}
	if *s3Endpoint != "" {
		s3 := server.S3Objects{Endpoint: *s3Endpoint, Bucket: *s3Bucket, Region: *s3Region, Prefix: *s3Prefix, PathStyle: *s3PathStyle,
			AccessKey: os.Getenv("CP_S3_ACCESS_KEY"), SecretKey: os.Getenv("CP_S3_SECRET_KEY")}
		if s3.Bucket == "" || s3.AccessKey == "" || s3.SecretKey == "" {
			return errors.New("--s3-endpoint needs --s3-bucket and CP_S3_ACCESS_KEY / CP_S3_SECRET_KEY")
		}
		objects = s3
		log.Info("object store: S3", "endpoint", *s3Endpoint, "bucket", *s3Bucket, "prefix", *s3Prefix, "path_style", *s3PathStyle)
	}
	srv := server.New(server.Config{
		Store: st, CA: issuer, Objects: objects,
		PublicURL: *publicURL, AdminToken: *adminToken, Logger: log, SpoolKey: spoolKey,
		ReleaseKeys: releaseKeys, CanaryPeriod: time.Duration(*canaryHours * float64(time.Hour)), AptDir: *aptDir,
		VendorOwnerToken: *ownerToken, Product: *product, Version: version, Contact: *contact,
		SLADays: sla, RawRetention: time.Duration(*retentionDays) * 24 * time.Hour, SupportRetention: time.Duration(*supportDays) * 24 * time.Hour,
	})
	if *ownerToken == "" {
		log.Warn("no vendor-owner token: scope changes cannot be approved (--owner-token / CP_OWNER_TOKEN)")
	}
	go srv.RunRollout(ctx, time.Minute)
	go srv.RunScheduler(ctx, 30*time.Second)
	go srv.RunWebhooks(ctx)
	go srv.RunRetention(ctx, time.Hour)
	go srv.RunWatch(ctx, 5*time.Minute)
	if *metricsAddr != "" {
		metricsSrv := &http.Server{Addr: *metricsAddr, Handler: srv.MetricsHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("metrics listener", "addr", *metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("metrics listener stopped", "err", err)
			}
		}()
		defer func() { _ = metricsSrv.Close() }()
	}
	enrollSrv := &http.Server{Addr: *enrollAddr, Handler: srv.EnrollHandler(), TLSConfig: server.TLSConfigEnroll(cert),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	mtlsSrv := &http.Server{Addr: *mtlsAddr, Handler: srv.MTLSHandler(), TLSConfig: server.TLSConfigMTLS(cert, issuer),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 60 * time.Second}

	errc := make(chan error, 2)
	go func() {
		log.Info("enroll listener", "addr", *enrollAddr)
		errc <- enrollSrv.ListenAndServeTLS("", "")
	}()
	go func() {
		log.Info("mTLS listener", "addr", *mtlsAddr, "public_url", *publicURL)
		errc <- mtlsSrv.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = enrollSrv.Shutdown(shutCtx)
	_ = mtlsSrv.Shutdown(shutCtx)
	return nil
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// parseSLA reads "critical=15,high=30,..." into days per severity.
func parseSLA(spec string) (map[string]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	out := map[string]int{}
	for k, v := range server.DefaultSLADays {
		out[k] = v
	}
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if !ok || err != nil || n < 0 || !v1.KnownSeverities[strings.ToLower(strings.TrimSpace(k))] {
			return nil, fmt.Errorf("--sla: bad entry %q (want severity=days)", part)
		}
		out[strings.ToLower(strings.TrimSpace(k))] = n
	}
	return out, nil
}

func loadOrIssueServerCert(issuer *ca.CA, certPath, keyPath, pkiDir, publicURL string, dev bool, log *slog.Logger) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}
	certPath = filepath.Join(pkiDir, "server.pem")
	keyPath = filepath.Join(pkiDir, "server-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if !dev {
		return tls.Certificate{}, errors.New("--server-cert/--server-key required (or --self-issue to issue one from the internal CA)")
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		return tls.Certificate{}, err
	}
	hosts := []string{u.Hostname(), "localhost", "127.0.0.1", "cp-api"}
	if hn, _ := os.Hostname(); hn != "" {
		hosts = append(hosts, hn)
	}
	certPEM, keyPEM, err := issuer.IssueServer(dedupe(hosts))
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	log.Info("dev: issued server certificate from intermediate", "hosts", hosts, "path", certPath)
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---- admin CLI (thin HTTP client for the /admin API) ----

// ownerOnly lists the subcommands sent with the vendor-owner token when
// --owner-token is set (PLAN §16: scope approval and attestation).
var ownerOnly = map[string]bool{"approve": true, "reject": true, "attest": true, "site-update": true, "scope-request": true}

func adminCmd(args []string) error {
	if len(args) < 1 {
		usage()
		return errors.New("admin subcommand required")
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin "+sub, flag.ContinueOnError)
	base := fs.String("url", envOr("CP_URL", "https://localhost:9443"), "mTLS listener URL")
	token := fs.String("token", envOr("CP_ADMIN_TOKEN", "dev"), "admin bearer token")
	rootCA := fs.String("ca", os.Getenv("CP_ROOT_CA"), "root CA PEM to trust (default: system roots)")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	vendor := fs.String("vendor", "", "vendor name")
	site := fs.String("site", "", "site name")
	cidrs := fs.String("cidrs", "", "comma-separated allowed CIDRs")
	tz := fs.String("tz", "", "timezone (site default UTC; job window default = site tz)")
	appliance := fs.String("appliance", "", "appliance id")
	siteID := fs.String("site-id", "", "site id filter")
	mode := fs.String("mode", "", "job mode: discovery|inventory|full")
	targets := fs.String("targets", "", "comma-separated target CIDRs/IPs")
	excludes := fs.String("excludes", "", "comma-separated excluded CIDRs/IPs")
	ports := fs.String("ports", "", "standard|full|explicit list")
	cronExpr := fs.String("cron", "", "window start (5-field cron); empty = any time")
	maxDur := fs.Int("max-duration", 0, "window max_duration_s")
	pps := fs.Int("pps", 0, "rate.pps")
	maxHosts := fs.Int("max-hosts", 0, "openvas max_hosts")
	maxChecks := fs.Int("max-checks", 0, "openvas max_checks")
	unsafe := fs.Bool("unsafe", false, "safe_checks=false (site must be unsafe_ok)")
	allowPublic := fs.Bool("allow-public", false, "job may target public ranges the site attests")
	now := fs.Bool("now", false, "run as soon as the appliance polls (ignores the window)")
	fragile := fs.String("fragile-ports", "", "comma-separated fragile device ports (site-update)")
	maxPPS := fs.Int("max-pps", -1, "site max_pps (site-update)")
	maxConc := fs.Int("max-concurrency", -1, "site max_concurrency (site-update)")
	unsafeOK := fs.String("unsafe-ok", "", "true|false (site-update)")
	sitePublic := fs.String("site-allow-public", "", "true|false: site attests public ranges (site-update)")
	lanRoutes := fs.String("lan-routes", "", "CIDR@gateway[,..] for split-network floors, or 'none' to clear (site-update)")
	dir := fs.String("dir", "", "bundle directory from `cp-api bundle build` (publish-bundle)")
	file := fs.String("file", "", "artifact to publish (publish-release)")
	component := fs.String("component", "", "release component, e.g. applianced-linux-amd64 (publish-release)")
	relVersion := fs.String("version", "", "release version (publish-release)")
	keyPath := fs.String("key", envOr("CP_RELEASE_KEY", "dev/pki/release-key.pem"), "release signing key PEM (publish-release)")
	canaryHrs := fs.Float64("canary-hours", 0, "canary period override in hours (publish-*)")
	reason := fs.String("reason", "", "reason recorded with a rollout, policy or review change")
	ownerTok := fs.String("owner-token", os.Getenv("CP_OWNER_TOKEN"), "act as the vendor owner (approve/reject/attest, direct scope edits)")
	actor := fs.String("actor", os.Getenv("CP_ACTOR"), "human identity recorded in the audit log (X-Actor)")
	ip := fs.String("ip", "", "host IP (fragile-set)")
	action := fs.String("action", "", "clear|unclear|mark|unmark (fragile-set)")
	review := fs.String("review", "", "false_positive|accepted|none (review)")
	codify := fs.Bool("codify", false, "also exclude the finding's detector on the site (review --review false_positive)")
	name := fs.String("name", "", "schedule name")
	enabled := fs.String("enabled", "", "true|false (schedule-update)")
	days := fs.Int("days", 30, "calendar horizon in days")
	statusFilter := fs.String("status", "", "filter: pending|approved|rejected (scope-requests)")
	modules := fs.String("modules", "", "comma-separated module list overriding the mode default (create-job, create-schedule, schedule-update)")
	fingerprintOn := fs.Bool("fingerprint", false, "add the nmap fingerprint pass to the job (needs the recorded legal sign-off)")
	udpOn := fs.Bool("udp", false, "add the udp module to the job: the engine's UDP tests, on every host in scope including those with no open TCP port (create-job)")
	fpIntensity := fs.Int("fingerprint-intensity", 5, "nmap --version-intensity 0..9 (with --fingerprint)")
	noOSDetect := fs.Bool("no-os-detection", false, "skip nmap -O in the fingerprint pass (with --fingerprint)")
	reference := fs.String("reference", "", "legal review reference (signoff)")
	note := fs.String("note", "", "free-text note (signoff)")
	revoke := fs.Bool("revoke", false, "remove the recorded sign-off (signoff)")
	kbPath := fs.String("kb", "", "Qualys KnowledgeBase XML to join QIDs with CVEs/titles (import-qualys)")
	scannedAt := fs.String("scanned-at", "", "RFC3339 time of the external scan (import-qualys, default now)")
	scanner := fs.String("scanner", "qualys", "external scanner name (parity)")
	daysBack := fs.Int("days-back", 60, "window in days for the parity report")
	minSeverity := fs.String("min-severity", "medium", "lowest severity compared (parity)")
	weeks := fs.Int("weeks", 12, "trend horizon in weeks")
	outPath := fs.String("out", "", "write the export to this file instead of stdout (export)")
	exportStatus := fs.String("status-filter", "all", "open|fixed|all (export findings)")
	hookURL := fs.String("url-hook", "", "webhook receiver URL (webhook add)")
	hookSecret := fs.String("secret", "", "webhook HMAC secret (webhook add)")
	hookEvents := fs.String("events", "", "comma-separated event names or prefixes like finding.* (webhook add; empty = all)")
	dryRun := fs.Bool("dry-run", false, "count instead of deleting (retention)")
	rest, err := parseInterleaved(fs, args[1:])
	if err != nil {
		return err
	}
	cl, err := adminClient(*rootCA, *insecure)
	if err != nil {
		return err
	}
	callRaw := func(method, path string, body io.Reader, headers map[string]string) (int, []byte, error) {
		req, err := http.NewRequest(method, strings.TrimRight(*base, "/")+path, body)
		if err != nil {
			return 0, nil, err
		}
		bearer := *token
		if *ownerTok != "" && ownerOnly[sub] {
			bearer = *ownerTok
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		if *actor != "" {
			req.Header.Set("X-Actor", *actor)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, nil
	}
	call := func(method, path string, body any) (int, []byte, error) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		return callRaw(method, path, &buf, map[string]string{"Content-Type": "application/json"})
	}
	var (
		status int
		out    []byte
	)
	switch sub {
	case "create-appliance":
		if *vendor == "" || *site == "" {
			return errors.New("--vendor and --site required")
		}
		var cs []string
		if *cidrs != "" {
			cs = strings.Split(*cidrs, ",")
		}
		status, out, err = call("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: *vendor, Site: *site, AllowedCIDRs: cs, TZ: *tz})
	case "create-job":
		if *appliance == "" || *mode == "" || *targets == "" {
			return errors.New("--appliance, --mode and --targets required")
		}
		req := v1.AdminJobRequest{ApplianceID: *appliance, Mode: *mode, Targets: splitCSV(*targets), Excludes: splitCSV(*excludes), Ports: *ports, AllowPublic: *allowPublic,
			Modules: splitCSV(*modules), UDP: *udpOn}
		if *fingerprintOn {
			req.Fingerprint = &v1.FingerprintParams{OSDetection: !*noOSDetect, Intensity: *fpIntensity}
		}
		if *cronExpr != "" {
			req.Window = &v1.Window{Cron: *cronExpr, TZ: *tz, MaxDurationS: *maxDur}
		} else if *maxDur > 0 {
			req.Window = &v1.Window{MaxDurationS: *maxDur}
		}
		if *pps > 0 {
			req.Rate = &v1.Rate{PPS: *pps, PerHostParallel: 2}
		}
		if *maxHosts > 0 || *maxChecks > 0 {
			cfg := *mode
			if cfg == "discovery" {
				return errors.New("--max-hosts/--max-checks only apply to inventory/full")
			}
			req.OpenVAS = &v1.OpenVASParams{Config: cfg, MaxHosts: orDefault(*maxHosts, 4), MaxChecks: orDefault(*maxChecks, 4), FragilePortsExclude: true}
		}
		if *unsafe {
			f := false
			req.SafeChecks = &f
		}
		status, out, err = call("POST", "/admin/jobs", req)
		if err == nil && status == 201 && *now {
			var jv v1.AdminJobView
			if json.Unmarshal(out, &jv) == nil {
				status, out, err = call("POST", "/admin/jobs/"+jv.ID+"/run-now", nil)
			}
		}
	case "jobs":
		status, out, err = call("GET", "/admin/jobs?appliance="+url.QueryEscape(*appliance)+"&site="+url.QueryEscape(*siteID), nil)
	case "job", "cancel-job", "run-now", "job-hosts":
		if len(rest) < 1 {
			return errors.New("job id required")
		}
		switch sub {
		case "job":
			status, out, err = call("GET", "/admin/jobs/"+rest[0], nil)
		case "cancel-job":
			status, out, err = call("POST", "/admin/jobs/"+rest[0]+"/cancel", nil)
		case "run-now":
			status, out, err = call("POST", "/admin/jobs/"+rest[0]+"/run-now", nil)
		case "job-hosts":
			status, out, err = call("GET", "/admin/jobs/"+rest[0]+"/hosts", nil)
		}
	case "sites":
		status, out, err = call("GET", "/admin/sites", nil)
	case "site", "hosts", "findings":
		if len(rest) < 1 {
			return errors.New("site id required")
		}
		path := "/admin/sites/" + rest[0]
		if sub != "site" {
			path += "/" + sub
		}
		status, out, err = call("GET", path, nil)
	case "site-update":
		if len(rest) < 1 {
			return errors.New("site id required")
		}
		upd := v1.AdminSiteUpdate{}
		if *cidrs != "" {
			v := splitCSV(*cidrs)
			upd.AllowedCIDRs = &v
		}
		if *excludes != "" {
			v := splitCSV(*excludes)
			upd.Excludes = &v
		}
		if *fragile != "" {
			var v []int
			for _, p := range splitCSV(*fragile) {
				n, err := strconv.Atoi(p)
				if err != nil {
					return fmt.Errorf("bad fragile port %q", p)
				}
				v = append(v, n)
			}
			upd.FragilePorts = &v
		}
		if *tz != "" {
			upd.TZ = tz
		}
		if *maxPPS >= 0 {
			upd.MaxPPS = maxPPS
		}
		if *maxConc >= 0 {
			upd.MaxConcurrency = maxConc
		}
		if *unsafeOK != "" {
			b, err := strconv.ParseBool(*unsafeOK)
			if err != nil {
				return err
			}
			upd.UnsafeOK = &b
		}
		if *sitePublic != "" {
			b, err := strconv.ParseBool(*sitePublic)
			if err != nil {
				return err
			}
			upd.AllowPublic = &b
		}
		if *lanRoutes != "" {
			routes := []v1.LANRoute{}
			if *lanRoutes != "none" {
				routes, err = parseLANRoutes(*lanRoutes)
				if err != nil {
					return err
				}
			}
			upd.LANRoutes = &routes
		}
		status, out, err = call("PATCH", "/admin/sites/"+rest[0], upd)
	case "publish-bundle":
		if *dir == "" {
			return errors.New("--dir required (output of `cp-api bundle build`)")
		}
		status, out, err = publishBundleDir(callRaw, *dir, *canaryHrs)
	case "publish-release":
		if *file == "" || *component == "" || *relVersion == "" {
			return errors.New("--file, --component and --version required")
		}
		status, out, err = publishRelease(callRaw, *file, *component, *relVersion, *keyPath, *canaryHrs)
	case "bundles":
		status, out, err = call("GET", "/admin/bundles", nil)
	case "releases":
		status, out, err = call("GET", "/admin/releases", nil)
	case "rollout":
		switch {
		case len(rest) == 3 && rest[0] == "bundle":
			status, out, err = call("POST", "/admin/bundles/"+rest[1]+"/rollout", v1.AdminRolloutRequest{Status: rest[2], Reason: *reason})
		case len(rest) == 4 && rest[0] == "release":
			status, out, err = call("POST", "/admin/releases/"+rest[1]+"/"+rest[2]+"/rollout", v1.AdminRolloutRequest{Status: rest[3], Reason: *reason})
		default:
			return errors.New("usage: admin rollout bundle VERSION STATUS | admin rollout release COMPONENT VERSION STATUS")
		}
	case "set-canary":
		if len(rest) < 2 {
			return errors.New("usage: admin set-canary ID true|false")
		}
		b, perr := strconv.ParseBool(rest[1])
		if perr != nil {
			return perr
		}
		status, out, err = call("PATCH", "/admin/appliances/"+rest[0], v1.AdminApplianceUpdate{Canary: &b})

	// ---- Phase 4 ----
	case "changes", "fragile", "exclusions", "tuning", "coverage":
		if len(rest) < 1 {
			return errors.New("site id required")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/"+sub, nil)
	case "calendar":
		if len(rest) < 1 {
			return errors.New("site id required")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/calendar?days="+strconv.Itoa(*days), nil)
	case "vendor-coverage":
		if len(rest) < 1 {
			return errors.New("vendor id required")
		}
		status, out, err = call("GET", "/admin/vendors/"+rest[0]+"/coverage", nil)
	case "alerts":
		status, out, err = call("GET", "/admin/alerts", nil)
	case "scope-request":
		if len(rest) < 1 || *cidrs == "" {
			return errors.New("usage: admin scope-request SITE --cidrs a/b,c/d --reason R")
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/scope-requests", v1.AdminScopeRequest{AllowedCIDRs: splitCSV(*cidrs), Reason: *reason})
	case "scope-requests":
		if len(rest) < 1 {
			return errors.New("site id required")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/scope-requests?status="+*statusFilter, nil)
	case "approve", "reject":
		if len(rest) < 2 {
			return fmt.Errorf("usage: admin %s SITE REQUEST_ID [--reason R] (needs --owner-token)", sub)
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/scope-requests/"+rest[1]+"/"+sub, v1.AdminDecision{Reason: *reason})
	case "attest":
		if len(rest) < 1 {
			return errors.New("usage: admin attest SITE [--reason R] (needs --owner-token)")
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/attest", v1.AdminDecision{Reason: *reason})
	case "fragile-set":
		if len(rest) < 1 || *ip == "" || *action == "" {
			return errors.New("usage: admin fragile-set SITE --ip IP --action clear|unclear|mark|unmark --reason R")
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/fragile", v1.AdminFragileRequest{IP: *ip, Action: *action, Reason: *reason})
	case "exclude":
		if len(rest) < 2 {
			return errors.New("usage: admin exclude SITE VT --reason R")
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/exclusions", v1.AdminExclusionRequest{VT: rest[1], Reason: *reason})
	case "unexclude":
		if len(rest) < 2 {
			return errors.New("usage: admin unexclude SITE VT")
		}
		status, out, err = call("DELETE", "/admin/sites/"+rest[0]+"/exclusions/"+rest[1]+"?reason="+url.QueryEscape(*reason), nil)
	case "finding", "host":
		if len(rest) < 1 {
			return errors.New(sub + " id required")
		}
		status, out, err = call("GET", "/admin/"+sub+"s/"+rest[0], nil)
	case "review":
		if len(rest) < 1 {
			return errors.New("usage: admin review FINDING --review false_positive|accepted|none --reason R [--codify]")
		}
		rv := *review
		if rv == "none" {
			rv = ""
		}
		status, out, err = call("PATCH", "/admin/findings/"+rest[0], v1.AdminFindingReview{Review: rv, Reason: *reason, Codify: *codify})
	case "create-schedule":
		if *appliance == "" || *mode == "" || *targets == "" || *cronExpr == "" {
			return errors.New("usage: admin create-schedule --appliance ID --mode M --targets a/b --cron \"0 22 * * 6\" [--tz TZ --max-duration S --excludes .. --ports .. --name N]")
		}
		status, out, err = call("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: *appliance, Name: *name, Mode: *mode, Targets: splitCSV(*targets),
			Excludes: splitCSV(*excludes), Ports: *ports, Cron: *cronExpr, TZ: *tz, MaxDurationS: *maxDur, Modules: splitCSV(*modules)})
	case "schedules":
		status, out, err = call("GET", "/admin/schedules?site="+*siteID, nil)
	case "schedule", "delete-schedule":
		if len(rest) < 1 {
			return errors.New("schedule id required")
		}
		if sub == "schedule" {
			status, out, err = call("GET", "/admin/schedules/"+rest[0], nil)
		} else {
			status, out, err = call("DELETE", "/admin/schedules/"+rest[0], nil)
		}
	case "schedule-update":
		if len(rest) < 1 {
			return errors.New("usage: admin schedule-update ID [--cron .. --tz .. --targets .. --mode .. --name .. --max-duration S --enabled true|false]")
		}
		req := v1.AdminScheduleRequest{Name: *name, Mode: *mode, Cron: *cronExpr, TZ: *tz, MaxDurationS: *maxDur, Ports: *ports}
		if *targets != "" {
			req.Targets = splitCSV(*targets)
		}
		if *modules != "" {
			req.Modules = splitCSV(*modules)
			if *modules == "default" {
				req.Modules = []string{}
			}
		}
		if *excludes != "" {
			req.Excludes = splitCSV(*excludes)
		}
		if *enabled != "" {
			b, perr := strconv.ParseBool(*enabled)
			if perr != nil {
				return perr
			}
			req.Enabled = &b
		}
		status, out, err = call("PATCH", "/admin/schedules/"+rest[0], req)
	case "transparency":
		status, out, err = call("GET", "/transparency.json", nil)
	case "signoff":
		// Phase 5 (PLAN §21): record, show or revoke the legal sign-off for nmap.
		tool := v1.SignoffNmap
		if len(rest) > 0 {
			tool = rest[0]
		}
		switch {
		case *revoke:
			status, out, err = call("DELETE", "/admin/signoffs/"+tool, nil)
		case *reference != "":
			status, out, err = call("PUT", "/admin/signoffs/"+tool, v1.AdminSignoffRequest{Reference: *reference, Note: *note})
		default:
			status, out, err = call("GET", "/admin/signoffs/"+tool, nil)
		}
	case "onboarding":
		if len(rest) < 1 {
			return errors.New("usage: admin onboarding SITE")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/onboarding", nil)
	// Phase 6 (Qualys replacement).
	case "import-qualys":
		if len(rest) < 2 {
			return errors.New("usage: admin import-qualys SITE EXPORT.csv|.xml [--kb kb.xml] [--scanned-at RFC3339]")
		}
		data, rerr := os.ReadFile(rest[1])
		if rerr != nil {
			return rerr
		}
		var kb qualys.KB
		if *kbPath != "" {
			kbData, kerr := os.ReadFile(*kbPath)
			if kerr != nil {
				return kerr
			}
			if kb, kerr = qualys.ParseKB(kbData); kerr != nil {
				return kerr
			}
		}
		hosts, perr := qualys.Parse(data, kb)
		if perr != nil {
			return perr
		}
		req := v1.ExternalScanRequest{Scanner: qualys.Scanner, Hosts: hosts}
		if *scannedAt != "" {
			t, terr := time.Parse(time.RFC3339, *scannedAt)
			if terr != nil {
				return fmt.Errorf("--scanned-at: %w", terr)
			}
			req.ScannedAt = &t
		}
		fmt.Fprintln(os.Stderr, "[import-qualys] parsed "+qualys.Summary(hosts))
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/external-scans", req)
	case "parity":
		if len(rest) < 1 {
			return errors.New("usage: admin parity SITE [--scanner qualys] [--days-back N] [--min-severity S]")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/parity?scanner="+url.QueryEscape(*scanner)+"&days="+strconv.Itoa(*daysBack)+"&min_severity="+url.QueryEscape(*minSeverity), nil)
	case "summary":
		if len(rest) < 1 {
			return errors.New("usage: admin summary SITE | admin vendor-summary VENDOR")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/summary", nil)
	case "vendor-summary":
		if len(rest) < 1 {
			return errors.New("usage: admin vendor-summary VENDOR")
		}
		status, out, err = call("GET", "/admin/vendors/"+rest[0]+"/summary", nil)
	case "trend":
		if len(rest) < 1 {
			return errors.New("usage: admin trend SITE [--weeks N]")
		}
		status, out, err = call("GET", "/admin/sites/"+rest[0]+"/trend?weeks="+strconv.Itoa(*weeks), nil)
	case "export":
		if len(rest) < 2 || (rest[1] != "findings" && rest[1] != "hosts") {
			return errors.New("usage: admin export SITE findings|hosts [--status-filter open|fixed|all] [--out file.csv] ; admin export --vendor-id V findings")
		}
		path := "/admin/sites/" + rest[0] + "/export/" + rest[1] + ".csv"
		if rest[1] == "findings" {
			path += "?status=" + url.QueryEscape(*exportStatus)
		}
		status, out, err = callRaw("GET", path, nil, nil)
		if err == nil && status < 300 && *outPath != "" {
			if werr := os.WriteFile(*outPath, out, 0o644); werr != nil {
				return werr
			}
			out = []byte("wrote " + *outPath)
		}
	case "vendor-export":
		if len(rest) < 1 {
			return errors.New("usage: admin vendor-export VENDOR [--status-filter open|fixed|all] [--out file.csv]")
		}
		status, out, err = callRaw("GET", "/admin/vendors/"+rest[0]+"/export/findings.csv?status="+url.QueryEscape(*exportStatus), nil, nil)
		if err == nil && status < 300 && *outPath != "" {
			if werr := os.WriteFile(*outPath, out, 0o644); werr != nil {
				return werr
			}
			out = []byte("wrote " + *outPath)
		}
	case "webhook":
		if len(rest) < 1 {
			return errors.New("usage: admin webhook add --url-hook URL [--secret S] [--events e1,e2] | list | delete ID | test ID | deliveries ID")
		}
		switch rest[0] {
		case "add":
			if *hookURL == "" {
				return errors.New("--url-hook required")
			}
			status, out, err = call("POST", "/admin/webhooks", v1.AdminWebhookRequest{URL: *hookURL, Secret: *hookSecret, Events: splitCSV(*hookEvents)})
		case "list":
			status, out, err = call("GET", "/admin/webhooks", nil)
		case "delete", "test", "deliveries":
			if len(rest) < 2 {
				return errors.New("webhook id required")
			}
			switch rest[0] {
			case "delete":
				status, out, err = call("DELETE", "/admin/webhooks/"+rest[1], nil)
			case "test":
				status, out, err = call("POST", "/admin/webhooks/"+rest[1]+"/test", nil)
			default:
				status, out, err = call("GET", "/admin/webhooks/"+rest[1]+"/deliveries", nil)
			}
		default:
			return fmt.Errorf("unknown webhook subcommand %q", rest[0])
		}
	case "retention":
		q := ""
		if *dryRun {
			q = "?dry_run=1"
		}
		status, out, err = call("POST", "/admin/retention/run"+q, nil)
	case "sla":
		status, out, err = call("GET", "/admin/sla", nil)
	case "metrics":
		status, out, err = callRaw("GET", "/admin/metrics", nil, nil)
	case "feed-gaps":
		status, out, err = call("GET", "/admin/feed-gaps?site="+url.QueryEscape(*siteID), nil)
	case "agent-inventory":
		if len(rest) < 2 {
			return errors.New("usage: admin agent-inventory SITE FILE.json")
		}
		b, rerr := os.ReadFile(rest[1])
		if rerr != nil {
			return rerr
		}
		var req v1.AdminAgentInventoryRequest
		if jerr := json.Unmarshal(b, &req); jerr != nil {
			// Accept a bare array of hosts too.
			if jerr2 := json.Unmarshal(b, &req.Hosts); jerr2 != nil {
				return fmt.Errorf("inventory file: %w", jerr)
			}
		}
		status, out, err = call("POST", "/admin/sites/"+rest[0]+"/agent-inventory", req)
	case "list":
		status, out, err = call("GET", "/admin/appliances", nil)
	case "get":
		if len(rest) < 1 {
			return errors.New("appliance id required")
		}
		status, out, err = call("GET", "/admin/appliances/"+rest[0], nil)
	case "code":
		if len(rest) < 1 {
			return errors.New("appliance id required")
		}
		status, out, err = call("POST", "/admin/appliances/"+rest[0]+"/code", nil)
	case "revoke":
		if len(rest) < 1 {
			return errors.New("appliance id required")
		}
		reason := ""
		if len(rest) > 1 {
			reason = rest[1]
		}
		status, out, err = call("POST", "/admin/appliances/"+rest[0]+"/revoke", map[string]string{"reason": reason})
	case "directive":
		if len(rest) < 2 {
			return errors.New("usage: admin directive ID TYPE [JSON]")
		}
		req := v1.AdminDirectiveRequest{Type: rest[1]}
		if len(rest) > 2 {
			if err := json.Unmarshal([]byte(rest[2]), &req.Payload); err != nil {
				return fmt.Errorf("payload: %w", err)
			}
		}
		status, out, err = call("POST", "/admin/appliances/"+rest[0]+"/directives", req)
	case "directives":
		if len(rest) < 1 {
			return errors.New("appliance id required")
		}
		status, out, err = call("GET", "/admin/appliances/"+rest[0]+"/directives", nil)
	default:
		return fmt.Errorf("unknown admin subcommand %q", sub)
	}
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSpace(string(out)))
	if status >= 300 {
		return fmt.Errorf("http %d", status)
	}
	return nil
}

// parseInterleaved parses flags wherever they stand among the positional
// arguments. The flag package stops at the first positional one, which
// silently dropped every flag in "rollout bundle VERSION held --reason R"
// or "export SITE findings --status-filter fixed", the order the usage text
// and the README show.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return rest, nil
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
}

func adminClient(rootCA string, insecure bool) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec
	if rootCA != "" {
		pem, err := os.ReadFile(rootCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificates in " + rootCA)
		}
		cfg.RootCAs = pool
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
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
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func envFloat(k string, d float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return d
}
