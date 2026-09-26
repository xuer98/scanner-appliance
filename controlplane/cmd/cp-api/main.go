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
  admin jobs [--appliance ID] [--site ID] | job ID | cancel-job ID | run-now ID | job-hosts ID
  admin sites | site ID | site-update ID [--cidrs ..] [--excludes ..] [--fragile-ports ..] [--max-pps N] [--max-concurrency N] [--unsafe-ok B] [--allow-public B]
  admin hosts SITE | findings SITE | agent-inventory SITE FILE.json
  admin flags: --url https://host:9443 (env CP_URL) --token T (env CP_ADMIN_TOKEN) --ca root.pem (env CP_ROOT_CA)`)
}

func caCmd(args []string) error {
	if len(args) < 1 || args[0] != "init" {
		return errors.New("usage: cp-api ca init --dir DIR [--org NAME]")
	}
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	dir := fs.String("dir", "pki", "output directory")
	org := fs.String("org", "TPRM", "organization name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if err := ca.Init(*dir, *org); err != nil {
		return err
	}
	if _, err := ensureSpoolKey(*dir, true, slog.Default()); err != nil {
		return err
	}
	fmt.Printf("wrote %s/{root.pem,root-key.pem,intermediate.pem,intermediate-key.pem,spool-key.pem}\n", *dir)
	fmt.Println("move root-key.pem offline; embed root.pem into applianced (daemon/internal/pki/roots.pem)")
	fmt.Println("spool-key.pem decrypts uploaded results; back it up with the intermediate key")
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
	logLevel := fs.String("log-level", envOr("CP_LOG_LEVEL", "info"), "debug|info|warn")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*logLevel)

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
	if *adminToken == "" {
		log.Warn("no admin token: /admin is disabled")
	}

	srv := server.New(server.Config{
		Store: st, CA: issuer, Objects: server.DirObjects{Root: *objDir},
		PublicURL: *publicURL, AdminToken: *adminToken, Logger: log, SpoolKey: spoolKey,
	})
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
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()
	cl, err := adminClient(*rootCA, *insecure)
	if err != nil {
		return err
	}
	call := func(method, path string, body any) (int, []byte, error) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, err := http.NewRequest(method, strings.TrimRight(*base, "/")+path, &buf)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := cl.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, nil
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
		req := v1.AdminJobRequest{ApplianceID: *appliance, Mode: *mode, Targets: splitCSV(*targets), Excludes: splitCSV(*excludes), Ports: *ports, AllowPublic: *allowPublic}
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
		status, out, err = call("PATCH", "/admin/sites/"+rest[0], upd)
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
