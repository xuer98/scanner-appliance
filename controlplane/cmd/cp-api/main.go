// cp-api is the appliance control plane (PLAN §17).
//
//	cp-api ca init --dir /pki [--org "TPRM"]
//	cp-api serve  --db postgres://... | --dev
//	cp-api admin create-appliance --vendor V --site S --cidrs 10.0.0.0/8[,..]
//	cp-api admin get <appliance_id>
//	cp-api admin directive <appliance_id> <type> [json payload]
//	cp-api admin directives <appliance_id>
//	cp-api admin revoke <appliance_id> [reason]
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
	"strings"
	"syscall"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/server"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
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
  serve --db URL | --dev   --pki-dir DIR --enroll-addr :8443 --mtls-addr :9443 --public-url URL
  ca init --dir DIR [--org NAME]
  admin create-appliance --vendor V --site S [--cidrs a/b,c/d] [--tz TZ]
  admin get|directives|revoke ID ; admin directive ID TYPE [JSON]
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
	fmt.Printf("wrote %s/{root.pem,root-key.pem,intermediate.pem,intermediate-key.pem}\n", *dir)
	fmt.Println("move root-key.pem offline; embed root.pem into applianced (daemon/internal/pki/roots.pem)")
	return nil
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

	cert, err := loadOrIssueServerCert(issuer, *serverCert, *serverKey, *pkiDir, *publicURL, *dev, log)
	if err != nil {
		return err
	}
	if *adminToken == "" {
		log.Warn("no admin token: /admin is disabled")
	}

	srv := server.New(server.Config{
		Store: st, CA: issuer, Objects: server.DirObjects{Root: *objDir},
		PublicURL: *publicURL, AdminToken: *adminToken, Logger: log,
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
		return tls.Certificate{}, errors.New("--server-cert/--server-key required outside --dev")
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
	tz := fs.String("tz", "UTC", "site timezone")
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
