// Package server implements the cp-api HTTP surface (PLAN §17.2).
//
// Two listeners:
//   - enroll listener: TLS, no client cert, serves only POST /v1/enroll.
//   - mTLS listener: TLS requiring a client certificate chained to the
//     issuing intermediate; serves everything else under /v1/ and /admin/.
//
// Admin routes are bearer-token protected here; in production they sit
// behind portal SSO.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/codes"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/guard"
	"github.com/tprm/scanner-appliance/internal/seal"
)

const (
	// DefaultPollInterval is the heartbeat interval handed out at enrollment.
	DefaultPollInterval = 60 * time.Second
	// OnlineWindow: online if a heartbeat arrived within 3 intervals (PLAN §8.4).
	OnlineWindow = 3 * DefaultPollInterval
	// MaxSkew before the server flags the appliance clock.
	MaxSkew = 5 * time.Second

	maxJSONBody          = 1 << 20  // 1 MiB
	maxSupportBundleSize = 64 << 20 // 64 MiB
)

// Config for a Server.
type Config struct {
	Store      store.Store
	CA         *ca.CA
	Objects    ObjectStore
	PublicURL  string // what appliances are told to use for mTLS traffic
	AdminToken string
	Logger     *slog.Logger
	// SpoolKey decrypts result chunks (PLAN §9). nil generates an ephemeral
	// key with a warning: fine for tests and --dev, useless in production
	// because a restart strands every appliance's spool.
	SpoolKey *SpoolKey
	// Now is overridable for tests.
	Now func() time.Time
	// Phase 3 (PLAN §13, §14): public keys that bundles and releases must be
	// signed with (pki-dir/release-pub.pem; several for rotation), the
	// canary period before general release, how long to wait for an
	// appliance to report a version before re-queueing its update, and the
	// directory served as the apt security mirror under /apt/.
	ReleaseKeys  []*ecdsa.PublicKey
	CanaryPeriod time.Duration
	RequeueAfter time.Duration
	AptDir       string
}

type Server struct {
	cfg       Config
	log       *slog.Logger
	limiter   *ipLimiter
	rolloutMu sync.Mutex
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Objects == nil {
		cfg.Objects = DiscardObjects{}
	}
	if cfg.SpoolKey == nil {
		k, err := seal.GenerateKey()
		if err != nil {
			panic(err)
		}
		cfg.SpoolKey = &SpoolKey{Key: k}
		cfg.Logger.Warn("no spool key configured; using an ephemeral one (results spooled against it are lost on restart)")
	}
	return &Server{cfg: cfg, log: cfg.Logger, limiter: newIPLimiter(10, time.Minute)}
}

// EnrollHandler serves the no-client-cert listener.
func (s *Server) EnrollHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return logging(s.log, mux)
}

// MTLSHandler serves the client-cert listener.
func (s *Server) MTLSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/renew", s.withAppliance(s.handleRenew))
	mux.HandleFunc("POST /v1/appliances/{id}/heartbeat", s.withAppliance(s.handleHeartbeat))
	mux.HandleFunc("POST /v1/appliances/{id}/support", s.withAppliance(s.handleSupport))
	mux.HandleFunc("POST /v1/appliances/{id}/wipe", s.withAppliance(s.handleWipe))
	mux.HandleFunc("GET /v1/appliances/{id}/jobs", s.withAppliance(s.handleJobs))
	mux.HandleFunc("POST /v1/jobs/{job}/status", s.withAppliance(s.handleJobStatus))
	mux.HandleFunc("POST /v1/jobs/{job}/results", s.withAppliance(s.handleResults))
	mux.HandleFunc("GET /v1/bundles/{version}/manifest", s.withAppliance(s.handleBundleManifest))
	mux.HandleFunc("GET /v1/bundles/{version}/files/{sha256}", s.withAppliance(s.handleBundleFile))
	mux.HandleFunc("GET /v1/releases/{component}/{version}", s.withAppliance(s.handleRelease))
	mux.HandleFunc("GET /apt/{path...}", s.withAppliance(s.handleApt))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	mux.HandleFunc("POST /admin/appliances", s.withAdmin(s.adminCreateAppliance))
	mux.HandleFunc("GET /admin/appliances", s.withAdmin(s.adminListAppliances))
	mux.HandleFunc("GET /admin/appliances/{id}", s.withAdmin(s.adminGetAppliance))
	mux.HandleFunc("POST /admin/appliances/{id}/code", s.withAdmin(s.adminReissueCode))
	mux.HandleFunc("POST /admin/appliances/{id}/revoke", s.withAdmin(s.adminRevoke))
	mux.HandleFunc("POST /admin/appliances/{id}/directives", s.withAdmin(s.adminCreateDirective))
	mux.HandleFunc("GET /admin/appliances/{id}/directives", s.withAdmin(s.adminListDirectives))
	mux.HandleFunc("PATCH /admin/appliances/{id}", s.withAdmin(s.adminUpdateAppliance))

	mux.HandleFunc("POST /admin/bundles/missing", s.withAdmin(s.adminMissingBundleFiles))
	mux.HandleFunc("PUT /admin/bundles/files/{sha256}", s.withAdmin(s.adminPutBundleFile))
	mux.HandleFunc("POST /admin/bundles", s.withAdmin(s.adminPublishBundle))
	mux.HandleFunc("GET /admin/bundles", s.withAdmin(s.adminListBundles))
	mux.HandleFunc("GET /admin/bundles/{version}", s.withAdmin(s.adminGetBundle))
	mux.HandleFunc("POST /admin/bundles/{version}/rollout", s.withAdmin(s.adminBundleRollout))
	mux.HandleFunc("PUT /admin/releases/{component}/{version}", s.withAdmin(s.adminPutRelease))
	mux.HandleFunc("GET /admin/releases", s.withAdmin(s.adminListReleases))
	mux.HandleFunc("POST /admin/releases/{component}/{version}/rollout", s.withAdmin(s.adminReleaseRollout))

	mux.HandleFunc("POST /admin/jobs", s.withAdmin(s.adminCreateJob))
	mux.HandleFunc("GET /admin/jobs", s.withAdmin(s.adminListJobs))
	mux.HandleFunc("GET /admin/jobs/{id}", s.withAdmin(s.adminGetJob))
	mux.HandleFunc("POST /admin/jobs/{id}/cancel", s.withAdmin(s.adminCancelJob))
	mux.HandleFunc("POST /admin/jobs/{id}/run-now", s.withAdmin(s.adminRunJobNow))
	mux.HandleFunc("GET /admin/jobs/{id}/hosts", s.withAdmin(s.adminJobHosts))
	mux.HandleFunc("GET /admin/sites", s.withAdmin(s.adminListSites))
	mux.HandleFunc("GET /admin/sites/{id}", s.withAdmin(s.adminGetSite))
	mux.HandleFunc("PATCH /admin/sites/{id}", s.withAdmin(s.adminUpdateSite))
	mux.HandleFunc("GET /admin/sites/{id}/hosts", s.withAdmin(s.adminSiteHosts))
	mux.HandleFunc("GET /admin/sites/{id}/findings", s.withAdmin(s.adminSiteFindings))
	mux.HandleFunc("POST /admin/sites/{id}/agent-inventory", s.withAdmin(s.adminAgentInventory))
	return logging(s.log, mux)
}

// TLSConfigEnroll is the server TLS config for the enroll listener.
func TLSConfigEnroll(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// TLSConfigMTLS requires and verifies a client certificate chained to the intermediate.
// Admin clients (portal, CLI) must also present a cert in this build; in
// production the admin path is a separate SSO-fronted listener.
func TLSConfigMTLS(cert tls.Certificate, c *ca.CA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    c.ClientPool(),
	}
}

// ---- middleware ----

type ctxKey int

const applianceKey ctxKey = 1

func applianceFrom(r *http.Request) *store.Appliance {
	a, _ := r.Context().Value(applianceKey).(*store.Appliance)
	return a
}

// withAppliance authenticates the peer certificate: chain already verified
// by TLS; here we bind serial → appliance row, check the revoked set on
// every request (PLAN §7.3), and check the path id matches the cert CN.
func (s *Server) withAppliance(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peer := peerCert(r)
		if peer == nil {
			writeErr(w, http.StatusUnauthorized, "client certificate required", "no_cert")
			return
		}
		serial := ca.SerialHex(peer.SerialNumber)
		revoked, err := s.cfg.Store.IsRevoked(r.Context(), serial)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store error", "store")
			return
		}
		if revoked {
			writeErr(w, http.StatusForbidden, "certificate revoked", "revoked")
			return
		}
		a, err := s.cfg.Store.GetApplianceBySerial(r.Context(), serial)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusForbidden, "unknown certificate", "unknown_cert")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store error", "store")
			return
		}
		if peer.Subject.CommonName != a.ID {
			writeErr(w, http.StatusForbidden, "certificate subject mismatch", "subject")
			return
		}
		if id := r.PathValue("id"); id != "" && id != a.ID {
			writeErr(w, http.StatusForbidden, "certificate does not match appliance id", "id_mismatch")
			return
		}
		switch a.Status {
		case v1.StatusEnrolled, v1.StatusQuarantined:
		default:
			writeErr(w, http.StatusForbidden, "appliance is "+a.Status, "status")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), applianceKey, a)))
	}
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			writeErr(w, http.StatusForbidden, "admin api disabled (no token configured)", "admin_disabled")
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.AdminToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "bad admin token", "admin_auth")
			return
		}
		next(w, r)
	}
}

func peerCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

// ---- /v1/enroll ----

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := s.cfg.Now()
	if !s.limiter.allow(ip, now) {
		writeErr(w, http.StatusTooManyRequests, "rate limited", "rate")
		return
	}
	var req v1.EnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	logAttempt := func(aplID string, ok bool, reason string) {
		_ = s.cfg.Store.LogEnrollAttempt(r.Context(), store.EnrollAttempt{At: now, SourceIP: ip, ApplianceID: aplID, OK: ok, Reason: reason})
		s.log.Info("enroll attempt", "ip", ip, "appliance", aplID, "ok", ok, "reason", reason)
	}
	norm, err := codes.Normalize(req.Code)
	if err != nil {
		logAttempt("", false, "malformed_code")
		writeErr(w, http.StatusBadRequest, "invalid code", "invalid_code")
		return
	}
	ec, err := s.cfg.Store.GetEnrollmentCodeByHash(r.Context(), codes.Hash(norm))
	if errors.Is(err, store.ErrNotFound) {
		logAttempt("", false, "unknown_code")
		writeErr(w, http.StatusUnauthorized, "invalid code", "invalid_code")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	reject := func(reason string) {
		_, _ = s.cfg.Store.BumpCodeAttempts(r.Context(), ec.CodeHash)
		logAttempt(ec.ApplianceID, false, reason)
		writeErr(w, http.StatusUnauthorized, "invalid code", "invalid_code")
	}
	switch {
	case ec.UsedAt != nil:
		reject("code_used")
		return
	case now.After(ec.ExpiresAt):
		reject("code_expired")
		return
	case ec.Attempts >= codes.MaxAttempts:
		reject("code_locked")
		return
	}
	apl, err := s.cfg.Store.GetAppliance(r.Context(), ec.ApplianceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	if apl.Status != v1.StatusPending {
		reject("appliance_" + apl.Status)
		return
	}
	site, err := s.cfg.Store.GetSite(r.Context(), apl.SiteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	issued, err := s.cfg.CA.IssueAppliance(req.CSRPEM, apl.ID, site.VendorID, site.ID)
	if err != nil {
		reject("bad_csr:" + err.Error())
		return
	}
	err = s.cfg.Store.CompleteEnrollment(r.Context(), store.EnrollUpdate{
		ApplianceID: apl.ID, CodeHash: ec.CodeHash, CertSerial: issued.Serial, CertNotAfter: issued.NotAfter,
		Version: req.Version, Fingerprint: req.Fingerprint,
	})
	if err != nil {
		// A concurrent enrollment won; the issued cert is unknown to the store and therefore useless.
		reject("race_lost")
		return
	}
	logAttempt(apl.ID, true, "ok")
	writeJSON(w, http.StatusOK, s.enrollResponse(apl.ID, issued.CertPEM, site))
}

func (s *Server) enrollResponse(applianceID, certPEM string, site *store.Site) v1.EnrollResponse {
	return v1.EnrollResponse{
		ApplianceID: applianceID, CertPEM: certPEM, ChainPEM: s.cfg.CA.ChainPEM(), CPURL: s.cfg.PublicURL,
		PollIntervalS: int(DefaultPollInterval / time.Second),
		Site:          site.Config(),
		SpoolPubKey:   s.cfg.SpoolKey.PublicString(), SpoolKID: s.cfg.SpoolKey.KID(),
	}
}

// ---- /v1/renew ----

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	var req v1.RenewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	site, err := s.cfg.Store.GetSite(r.Context(), apl.SiteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	issued, err := s.cfg.CA.IssueAppliance(req.CSRPEM, apl.ID, site.VendorID, site.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_csr")
		return
	}
	if err := s.cfg.Store.UpdateCert(r.Context(), apl.ID, issued.Serial, issued.NotAfter); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	// The old serial keeps working until its NotAfter; revoking it here would
	// strand an appliance that crashes before persisting the new cert.
	s.log.Info("cert renewed", "appliance", apl.ID, "old_serial", apl.CertSerial, "new_serial", issued.Serial)
	writeJSON(w, http.StatusOK, s.enrollResponse(apl.ID, issued.CertPEM, site))
}

// ---- /v1/appliances/{id}/heartbeat ----

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	var hb v1.Heartbeat
	if err := decodeJSON(r, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	now := s.cfg.Now()
	if hb.ClockEpoch != 0 {
		hb.SkewS = hb.ClockEpoch - now.Unix()
		if d := time.Duration(hb.SkewS) * time.Second; d > MaxSkew || d < -MaxSkew {
			s.log.Warn("clock skew", "appliance", apl.ID, "skew_s", hb.SkewS)
		}
	}
	if len(hb.AckedDirectiveIDs) > 0 {
		if err := s.cfg.Store.AckDirectives(r.Context(), apl.ID, hb.AckedDirectiveIDs, now); err != nil {
			writeErr(w, http.StatusInternalServerError, "store error", "store")
			return
		}
	}
	if err := s.cfg.Store.RecordHeartbeat(r.Context(), apl.ID, now, &hb); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	s.noteUpdateError(r.Context(), apl, &hb)
	pending, err := s.cfg.Store.PendingDirectives(r.Context(), apl.ID, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	out := make([]v1.Directive, 0, len(pending))
	for _, d := range pending {
		out = append(out, v1.Directive{ID: d.ID, Type: d.Type, Payload: d.Payload})
	}
	writeJSON(w, http.StatusOK, v1.HeartbeatResponse{ServerEpoch: now.Unix(), Directives: out})
}

// ---- /v1/appliances/{id}/support ----

func (s *Server) handleSupport(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	key := fmt.Sprintf("support/%s/%s.tar.gz", apl.ID, s.cfg.Now().UTC().Format("20060102T150405Z"))
	n, err := s.cfg.Objects.Put(r.Context(), key, http.MaxBytesReader(w, r.Body, maxSupportBundleSize))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upload failed: "+err.Error(), "upload")
		return
	}
	if err := s.cfg.Store.RecordSupportBundle(r.Context(), apl.ID, key, n); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	s.log.Info("support bundle stored", "appliance", apl.ID, "key", key, "bytes", n)
	writeJSON(w, http.StatusOK, v1.SupportBundleAck{ObjectKey: key, Bytes: n})
}

// ---- /v1/appliances/{id}/wipe ----

func (s *Server) handleWipe(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	var req v1.WipeRequest
	_ = decodeJSON(r, &req)
	if err := s.cfg.Store.SetStatus(r.Context(), apl.ID, v1.StatusWiped); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	_ = s.cfg.Store.Revoke(r.Context(), apl.CertSerial, "wiped: "+req.Reason)
	s.log.Warn("appliance wiped", "appliance", apl.ID, "reason", req.Reason)
	w.WriteHeader(http.StatusNoContent)
}

// ---- admin ----

func (s *Server) adminCreateAppliance(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminCreateApplianceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if req.Vendor == "" || req.Site == "" {
		writeErr(w, http.StatusBadRequest, "vendor and site are required", "missing")
		return
	}
	if err := guard.ValidCIDRs(req.AllowedCIDRs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_cidr")
		return
	}
	ctx := r.Context()
	vendor, err := s.cfg.Store.EnsureVendor(ctx, req.Vendor)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	site, err := s.cfg.Store.EnsureSite(ctx, vendor.ID, req.Site, req.AllowedCIDRs, req.TZ, req.MaxPPS)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if req.MaxConcurrency > 0 && req.MaxConcurrency != site.MaxConcurrency {
		site.MaxConcurrency = req.MaxConcurrency
		if err := s.cfg.Store.UpdateSite(ctx, site); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
	}
	apl, err := s.cfg.Store.CreateAppliance(ctx, site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	code, exp, err := s.issueCode(ctx, apl.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusCreated, v1.AdminCreateApplianceResponse{ApplianceID: apl.ID, SiteID: site.ID, Code: code, ExpiresAt: exp})
}

func (s *Server) issueCode(ctx context.Context, applianceID string) (string, time.Time, error) {
	code, err := codes.New()
	if err != nil {
		return "", time.Time{}, err
	}
	norm, _ := codes.Normalize(code)
	exp := s.cfg.Now().Add(codes.TTL)
	err = s.cfg.Store.PutEnrollmentCode(ctx, store.EnrollmentCode{ApplianceID: applianceID, CodeHash: codes.Hash(norm), ExpiresAt: exp})
	return code, exp, err
}

func (s *Server) adminReissueCode(w http.ResponseWriter, r *http.Request) {
	apl, err := s.cfg.Store.GetAppliance(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
		return
	}
	if apl.Status != v1.StatusPending {
		writeErr(w, http.StatusConflict, "appliance is "+apl.Status+"; revoke first to re-enroll", "status")
		return
	}
	code, exp, err := s.issueCode(r.Context(), apl.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, v1.AdminCreateApplianceResponse{ApplianceID: apl.ID, SiteID: apl.SiteID, Code: code, ExpiresAt: exp})
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	apl, err := s.cfg.Store.GetAppliance(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &body)
	if apl.CertSerial != "" {
		if err := s.cfg.Store.Revoke(r.Context(), apl.CertSerial, body.Reason); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
	}
	if err := s.cfg.Store.SetStatus(r.Context(), apl.ID, v1.StatusRevoked); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListAppliances(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListAppliances(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminApplianceView, 0, len(list))
	for _, a := range list {
		out = append(out, s.view(a))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminGetAppliance(w http.ResponseWriter, r *http.Request) {
	a, err := s.cfg.Store.GetAppliance(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, s.view(a))
}

func (s *Server) view(a *store.Appliance) v1.AdminApplianceView {
	online := a.LastHeartbeatAt != nil && s.cfg.Now().Sub(*a.LastHeartbeatAt) <= OnlineWindow
	feed := ""
	if a.LastHeartbeat != nil {
		feed = a.LastHeartbeat.FeedVersion
	}
	return v1.AdminApplianceView{
		ApplianceID: a.ID, SiteID: a.SiteID, Status: a.Status, Online: online, Version: a.Version, BundleVersion: a.BundleVersion, FeedVersion: feed,
		CertSerial: a.CertSerial, CertNotAfter: a.CertNotAfter, LastHeartbeatAt: a.LastHeartbeatAt, LastHeartbeat: a.LastHeartbeat,
		SkewS: a.SkewS, Ifaces: a.Ifaces, Fingerprint: a.Fingerprint,
		Canary: a.Canary, OS: a.OS, Arch: a.Arch, UpdateError: a.UpdateError,
	}
}

func (s *Server) adminCreateDirective(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminDirectiveRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if !v1.KnownDirectives[req.Type] {
		writeErr(w, http.StatusBadRequest, "unknown directive type", "bad_type")
		return
	}
	if req.Type == v1.DirectiveSetInterval {
		sec, _ := req.Payload["s"].(float64)
		if sec < 10 || sec > 3600 {
			writeErr(w, http.StatusBadRequest, "set_interval payload.s must be 10..3600", "bad_payload")
			return
		}
	}
	d, err := s.cfg.Store.CreateDirective(r.Context(), r.PathValue("id"), req.Type, req.Payload)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusCreated, dirView(*d))
}

func (s *Server) adminListDirectives(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListDirectives(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminDirectiveView, 0, len(list))
	for _, d := range list {
		out = append(out, dirView(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func dirView(d store.Directive) v1.AdminDirectiveView {
	return v1.AdminDirectiveView{ID: d.ID, Type: d.Type, Payload: d.Payload, CreatedAt: d.CreatedAt, DeliveredAt: d.DeliveredAt, AckedAt: d.AckedAt}
}

// ---- helpers ----

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg, code string) {
	writeJSON(w, status, v1.ErrorResponse{Error: msg, Code: code})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rw.status, "ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

// ipLimiter is a fixed-window per-IP counter for the enroll endpoint.
type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string]*ipWindow
}

type ipWindow struct {
	start time.Time
	n     int
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, seen: map[string]*ipWindow{}}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.seen[ip]
	if w == nil || now.Sub(w.start) > l.window {
		if len(l.seen) > 10000 {
			l.seen = map[string]*ipWindow{}
		}
		l.seen[ip] = &ipWindow{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}
