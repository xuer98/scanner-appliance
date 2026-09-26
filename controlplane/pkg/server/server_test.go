package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

type harness struct {
	t        *testing.T
	ca       *ca.CA
	st       *store.Memory
	srv      *Server
	enroll   *httptest.Server
	mtls     *httptest.Server
	rootPool *x509.CertPool
	now      time.Time
	adminTok string
	applKey  *ecdsa.PrivateKey
	applCert tls.Certificate
	applID   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, "Test"); err != nil {
		t.Fatal(err)
	}
	c, err := ca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ca: c, st: store.NewMemory(), now: time.Now(), adminTok: "secret"}
	h.srv = New(Config{Store: h.st, CA: c, PublicURL: "https://cp.test", AdminToken: h.adminTok, Now: func() time.Time { return h.now }})

	certPEM, keyPEM, err := c.IssueServer([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	h.rootPool = x509.NewCertPool()
	rootPEM, _ := os.ReadFile(dir + "/root.pem")
	h.rootPool.AppendCertsFromPEM(rootPEM)

	h.enroll = httptest.NewUnstartedServer(h.srv.EnrollHandler())
	h.enroll.TLS = TLSConfigEnroll(serverCert)
	h.enroll.StartTLS()
	h.mtls = httptest.NewUnstartedServer(h.srv.MTLSHandler())
	h.mtls.TLS = TLSConfigMTLS(serverCert, c)
	h.mtls.StartTLS()
	t.Cleanup(func() { h.enroll.Close(); h.mtls.Close() })
	return h
}

func (h *harness) client(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: h.rootPool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (h *harness) admin(method, path string, body any, out any) int {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, h.mtls.URL+path, &buf)
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	resp, err := h.client(nil).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (h *harness) csr() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.applKey = key
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (h *harness) doEnroll(code string) (*v1.EnrollResponse, int) {
	h.t.Helper()
	body, _ := json.Marshal(v1.EnrollRequest{Code: code, CSRPEM: h.csr(), Version: "test", Fingerprint: v1.Fingerprint{Hypervisor: "test"}})
	resp, err := h.client(nil).Post(h.enroll.URL+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		h.t.Logf("enroll: %d %s", resp.StatusCode, b)
		return nil, resp.StatusCode
	}
	var er v1.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		h.t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(h.applKey)
	cert, err := tls.X509KeyPair([]byte(er.CertPEM+er.ChainPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		h.t.Fatal(err)
	}
	h.applCert = cert
	h.applID = er.ApplianceID
	return &er, 200
}

func (h *harness) heartbeat(hb v1.Heartbeat) (*v1.HeartbeatResponse, int) {
	h.t.Helper()
	body, _ := json.Marshal(hb)
	resp, err := h.client(&h.applCert).Post(h.mtls.URL+"/v1/appliances/"+h.applID+"/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		h.t.Logf("heartbeat: %d %s", resp.StatusCode, b)
		return nil, resp.StatusCode
	}
	var hr v1.HeartbeatResponse
	_ = json.NewDecoder(resp.Body).Decode(&hr)
	return &hr, 200
}

func TestEnrollHeartbeatDirectiveFlow(t *testing.T) {
	h := newHarness(t)

	var created v1.AdminCreateApplianceResponse
	if st := h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme 3PL", Site: "Reno DC", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create: %d", st)
	}
	var view v1.AdminApplianceView
	h.admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
	if view.Status != v1.StatusPending {
		t.Fatalf("status %s", view.Status)
	}

	// Heartbeat without a cert is refused.
	resp, _ := h.client(nil).Post(h.mtls.URL+"/v1/appliances/"+created.ApplianceID+"/heartbeat", "application/json", bytes.NewReader([]byte("{}")))
	if resp.StatusCode != 401 {
		t.Fatalf("no-cert heartbeat: %d", resp.StatusCode)
	}

	// Wrong code.
	if _, st := h.doEnroll("0000-0000-0000-0000-0000"); st != 401 {
		t.Fatalf("bad code: %d", st)
	}
	er, st := h.doEnroll(created.Code)
	if st != 200 {
		t.Fatalf("enroll: %d", st)
	}
	if er.ApplianceID != created.ApplianceID || er.CPURL != "https://cp.test" || len(er.Site.AllowedCIDRs) != 1 {
		t.Fatalf("enroll resp: %+v", er)
	}
	// Code is single-use.
	if _, st := h.doEnroll(created.Code); st != 401 {
		t.Fatalf("reuse: %d", st)
	}
	// Restore the first cert (doEnroll overwrote applKey on the failed retry).
	h.admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
	if view.Status != v1.StatusEnrolled || view.Online {
		t.Fatalf("after enroll: %+v", view)
	}

	// Queue directives, then heartbeat.
	var d1, d2 v1.AdminDirectiveView
	if st := h.admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "set_interval", Payload: map[string]any{"s": 30.0}}, &d1); st != 201 {
		t.Fatalf("directive: %d", st)
	}
	h.admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "stop_all"}, &d2)
	if st := h.admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: "exec"}, nil); st != 400 {
		t.Fatalf("unknown directive accepted: %d", st)
	}

	hr, st := h.heartbeat(v1.Heartbeat{Version: "test", ClockEpoch: h.now.Unix() + 7, State: "idle"})
	if st != 200 {
		t.Fatalf("heartbeat: %d", st)
	}
	if len(hr.Directives) != 2 || hr.Directives[0].ID != d1.ID || hr.Directives[1].Type != "stop_all" {
		t.Fatalf("directives: %+v", hr.Directives)
	}
	if hr.ServerEpoch != h.now.Unix() {
		t.Fatalf("epoch %d", hr.ServerEpoch)
	}
	h.admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
	if !view.Online || view.SkewS != 7 || view.LastHeartbeat == nil {
		t.Fatalf("view after hb: %+v", view)
	}

	// Ack in next heartbeat; directive list shows acked; no more pending.
	hr, _ = h.heartbeat(v1.Heartbeat{Version: "test", AckedDirectiveIDs: []string{d1.ID, d2.ID}})
	if len(hr.Directives) != 0 {
		t.Fatalf("still pending: %+v", hr.Directives)
	}
	var list []v1.AdminDirectiveView
	h.admin("GET", "/admin/appliances/"+created.ApplianceID+"/directives", nil, &list)
	for _, d := range list {
		if d.AckedAt == nil || d.DeliveredAt == nil {
			t.Fatalf("not acked: %+v", d)
		}
	}

	// Path id must match cert.
	body, _ := json.Marshal(v1.Heartbeat{})
	resp, _ = h.client(&h.applCert).Post(h.mtls.URL+"/v1/appliances/apl_OTHER/heartbeat", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 403 {
		t.Fatalf("id mismatch: %d", resp.StatusCode)
	}

	// Support bundle upload.
	resp, _ = h.client(&h.applCert).Post(h.mtls.URL+"/v1/appliances/"+h.applID+"/support", "application/gzip", bytes.NewReader(make([]byte, 1024)))
	if resp.StatusCode != 200 {
		t.Fatalf("support: %d", resp.StatusCode)
	}
	var ack v1.SupportBundleAck
	_ = json.NewDecoder(resp.Body).Decode(&ack)
	if ack.Bytes != 1024 {
		t.Fatalf("ack %+v", ack)
	}

	// Renew: new cert works, old one still works until revoked.
	rb, _ := json.Marshal(v1.RenewRequest{CSRPEM: h.csr(), Version: "test2"})
	resp, _ = h.client(&h.applCert).Post(h.mtls.URL+"/v1/renew", "application/json", bytes.NewReader(rb))
	if resp.StatusCode != 200 {
		t.Fatalf("renew: %d", resp.StatusCode)
	}
	var rr v1.EnrollResponse
	_ = json.NewDecoder(resp.Body).Decode(&rr)
	keyDER, _ := x509.MarshalECPrivateKey(h.applKey)
	newCert, _ := tls.X509KeyPair([]byte(rr.CertPEM+rr.ChainPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	oldCert := h.applCert
	h.applCert = newCert
	if _, st := h.heartbeat(v1.Heartbeat{Version: "test2"}); st != 200 {
		t.Fatalf("hb with renewed cert: %d", st)
	}
	// Old serial no longer maps to the appliance row (store keeps one serial).
	h.applCert = oldCert
	if _, st := h.heartbeat(v1.Heartbeat{}); st != 403 {
		t.Fatalf("hb with old cert: %d", st)
	}
	h.applCert = newCert

	// Revoke → 403 on every request; status revoked.
	if st := h.admin("POST", "/admin/appliances/"+created.ApplianceID+"/revoke", map[string]string{"reason": "test"}, nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	if _, st := h.heartbeat(v1.Heartbeat{}); st != 403 {
		t.Fatalf("hb after revoke: %d", st)
	}

	// Online flips to false after 3 intervals.
	h.now = h.now.Add(OnlineWindow + time.Second)
	h.admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
	if view.Online || view.Status != v1.StatusRevoked {
		t.Fatalf("stale view: %+v", view)
	}
}

func TestEnrollAbuseControls(t *testing.T) {
	h := newHarness(t)
	var created v1.AdminCreateApplianceResponse
	h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "V", Site: "S"}, &created)

	// Expired code.
	h.now = h.now.Add(15 * 24 * time.Hour)
	if _, st := h.doEnroll(created.Code); st != 401 {
		t.Fatalf("expired: %d", st)
	}
	h.now = h.now.Add(-15 * 24 * time.Hour)
	// Re-issue and lock via attempts: each failed check bumps attempts; expired
	// attempts above counted one. Use a wiped appliance status to force failures.
	var re v1.AdminCreateApplianceResponse
	if st := h.admin("POST", "/admin/appliances/"+created.ApplianceID+"/code", nil, &re); st != 200 {
		t.Fatalf("reissue: %d", st)
	}
	_ = h.st.SetStatus(t.Context(), created.ApplianceID, v1.StatusQuarantined)
	for i := 0; i < 3; i++ {
		if _, st := h.doEnroll(re.Code); st != 401 {
			t.Fatalf("attempt %d: %d", i, st)
		}
	}
	_ = h.st.SetStatus(t.Context(), created.ApplianceID, v1.StatusPending)
	if _, st := h.doEnroll(re.Code); st != 401 {
		t.Fatal("locked code accepted after 3 failures")
	}

	// Per-IP rate limit.
	for i := 0; i < 12; i++ {
		_, st := h.doEnroll("0000-0000-0000-0000-0000")
		if i >= 10-4 && st == 429 { // already used several attempts above
			return
		}
	}
	t.Fatal("rate limit never triggered")
}

func TestAdminAuth(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.mtls.URL+"/admin/appliances", nil)
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}
