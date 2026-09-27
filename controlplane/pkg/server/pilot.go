package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// Phase 4 operations (PLAN §10.6 fragile-device policy, §16 scope approval
// by the vendor owner, §19 attestation, §22 false-positive lifecycle and
// codified exclusions).

// AttestationMaxAge is how old a scope attestation may be before the
// portal is told to re-attest (PLAN §19.2: quarterly).
const AttestationMaxAge = 90 * 24 * time.Hour

// role identifies the caller from its bearer token: the operator token or
// the vendor-owner token (the only role that may approve scope changes).
func (s *Server) role(r *http.Request) string {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tok == "" {
		return ""
	}
	if s.cfg.VendorOwnerToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.VendorOwnerToken)) == 1 {
		return v1.RoleVendorOwner
	}
	if s.cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.AdminToken)) == 1 {
		return v1.RoleOperator
	}
	return ""
}

// actor is what the audit log records: the portal passes the human's
// identity in X-Actor; otherwise the role stands in.
func (s *Server) actor(r *http.Request) string {
	if a := strings.TrimSpace(r.Header.Get("X-Actor")); a != "" {
		if len(a) > 120 {
			a = a[:120]
		}
		return a
	}
	return s.role(r)
}

func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) bool {
	if s.role(r) != v1.RoleVendorOwner {
		writeErr(w, http.StatusForbidden, "the vendor-owner token is required for this action", "role")
		return false
	}
	return true
}

func jsonStr(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// commitSite bumps the policy version, persists the site and records the
// audit entries (one per changed field).
func (s *Server) commitSite(ctx context.Context, site *store.Site, actor string, changes []store.SiteChange) error {
	if len(changes) == 0 {
		return nil
	}
	site.Version++
	if err := s.cfg.Store.UpdateSite(ctx, site); err != nil {
		return err
	}
	now := s.cfg.Now()
	for i := range changes {
		c := changes[i]
		c.SiteID, c.Version, c.At, c.Actor = site.ID, site.Version, now, actor
		if err := s.cfg.Store.RecordSiteChange(ctx, &c); err != nil {
			return err
		}
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func without(in []string, v string) []string {
	var out []string
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func containsStr(in []string, v string) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}

// ---- audit log ----

func changeView(c *store.SiteChange) v1.AdminSiteChangeView {
	return v1.AdminSiteChangeView{ID: c.ID, SiteID: c.SiteID, Version: c.Version, At: c.At, Actor: c.Actor, Kind: c.Kind, Field: c.Field, Old: c.Old, New: c.New, Reason: c.Reason}
}

func (s *Server) adminSiteChanges(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	list, err := s.cfg.Store.ListSiteChanges(r.Context(), site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminSiteChangeView, 0, len(list))
	for _, c := range list {
		out = append(out, changeView(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- scope requests (PLAN §16, §19.2) ----

func scopeView(r *store.ScopeRequest) v1.AdminScopeRequestView {
	v := v1.AdminScopeRequestView{ID: r.ID, SiteID: r.SiteID, Status: r.Status, AllowedCIDRs: r.AllowedCIDRs, Reason: r.Reason,
		RequestedAt: r.RequestedAt, RequestedBy: r.RequestedBy, DecidedAt: r.DecidedAt, DecidedBy: r.DecidedBy, Decision: r.Decision}
	if v.AllowedCIDRs == nil {
		v.AllowedCIDRs = []string{}
	}
	return v
}

func (s *Server) adminCreateScopeRequest(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.AdminScopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if err := guard.ValidCIDRs(req.AllowedCIDRs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_cidr")
		return
	}
	if len(req.AllowedCIDRs) == 0 {
		writeErr(w, http.StatusBadRequest, "allowed_cidrs required", "bad_cidr")
		return
	}
	now := s.cfg.Now()
	sr := &store.ScopeRequest{SiteID: site.ID, Status: v1.ScopePending, AllowedCIDRs: dedupe(req.AllowedCIDRs), Reason: req.Reason, RequestedAt: now, RequestedBy: s.actor(r)}
	if err := s.cfg.Store.CreateScopeRequest(r.Context(), sr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("scope request created", "site", site.ID, "request", sr.ID, "by", sr.RequestedBy, "cidrs", sr.AllowedCIDRs)
	// The vendor owner's own request needs no second approval.
	if s.role(r) == v1.RoleVendorOwner {
		if err := s.applyScope(r.Context(), site, sr, s.actor(r), "requested by the vendor owner"); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
	}
	s.emit(r.Context(), EventScopeRequested, site.ID, "", "", scopeView(sr))
	writeJSON(w, http.StatusCreated, scopeView(sr))
}

func (s *Server) adminListScopeRequests(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	list, err := s.cfg.Store.ListScopeRequests(r.Context(), site.ID, r.URL.Query().Get("status"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := make([]v1.AdminScopeRequestView, 0, len(list))
	for _, sr := range list {
		out = append(out, scopeView(sr))
	}
	writeJSON(w, http.StatusOK, out)
}

// applyScope approves a request and puts its CIDRs in force.
func (s *Server) applyScope(ctx context.Context, site *store.Site, sr *store.ScopeRequest, actor, decision string) error {
	now := s.cfg.Now()
	old := site.AllowedCIDRs
	site.AllowedCIDRs = sr.AllowedCIDRs
	if err := s.commitSite(ctx, site, actor, []store.SiteChange{{Kind: "scope", Field: "allowed_cidrs", Old: jsonStr(old), New: jsonStr(sr.AllowedCIDRs), Reason: sr.Reason + " / " + decision}}); err != nil {
		return err
	}
	sr.Status, sr.DecidedAt, sr.DecidedBy, sr.Decision = v1.ScopeApproved, &now, actor, decision
	if err := s.cfg.Store.UpdateScopeRequest(ctx, sr); err != nil {
		return err
	}
	s.log.Info("scope change approved", "site", site.ID, "request", sr.ID, "by", actor, "allowed_cidrs", sr.AllowedCIDRs, "version", site.Version)
	return nil
}

func (s *Server) adminDecideScopeRequest(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	sr, err := s.cfg.Store.GetScopeRequest(r.Context(), r.PathValue("rid"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && sr.SiteID != site.ID) {
		writeErr(w, http.StatusNotFound, "no such scope request", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if sr.Status != v1.ScopePending {
		writeErr(w, http.StatusConflict, "request is "+sr.Status, "decided")
		return
	}
	var d v1.AdminDecision
	_ = decodeJSON(r, &d)
	actor := s.actor(r)
	switch r.PathValue("decision") {
	case "approve":
		if err := s.applyScope(r.Context(), site, sr, actor, d.Reason); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
	case "reject":
		now := s.cfg.Now()
		sr.Status, sr.DecidedAt, sr.DecidedBy, sr.Decision = v1.ScopeRejected, &now, actor, d.Reason
		if err := s.cfg.Store.UpdateScopeRequest(r.Context(), sr); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		s.log.Info("scope change rejected", "site", site.ID, "request", sr.ID, "by", actor)
	default:
		writeErr(w, http.StatusNotFound, "decision must be approve or reject", "not_found")
		return
	}
	writeJSON(w, http.StatusOK, scopeView(sr))
}

func (s *Server) adminAttestSite(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var d v1.AdminDecision
	_ = decodeJSON(r, &d)
	now := s.cfg.Now()
	old := ""
	if site.AttestedAt != nil {
		old = site.AttestedAt.UTC().Format(time.RFC3339)
	}
	actor := s.actor(r)
	site.AttestedAt, site.AttestedBy = &now, actor
	if err := s.commitSite(r.Context(), site, actor, []store.SiteChange{{Kind: "attest", Field: "attested_at", Old: old, New: now.UTC().Format(time.RFC3339) + " " + jsonStr(site.AllowedCIDRs), Reason: d.Reason}}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, s.siteView(r, site))
}

// ---- fragile-device policy (PLAN §10.6) ----

func (s *Server) adminFragile(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	hosts, err := s.cfg.Store.ListHosts(r.Context(), site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	fragile := site.FragilePorts
	if len(fragile) == 0 {
		fragile = []int{9100, 515, 631, 161, 502, 44818}
	}
	isFragile := map[int]bool{}
	for _, p := range fragile {
		isFragile[p] = true
	}
	out := v1.AdminFragileView{SiteID: site.ID, Version: site.Version, FragilePorts: fragile, Cleared: site.FragileCleared, Marked: site.FragileHosts, Hosts: []v1.AdminFragileHostView{}}
	if out.Cleared == nil {
		out.Cleared = []string{}
	}
	if out.Marked == nil {
		out.Marked = []string{}
	}
	listed := map[string]bool{}
	for _, h := range hosts {
		var ports []int
		for _, p := range h.Ports {
			if p.Proto == "tcp" && isFragile[p.Port] {
				ports = append(ports, p.Port)
			}
		}
		noted := false
		for _, n := range h.Notes {
			if strings.HasPrefix(n, "fragile:") {
				noted = true
			}
		}
		marked, cleared := containsStr(site.FragileHosts, h.IP), containsStr(site.FragileCleared, h.IP)
		if len(ports) == 0 && !noted && !marked && !cleared {
			continue
		}
		v := v1.AdminFragileHostView{IP: h.IP, Hostname: h.Hostname, FragilePorts: ports, Cleared: cleared, Marked: marked, LastSeen: h.LastSeen.UTC().Format(time.RFC3339)}
		if v.FragilePorts == nil {
			v.FragilePorts = []int{}
		}
		switch {
		case marked:
			v.Excluded, v.Reason = true, "policy"
		case len(ports) > 0 && cleared:
			v.Excluded, v.Reason = false, "cleared"
		case len(ports) > 0:
			v.Excluded, v.Reason = true, fmt.Sprintf("port %d", ports[0])
		default:
			v.Excluded, v.Reason = false, "cleared"
		}
		out.Hosts = append(out.Hosts, v)
		listed[h.IP] = true
	}
	for _, ip := range append(append([]string{}, site.FragileHosts...), site.FragileCleared...) {
		if listed[ip] {
			continue
		}
		listed[ip] = true
		v := v1.AdminFragileHostView{IP: ip, FragilePorts: []int{}, Marked: containsStr(site.FragileHosts, ip), Cleared: containsStr(site.FragileCleared, ip)}
		if v.Marked {
			v.Excluded, v.Reason = true, "policy"
		} else {
			v.Reason = "cleared"
		}
		out.Hosts = append(out.Hosts, v)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].IP < out.Hosts[j].IP })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminFragilePolicy(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.AdminFragileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		writeErr(w, http.StatusBadRequest, "ip required", "bad_ip")
		return
	}
	ipStr := ip.String()
	if strings.TrimSpace(req.Reason) == "" {
		writeErr(w, http.StatusBadRequest, "reason required (it goes in the audit log)", "reason")
		return
	}
	var changes []store.SiteChange
	switch req.Action {
	case "clear":
		old := site.FragileCleared
		site.FragileCleared = dedupe(append(append([]string{}, site.FragileCleared...), ipStr))
		site.FragileHosts = without(site.FragileHosts, ipStr)
		changes = append(changes, store.SiteChange{Kind: "fragile", Field: "fragile_cleared", Old: jsonStr(old), New: jsonStr(site.FragileCleared), Reason: req.Reason})
	case "unclear":
		old := site.FragileCleared
		site.FragileCleared = without(site.FragileCleared, ipStr)
		changes = append(changes, store.SiteChange{Kind: "fragile", Field: "fragile_cleared", Old: jsonStr(old), New: jsonStr(site.FragileCleared), Reason: req.Reason})
	case "mark":
		old := site.FragileHosts
		site.FragileHosts = dedupe(append(append([]string{}, site.FragileHosts...), ipStr))
		site.FragileCleared = without(site.FragileCleared, ipStr)
		changes = append(changes, store.SiteChange{Kind: "fragile", Field: "fragile_hosts", Old: jsonStr(old), New: jsonStr(site.FragileHosts), Reason: req.Reason})
	case "unmark":
		old := site.FragileHosts
		site.FragileHosts = without(site.FragileHosts, ipStr)
		changes = append(changes, store.SiteChange{Kind: "fragile", Field: "fragile_hosts", Old: jsonStr(old), New: jsonStr(site.FragileHosts), Reason: req.Reason})
	default:
		writeErr(w, http.StatusBadRequest, "action must be clear|unclear|mark|unmark", "bad_action")
		return
	}
	if err := s.commitSite(r.Context(), site, s.actor(r), changes); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("fragile-device policy changed", "site", site.ID, "ip", ipStr, "action", req.Action, "version", site.Version)
	s.adminFragile(w, r)
}

// ---- codified exclusions and finding review (PLAN §22) ----

func (s *Server) adminListExclusions(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	ex := site.VTExcludes
	if ex == nil {
		ex = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"site_id": site.ID, "version": site.Version, "vt_excludes": ex})
}

func validDetector(vt string) bool {
	vt = strings.TrimSpace(vt)
	if vt == "" || len(vt) > 200 || strings.ContainsAny(vt, " \t\n\"'\\") {
		return false
	}
	return true
}

// addExclusion codifies a detector for the site and reviews its existing
// findings as false positives.
func (s *Server) addExclusion(ctx context.Context, site *store.Site, vt, actor, reason string) (int, error) {
	vt = strings.TrimSpace(vt)
	if containsStr(site.VTExcludes, vt) {
		return 0, nil
	}
	old := site.VTExcludes
	site.VTExcludes = dedupe(append(append([]string{}, site.VTExcludes...), vt))
	if err := s.commitSite(ctx, site, actor, []store.SiteChange{{Kind: "exclusion", Field: "vt_excludes", Old: jsonStr(old), New: jsonStr(site.VTExcludes), Reason: reason}}); err != nil {
		return 0, err
	}
	n, err := s.cfg.Store.ReviewByDetector(ctx, site.ID, vt, actor, "site exclusion: "+reason, s.cfg.Now())
	if err != nil {
		return 0, err
	}
	s.log.Info("exclusion codified", "site", site.ID, "vt", vt, "reviewed", n, "version", site.Version)
	return n, nil
}

func (s *Server) adminAddExclusion(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	var req v1.AdminExclusionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if !validDetector(req.VT) {
		writeErr(w, http.StatusBadRequest, "vt must be an NVT OID or a nuclei template id", "bad_vt")
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeErr(w, http.StatusBadRequest, "reason required (it goes in the audit log)", "reason")
		return
	}
	n, err := s.addExclusion(r.Context(), site, req.VT, s.actor(r), req.Reason)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"site_id": site.ID, "version": site.Version, "vt_excludes": site.VTExcludes, "reviewed": n})
}

func (s *Server) adminRemoveExclusion(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	vt := r.PathValue("vt")
	if !containsStr(site.VTExcludes, vt) {
		writeErr(w, http.StatusNotFound, "not excluded", "not_found")
		return
	}
	old := site.VTExcludes
	site.VTExcludes = without(site.VTExcludes, vt)
	if err := s.commitSite(r.Context(), site, s.actor(r), []store.SiteChange{{Kind: "exclusion", Field: "vt_excludes", Old: jsonStr(old), New: jsonStr(site.VTExcludes), Reason: r.URL.Query().Get("reason")}}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"site_id": site.ID, "version": site.Version, "vt_excludes": site.VTExcludes})
}

func (s *Server) adminGetFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.cfg.Store.GetFinding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such finding", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	d := v1.AdminFindingDetail{Finding: s.findingViewTier(f, s.siteTier(r.Context(), hostSiteID(s, r, f)))}
	if h, err := s.cfg.Store.GetHost(r.Context(), f.HostID); err == nil {
		d.Host = hostView(h)
	}
	if f.NVTOID != "" {
		if n, err := s.cfg.Store.GetNVT(r.Context(), f.NVTOID); err == nil {
			d.NVT = &v1.AdminNVTView{OID: n.OID, Name: n.Name, Family: n.Family, CVSS: n.CVSS, CVEs: n.CVEs, QoD: n.QoD, Solution: n.Solution, FeedVersion: n.FeedVersion}
			if d.NVT.CVEs == nil {
				d.NVT.CVEs = []string{}
			}
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) adminReviewFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.cfg.Store.GetFinding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such finding", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	var req v1.AdminFindingReview
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	switch req.Review {
	case "", v1.ReviewFalsePositive, v1.ReviewAccepted:
	default:
		writeErr(w, http.StatusBadRequest, "review must be false_positive, accepted or empty (reopen)", "bad_review")
		return
	}
	if req.Review != "" && strings.TrimSpace(req.Reason) == "" {
		writeErr(w, http.StatusBadRequest, "reason required", "reason")
		return
	}
	actor := s.actor(r)
	if err := s.cfg.Store.ReviewFinding(r.Context(), f.ID, req.Review, actor, req.Reason, s.cfg.Now()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if req.Codify && req.Review == v1.ReviewFalsePositive && f.Detector() != "" {
		h, err := s.cfg.Store.GetHost(r.Context(), f.HostID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		site, err := s.cfg.Store.GetSite(r.Context(), h.SiteID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		if _, err := s.addExclusion(r.Context(), site, f.Detector(), actor, "codified from finding "+f.ID+": "+req.Reason); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
	}
	f, _ = s.cfg.Store.GetFinding(r.Context(), f.ID)
	writeJSON(w, http.StatusOK, s.findingViewTier(f, s.siteTier(r.Context(), hostSiteID(s, r, f))))
}

func (s *Server) adminGetHost(w http.ResponseWriter, r *http.Request) {
	h, err := s.cfg.Store.GetHost(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such host", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.writeHosts(w, r, []*store.Host{h})
}

// adminTuning is the false-positive review of PLAN §20 Phase 4.
func (s *Server) adminTuning(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	list, err := s.cfg.Store.ListFindings(r.Context(), site.ID, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	rep := v1.AdminTuningReport{SiteID: site.ID, BySeverity: map[string]int{}, ByDetector: []v1.AdminDetectorStat{}, Exclusions: site.VTExcludes}
	if rep.Exclusions == nil {
		rep.Exclusions = []string{}
	}
	byDet := map[string]*v1.AdminDetectorStat{}
	for _, f := range list {
		if f.Source == v1.SourceAgent {
			continue // only appliance detections are tuned here
		}
		rep.Findings++
		rep.BySeverity[f.Severity]++
		switch f.Review {
		case v1.ReviewFalsePositive:
			rep.Reviewed++
			rep.FalsePositives++
		case v1.ReviewAccepted:
			rep.Reviewed++
			rep.Accepted++
		}
		if f.State == v1.FindingSuspected && f.Review == "" {
			rep.Suspected++
		}
		det := f.Detector()
		if det == "" {
			continue
		}
		st := byDet[det]
		if st == nil {
			st = &v1.AdminDetectorStat{Detector: det, Name: f.Name, Excluded: containsStr(site.VTExcludes, det) || containsStr(site.VTExcludes, f.TemplateID)}
			byDet[det] = st
		}
		st.Findings++
		if f.Review == v1.ReviewFalsePositive {
			st.FalsePositives++
		}
		if f.State == v1.FindingSuspected && f.Review == "" {
			st.Suspected++
		}
	}
	if rep.Findings > 0 {
		rep.FalsePositiveRate = float64(rep.FalsePositives) / float64(rep.Findings)
	}
	for _, st := range byDet {
		rep.ByDetector = append(rep.ByDetector, *st)
	}
	sort.Slice(rep.ByDetector, func(i, j int) bool {
		a, b := rep.ByDetector[i], rep.ByDetector[j]
		if a.FalsePositives != b.FalsePositives {
			return a.FalsePositives > b.FalsePositives
		}
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		return a.Detector < b.Detector
	})
	writeJSON(w, http.StatusOK, rep)
}

// hostSiteID is the site of a finding's host ("" when unknown).
func hostSiteID(s *Server, r *http.Request, f *store.Finding) string {
	if h, err := s.cfg.Store.GetHost(r.Context(), f.HostID); err == nil {
		return h.SiteID
	}
	return ""
}
