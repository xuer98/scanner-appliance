package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/guard"
)

// Phase 5 "Depth" (PLAN §20): the nmap fingerprint pass behind a recorded
// legal sign-off (§21), the full-range port option budgeted against the
// site inventory (§10.2), the onboarding checklist that tracks a site
// through §19.2 (the phase's definition of done is the second and third
// site), and the feed-gap report behind the Enterprise Feed evaluation.

// ---- legal sign-off ----

// signoffRecord is what the setting "signoff:<tool>" holds.
type signoffRecord struct {
	Reference string    `json:"reference"`
	Note      string    `json:"note,omitempty"`
	By        string    `json:"by"`
	At        time.Time `json:"at"`
}

func signoffKey(tool string) string { return "signoff:" + tool }

// signoff returns the recorded sign-off for a tool, or nil.
func (s *Server) signoff(ctx context.Context, tool string) (*signoffRecord, error) {
	v, err := s.cfg.Store.GetSetting(ctx, signoffKey(tool))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec signoffRecord
	if err := json.Unmarshal([]byte(v), &rec); err != nil {
		return nil, fmt.Errorf("signoff %s: %w", tool, err)
	}
	return &rec, nil
}

// fingerprintApproved reports whether nmap may be dispatched.
func (s *Server) fingerprintApproved(ctx context.Context) bool {
	rec, err := s.signoff(ctx, v1.SignoffNmap)
	if err != nil {
		s.log.Warn("signoff lookup", "err", err)
		return false
	}
	return rec != nil
}

func signoffView(tool string, rec *signoffRecord) v1.AdminSignoffView {
	v := v1.AdminSignoffView{Tool: tool}
	if rec != nil {
		at := rec.At
		v.Approved, v.Reference, v.Note, v.By, v.At = true, rec.Reference, rec.Note, rec.By, &at
	}
	return v
}

func signoffTool(w http.ResponseWriter, r *http.Request) (string, bool) {
	tool := r.PathValue("tool")
	if tool != v1.SignoffNmap {
		writeErr(w, http.StatusNotFound, "no sign-off is tracked for "+tool+" (only nmap needs one, PLAN §21)", "not_found")
		return "", false
	}
	return tool, true
}

func (s *Server) adminGetSignoff(w http.ResponseWriter, r *http.Request) {
	tool, ok := signoffTool(w, r)
	if !ok {
		return
	}
	rec, err := s.signoff(r.Context(), tool)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, signoffView(tool, rec))
}

// adminPutSignoff records the legal sign-off. It is the programme's own
// decision (operator token), not the vendor owner's; the reference is
// mandatory so the audit trail points at the review.
func (s *Server) adminPutSignoff(w http.ResponseWriter, r *http.Request) {
	tool, ok := signoffTool(w, r)
	if !ok {
		return
	}
	var req v1.AdminSignoffRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	req.Reference = strings.TrimSpace(req.Reference)
	if req.Reference == "" || len(req.Reference) > 200 || len(req.Note) > 2000 {
		writeErr(w, http.StatusBadRequest, "reference (1..200 chars) is required; note up to 2000 chars", "bad_reference")
		return
	}
	rec := signoffRecord{Reference: req.Reference, Note: strings.TrimSpace(req.Note), By: s.actor(r), At: s.cfg.Now()}
	b, _ := json.Marshal(rec)
	if err := s.cfg.Store.PutSetting(r.Context(), signoffKey(tool), string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Warn("legal sign-off recorded", "tool", tool, "reference", rec.Reference, "by", rec.By)
	s.emit(r.Context(), EventSignoffChanged, "", "", "", signoffView(tool, &rec))
	writeJSON(w, http.StatusOK, signoffView(tool, &rec))
}

func (s *Server) adminDeleteSignoff(w http.ResponseWriter, r *http.Request) {
	tool, ok := signoffTool(w, r)
	if !ok {
		return
	}
	err := s.cfg.Store.DeleteSetting(r.Context(), signoffKey(tool))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Warn("legal sign-off revoked", "tool", tool, "by", s.actor(r))
	s.emit(r.Context(), EventSignoffChanged, "", "", "", signoffView(tool, nil))
	writeJSON(w, http.StatusOK, signoffView(tool, nil))
}

// ---- job builder hooks ----

// applyDepth finishes a job spec for Phase 5: the fingerprint module
// (explicit params imply it; full mode includes it once nmap is signed
// off; never without the sign-off) and the live-host hint for the
// full-range budget. Returns an HTTP status and message when refused.
func (s *Server) applyDepth(ctx context.Context, req v1.AdminJobRequest, site *store.Site, spec *v1.JobSpec) (int, string, string) {
	if req.Fingerprint != nil {
		spec.Fingerprint = req.Fingerprint
		if !spec.HasModule(v1.ModuleFingerprint) {
			spec.Modules = append(spec.Modules, v1.ModuleFingerprint)
		}
	}
	approved := s.fingerprintApproved(ctx)
	if approved && len(req.Modules) == 0 && spec.Mode == v1.ModeFull && !spec.HasModule(v1.ModuleFingerprint) {
		spec.Modules = append(spec.Modules, v1.ModuleFingerprint)
	}
	if spec.HasModule(v1.ModuleFingerprint) {
		if spec.Fingerprint == nil {
			spec.Fingerprint = v1.DefaultFingerprintParams()
		}
		if !approved {
			return http.StatusForbidden, "the fingerprint module (nmap, NPSL) needs the legal sign-off recorded first: PUT /admin/signoffs/nmap (cp-api admin signoff nmap --reference ...)", "fingerprint_not_approved"
		}
	}
	if v1.PortCount(spec.Ports) > guard.FullRangeThreshold {
		n, err := s.expectedHosts(ctx, site.ID, spec)
		if err != nil {
			return http.StatusInternalServerError, "store error", "store"
		}
		spec.ExpectedHosts = n
	}
	return 0, "", ""
}

// inventoryFreshness is how recent a host sighting must be to count as a
// live host for the full-range budget.
const inventoryFreshness = 45 * 24 * time.Hour

// expectedHosts counts the site's inventory hosts inside the job's targets
// (and outside its excludes) seen recently; 0 when the site has no
// inventory yet, which makes the guardrail fall back to address counts.
func (s *Server) expectedHosts(ctx context.Context, siteID string, spec *v1.JobSpec) (int, error) {
	hosts, err := s.cfg.Store.ListHosts(ctx, siteID)
	if err != nil {
		return 0, err
	}
	cutoff := s.cfg.Now().Add(-inventoryFreshness)
	n := 0
	for _, h := range hosts {
		if h.IP == "" || h.LastSeen.Before(cutoff) {
			continue
		}
		if !guard.Contains(spec.Targets, h.IP) || guard.Contains(spec.Excludes, h.IP) {
			continue
		}
		n++
	}
	return n, nil
}

// ---- onboarding checklist (PLAN §19.2) ----

// twoCycles is the number of completed inventory scans that count as
// "two scan cycles" (the pilot's definition of done, carried over as the
// last onboarding step).
const twoCycles = 2

func (s *Server) onboarding(ctx context.Context, site *store.Site) (v1.AdminOnboardingView, error) {
	now := s.cfg.Now()
	out := v1.AdminOnboardingView{SiteID: site.ID}
	step := func(key, title string, done bool, detail string) {
		out.Steps = append(out.Steps, v1.OnboardingStep{Key: key, Title: title, Done: done, Detail: detail})
	}

	// 1. Scope attested by the vendor owner.
	switch {
	case site.AttestedAt == nil:
		step("scope_attested", "Vendor owner attested the scope", false, "no attestation: the vendor-owner token must attest the allowed ranges (admin attest)")
	default:
		step("scope_attested", "Vendor owner attested the scope", true, fmt.Sprintf("attested by %s on %s", site.AttestedBy, site.AttestedAt.UTC().Format("2006-01-02")))
	}

	// 2/3. An appliance enrolled and online.
	apls, err := s.cfg.Store.ListAppliances(ctx)
	if err != nil {
		return out, err
	}
	enrolled, online := 0, 0
	for _, a := range apls {
		if a.SiteID != site.ID || a.Status != v1.StatusEnrolled {
			continue
		}
		enrolled++
		if s.health(a, now) == v1.HealthOnline {
			online++
		}
	}
	step("appliance_enrolled", "Appliance deployed and enrolled", enrolled > 0, fmt.Sprintf("%d enrolled", enrolled))
	step("appliance_online", "Appliance online", online > 0, fmt.Sprintf("%d online", online))

	// 4. Discovery run and reviewed: a done discovery job, and no host is
	// still waiting for a fragile-device decision.
	jobs, err := s.cfg.Store.ListJobs(ctx, site.ID, "")
	if err != nil {
		return out, err
	}
	discovery, inventories := 0, 0
	var lastInventory *time.Time
	for _, j := range jobs {
		if j.Status != v1.JobDone {
			continue
		}
		switch {
		case j.Spec.Mode == v1.ModeDiscovery:
			discovery++
		case j.Spec.HasModule(v1.ModuleOpenVAS):
			inventories++
			if j.FinishedAt != nil && (lastInventory == nil || j.FinishedAt.After(*lastInventory)) {
				t := *j.FinishedAt
				lastInventory = &t
			}
		}
	}
	step("discovery_done", "Discovery scan completed", discovery > 0, fmt.Sprintf("%d completed discovery scan(s)", discovery))
	pending, err := s.pendingFragile(ctx, site)
	if err != nil {
		return out, err
	}
	switch {
	case discovery == 0:
		step("exclusions_reviewed", "Exclusions and fragile devices reviewed with the vendor", false, "waiting for the discovery scan")
	case pending > 0:
		step("exclusions_reviewed", "Exclusions and fragile devices reviewed with the vendor", false, fmt.Sprintf("%d host(s) with a fragile-device port open await a clear/mark decision (admin fragile-set)", pending))
	default:
		step("exclusions_reviewed", "Exclusions and fragile devices reviewed with the vendor", true, fmt.Sprintf("policy version %d, %d excluded range(s), %d cleared, %d marked", site.Version, len(site.Excludes), len(site.FragileCleared), len(site.FragileHosts)))
	}

	// 5. Weekly inventory and monthly full schedules enabled.
	scheds, err := s.cfg.Store.ListSchedules(ctx, site.ID)
	if err != nil {
		return out, err
	}
	inv, full := 0, 0
	for _, sc := range scheds {
		if !sc.Enabled {
			continue
		}
		switch sc.Mode {
		case v1.ModeInventory:
			inv++
		case v1.ModeFull:
			full++
		}
	}
	step("inventory_scheduled", "Weekly inventory schedule enabled", inv > 0, fmt.Sprintf("%d enabled inventory schedule(s)", inv))
	step("full_scheduled", "Monthly full schedule enabled", full > 0, fmt.Sprintf("%d enabled full schedule(s)", full))

	// 6. Two scan cycles completed.
	detail := fmt.Sprintf("%d completed inventory/full scan(s)", inventories)
	if lastInventory != nil {
		detail += ", last on " + lastInventory.UTC().Format("2006-01-02")
	}
	step("two_cycles", "Two scan cycles completed", inventories >= twoCycles, detail)

	// 7. Attestation current (quarterly).
	stale := site.AttestedAt == nil || now.Sub(*site.AttestedAt) > AttestationMaxAge
	step("attestation_current", "Quarterly re-attestation current", !stale, "re-attest every 90 days (PLAN §19.2)")

	out.Complete = true
	for _, st := range out.Steps {
		if !st.Done {
			out.Complete = false
			out.Next = st.Title
			break
		}
	}
	return out, nil
}

// pendingFragile counts hosts with a fragile-device port open that are
// neither cleared nor marked.
func (s *Server) pendingFragile(ctx context.Context, site *store.Site) (int, error) {
	hosts, err := s.cfg.Store.ListHosts(ctx, site.ID)
	if err != nil {
		return 0, err
	}
	fragile := site.FragilePorts
	if len(fragile) == 0 {
		fragile = []int{9100, 515, 631, 161, 502, 44818}
	}
	isFragile := map[int]bool{}
	for _, p := range fragile {
		isFragile[p] = true
	}
	n := 0
	for _, h := range hosts {
		if containsStr(site.FragileHosts, h.IP) || containsStr(site.FragileCleared, h.IP) {
			continue
		}
		for _, p := range h.Ports {
			if p.Proto == "tcp" && isFragile[p.Port] {
				n++
				break
			}
		}
	}
	return n, nil
}

func (s *Server) adminOnboarding(w http.ResponseWriter, r *http.Request) {
	site := s.loadSite(w, r)
	if site == nil {
		return
	}
	out, err := s.onboarding(r.Context(), site)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- feed-gap report (Enterprise Feed evaluation) ----

// enterpriseVendors are product families the Greenbone Enterprise Feed
// covers and the Community Feed covers thinly (Greenbone's own
// positioning: enterprise network, security and infrastructure products).
// Matching is a keyword heuristic over what the appliance reports (port
// product, CPE, HTTP server/tech, OS guess, hostname); the evaluation in
// docs/ENTERPRISE-FEED.md explains how to read the numbers.
var enterpriseVendors = []struct {
	Vendor   string
	Keywords []string
}{
	{"Cisco", []string{"cisco", "ios-xe", "ios xe", "nx-os", "meraki", "catalyst", "asa "}},
	{"Fortinet", []string{"fortinet", "fortigate", "fortios", "fortimanager", "fortiweb"}},
	{"Palo Alto Networks", []string{"palo alto", "paloalto", "pan-os", "panos", "globalprotect"}},
	{"Juniper", []string{"juniper", "junos"}},
	{"F5", []string{"big-ip", "bigip", "f5 networks", "cpe:/a:f5", "cpe:/o:f5"}},
	{"Citrix", []string{"citrix", "netscaler", "xenserver"}},
	{"VMware", []string{"vmware", "esxi", "vcenter", "vsphere", "horizon"}},
	{"SAP", []string{"sap netweaver", "netweaver", "cpe:/a:sap", "sap router", "saprouter"}},
	{"Oracle", []string{"weblogic", "oracle database", "oracle-tns", "cpe:/a:oracle:database", "cpe:/a:oracle:weblogic", "oracle http"}},
	{"IBM", []string{"cpe:/a:ibm", "websphere", "db2", "domino", "ibm http"}},
	{"Check Point", []string{"check point", "checkpoint", "gaia"}},
	{"SonicWall", []string{"sonicwall", "sonicos"}},
	{"HPE / Aruba", []string{"aruba", "procurve", "hewlett", "hpe ", "integrated lights-out", "ilo"}},
	{"Dell", []string{"dell", "idrac", "powerconnect"}},
	{"NetApp", []string{"netapp", "ontap"}},
	{"Veeam", []string{"veeam"}},
	{"Sophos", []string{"sophos"}},
	{"WatchGuard", []string{"watchguard"}},
	{"Zyxel", []string{"zyxel"}},
	{"Siemens", []string{"siemens", "simatic", "s7comm"}},
	{"Rockwell", []string{"rockwell", "allen-bradley", "controllogix", "ethernet-ip"}},
	{"Schneider Electric", []string{"schneider", "modicon"}},
	{"Zebra", []string{"zebra"}},
	{"Honeywell", []string{"honeywell"}},
}

// maxGapExamples bounds the examples per vendor.
const maxGapExamples = 5

func hostText(h *store.Host) []string {
	var parts []string
	if h.Hostname != "" {
		parts = append(parts, h.Hostname)
	}
	if h.OSGuess != nil {
		parts = append(parts, h.OSGuess.Name, h.OSGuess.CPE)
	}
	return parts
}

func portText(p v1.Port) string {
	parts := []string{p.Service, p.Product, p.CPE}
	if p.Web != nil {
		parts = append(parts, p.Web.Server, p.Web.Title)
		parts = append(parts, p.Web.Tech...)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func matchVendor(text string) string {
	for _, ev := range enterpriseVendors {
		for _, kw := range ev.Keywords {
			if strings.Contains(text, kw) {
				return ev.Vendor
			}
		}
	}
	return ""
}

func (s *Server) feedGaps(ctx context.Context, siteID string) (v1.AdminFeedGapReport, error) {
	out := v1.AdminFeedGapReport{SiteID: siteID, Enterprise: []v1.AdminFeedGapEntry{}, ComputedAt: s.cfg.Now()}
	var sites []*store.Site
	if siteID != "" {
		site, err := s.cfg.Store.GetSite(ctx, siteID)
		if err != nil {
			return out, err
		}
		sites = []*store.Site{site}
	} else {
		list, err := s.cfg.Store.ListSites(ctx)
		if err != nil {
			return out, err
		}
		sites = list
	}
	type agg struct {
		hosts, ports, findings int
		examples               []string
		seen                   map[string]bool
	}
	byVendor := map[string]*agg{}
	for _, site := range sites {
		hosts, err := s.cfg.Store.ListHosts(ctx, site.ID)
		if err != nil {
			return out, err
		}
		findings, err := s.cfg.Store.ListFindings(ctx, site.ID, "")
		if err != nil {
			return out, err
		}
		perHost := map[string]int{}
		for _, f := range findings {
			if f.Review != v1.ReviewFalsePositive {
				perHost[f.HostID]++
			}
		}
		for _, h := range hosts {
			if h.Source == v1.SourceAgent || len(h.Ports) == 0 {
				continue // network-visible hosts only
			}
			out.Hosts++
			if perHost[h.ID] == 0 {
				out.HostsNoFindings++
			}
			hostVendor := matchVendor(strings.ToLower(strings.Join(hostText(h), " ")))
			vendorsOnHost := map[string]bool{}
			if hostVendor != "" {
				vendorsOnHost[hostVendor] = true
			}
			for _, p := range h.Ports {
				out.OpenPorts++
				text := portText(p)
				if p.Service != "" || p.Product != "" || p.CPE != "" || p.Web != nil {
					out.IdentifiedPorts++
				} else {
					out.UnidentifiedPorts++
				}
				vendor := matchVendor(text)
				if vendor == "" {
					continue
				}
				vendorsOnHost[vendor] = true
				a := byVendor[vendor]
				if a == nil {
					a = &agg{seen: map[string]bool{}}
					byVendor[vendor] = a
				}
				a.ports++
				ex := fmt.Sprintf("%s:%d %s", h.IP, p.Port, strings.TrimSpace(strings.Join([]string{p.Product, p.Version, p.CPE}, " ")))
				if len(a.examples) < maxGapExamples && !a.seen[ex] {
					a.seen[ex] = true
					a.examples = append(a.examples, ex)
				}
			}
			if len(vendorsOnHost) > 0 {
				out.EnterpriseHosts++
			}
			for vendor := range vendorsOnHost {
				a := byVendor[vendor]
				if a == nil {
					a = &agg{seen: map[string]bool{}}
					byVendor[vendor] = a
				}
				a.hosts++
				a.findings += perHost[h.ID]
				if hostVendor == vendor && len(a.examples) < maxGapExamples {
					ex := h.IP + " " + strings.TrimSpace(strings.Join(hostText(h), " "))
					if !a.seen[ex] {
						a.seen[ex] = true
						a.examples = append(a.examples, ex)
					}
				}
			}
		}
	}
	for vendor, a := range byVendor {
		out.Enterprise = append(out.Enterprise, v1.AdminFeedGapEntry{Vendor: vendor, Hosts: a.hosts, Ports: a.ports, Findings: a.findings, Examples: a.examples})
	}
	sort.Slice(out.Enterprise, func(i, j int) bool {
		if out.Enterprise[i].Hosts != out.Enterprise[j].Hosts {
			return out.Enterprise[i].Hosts > out.Enterprise[j].Hosts
		}
		return out.Enterprise[i].Vendor < out.Enterprise[j].Vendor
	})
	out.Recommendation = feedRecommendation(out)
	return out, nil
}

// feedRecommendation turns the counts into the evaluation's verdict
// (thresholds in docs/ENTERPRISE-FEED.md).
func feedRecommendation(r v1.AdminFeedGapReport) string {
	if r.Hosts == 0 {
		return "no appliance inventory yet: run discovery and inventory scans before judging feed coverage"
	}
	entShare := float64(r.EnterpriseHosts) / float64(r.Hosts)
	quiet := 0
	for _, e := range r.Enterprise {
		if e.Findings == 0 {
			quiet += e.Hosts
		}
	}
	unidentified := 0.0
	if r.OpenPorts > 0 {
		unidentified = float64(r.UnidentifiedPorts) / float64(r.OpenPorts)
	}
	switch {
	case entShare >= 0.15 || quiet >= 10:
		return fmt.Sprintf("evaluate the Enterprise Feed: %d of %d network-visible hosts (%.0f%%) run enterprise products the community feed covers thinly, %d of them without a single finding; request a trial subscription and compare on the lab segment (docs/ENTERPRISE-FEED.md)",
			r.EnterpriseHosts, r.Hosts, entShare*100, quiet)
	case unidentified >= 0.3:
		return fmt.Sprintf("identify first: %.0f%% of open ports carry no service identification; enable the fingerprint pass (after the nmap sign-off) and re-run before judging feed coverage", unidentified*100)
	default:
		return fmt.Sprintf("stay on the community feed: enterprise products are %.0f%% of network-visible hosts and %.0f%% of open ports are identified", entShare*100, (1-unidentified)*100)
	}
}

func (s *Server) adminFeedGaps(w http.ResponseWriter, r *http.Request) {
	out, err := s.feedGaps(r.Context(), r.URL.Query().Get("site"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such site", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
