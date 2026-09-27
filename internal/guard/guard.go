// Package guard holds the job guardrails that PLAN §11 enforces twice: on
// dispatch by the control plane and on receipt by the appliance. Both call
// the same Check so the two sides cannot drift.
package guard

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/cron"
)

// Check names.
const (
	CheckShape       = "shape"
	CheckScope       = "scope"
	CheckPublic      = "public"
	CheckWindow      = "window"
	CheckRate        = "rate"
	CheckConcurrency = "concurrency"
	CheckSafeChecks  = "safe_checks"
	CheckExcludes    = "excludes"
	// CheckDuration (Phase 5): a wide port range must fit max_duration_s at
	// the job's packet rate for the hosts it is expected to find.
	CheckDuration = "duration"
)

// DefaultMaxConcurrency applies when the site does not set one.
const DefaultMaxConcurrency = 16

// FullRangeThreshold is the port count above which the duration budget is
// checked: the "full" option (65535) and explicit specs wider than the
// standard preset. Standard scans stay unbudgeted, as they have been since
// Phase 2 (discovery trims them to live hosts).
const FullRangeThreshold = 2048

// MaxAddressCount caps the address count of a target list.
const MaxAddressCount = 1 << 24

// AddressCount is the number of addresses in the target list (IPv4 and
// IPv6 prefixes; an IPv6 prefix wider than /104 counts as MaxAddressCount).
func AddressCount(targets []string) int {
	ps, err := parsePrefixes(targets)
	if err != nil {
		return 0
	}
	total := 0
	for _, p := range ps {
		hostBits := p.Addr().BitLen() - p.Bits()
		if hostBits >= 24 {
			return MaxAddressCount
		}
		total += 1 << hostBits
		if total >= MaxAddressCount {
			return MaxAddressCount
		}
	}
	return total
}

// EstimateSeconds is the time a port scan of ports × hosts takes at pps
// packets per second, with naabu's one retry and warm-up folded in.
func EstimateSeconds(hosts, ports, pps int) int64 {
	if hosts <= 0 || ports <= 0 {
		return 0
	}
	if pps <= 0 {
		pps = 1
	}
	probes := int64(hosts) * int64(ports)
	return probes*11/10/int64(pps) + 30
}

// FormatDuration renders seconds as "2h 15m" / "45m" / "20s".
func FormatDuration(sec int64) string {
	switch {
	case sec >= 3600:
		return fmt.Sprintf("%dh %02dm", sec/3600, (sec%3600)/60)
	case sec >= 60:
		return fmt.Sprintf("%dm", sec/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// Failure is one failed guardrail.
type Failure struct {
	Check  string
	Detail string
}

func (f Failure) Error() string { return f.Check + ": " + f.Detail }

// Input for Check.
type Input struct {
	Spec v1.JobSpec
	Site v1.SiteConfig
	Now  time.Time
	// SkewTolerance widens the window check for clock skew.
	SkewTolerance time.Duration
}

// Check runs every shared guardrail and returns all failures (a rejected
// job reports the first one; the log keeps them all).
func Check(in Input) []Failure {
	var fails []Failure
	add := func(check, format string, a ...any) {
		fails = append(fails, Failure{Check: check, Detail: fmt.Sprintf(format, a...)})
	}
	spec := in.Spec
	if err := spec.ValidateShape(); err != nil {
		add(CheckShape, "%v", err)
		return fails
	}

	allowed, err := parsePrefixes(in.Site.AllowedCIDRs)
	if err != nil {
		add(CheckScope, "site allowed_cidrs: %v", err)
	}
	targets, err := parsePrefixes(spec.Targets)
	if err != nil {
		add(CheckScope, "targets: %v", err)
	}
	if _, err := parsePrefixes(spec.Excludes); err != nil {
		add(CheckExcludes, "%v", err)
	}
	for i, tgt := range targets {
		if !covered(tgt, allowed) {
			add(CheckScope, "target %s is outside the site's allowed ranges", spec.Targets[i])
		}
		if !isPrivate(tgt) {
			switch {
			case !spec.AllowPublic:
				add(CheckPublic, "target %s is a public range and the job is not flagged allow_public", spec.Targets[i])
			case !in.Site.AllowPublic:
				add(CheckPublic, "target %s is a public range and the site has not attested ownership", spec.Targets[i])
			}
		}
	}

	if spec.Window != nil && spec.Window.Cron != "" {
		tz := spec.Window.TZ
		if tz == "" {
			tz = in.Site.TZ
		}
		open, err := cron.WindowOpen(spec.Window.Cron, tz, time.Duration(spec.Window.MaxDurationS)*time.Second, in.Now, in.SkewTolerance)
		switch {
		case err != nil:
			add(CheckWindow, "%v", err)
		case !open:
			add(CheckWindow, "window %q (%s) is closed at %s", spec.Window.Cron, tz, in.Now.UTC().Format(time.RFC3339))
		}
	}

	if in.Site.MaxPPS > 0 && spec.Rate.PPS > in.Site.MaxPPS {
		add(CheckRate, "rate.pps %d exceeds the site cap %d", spec.Rate.PPS, in.Site.MaxPPS)
	}
	if spec.HasModule(v1.ModuleOpenVAS) && spec.OpenVAS != nil {
		cap := in.Site.MaxConcurrency
		if cap <= 0 {
			cap = DefaultMaxConcurrency
		}
		if n := spec.OpenVAS.MaxHosts * spec.OpenVAS.MaxChecks; n > cap {
			add(CheckConcurrency, "max_hosts × max_checks = %d exceeds the site cap %d", n, cap)
		}
	}
	if !spec.SafeChecks && !in.Site.UnsafeOK {
		add(CheckSafeChecks, "safe_checks=false requires the site to be flagged unsafe_ok")
	}
	if spec.HasModule(v1.ModulePortscan) {
		if n := v1.PortCount(spec.Ports); n > FullRangeThreshold {
			hosts := spec.ExpectedHosts
			if hosts <= 0 {
				hosts = AddressCount(spec.Targets)
			}
			if est := EstimateSeconds(hosts, n, spec.Rate.PPS); est > int64(spec.MaxDuration()) {
				add(CheckDuration, "a %d-port scan of ~%d hosts at %d pps needs about %s, more than max_duration_s %d: raise rate.pps or the window, narrow the targets, run discovery first, or use ports=standard",
					n, hosts, spec.Rate.PPS, FormatDuration(est), spec.MaxDuration())
			}
		}
	}
	return fails
}

// First returns the first failure as an error, or nil.
func First(fails []Failure) error {
	if len(fails) == 0 {
		return nil
	}
	return fails[0]
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("bad address or cidr %q", s)
	}
	return out, nil
}

// covered reports whether every address of p lies inside one allowed prefix.
func covered(p netip.Prefix, allowed []netip.Prefix) bool {
	for _, a := range allowed {
		if a.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

var privateRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// isPrivate reports whether the whole prefix is inside private/reserved space.
func isPrivate(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Contains reports whether ip is inside any of the given prefixes or
// addresses; the engine uses it to apply excludes.
func Contains(list []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	ps, err := parsePrefixes(list)
	if err != nil {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ValidCIDRs checks a list the way the admin API accepts it.
func ValidCIDRs(list []string) error {
	for _, c := range list {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("bad cidr %q", c)
		}
	}
	return nil
}
