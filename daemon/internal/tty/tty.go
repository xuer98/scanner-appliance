// Package tty is the console menu on tty1 (PLAN §6).
//
// It runs as root but offers no shell: every input is matched against a
// fixed grammar, screens time out back to Status after five idle minutes,
// and destructive actions require typing the appliance ID.
package tty

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/cpclient"
	"github.com/tprm/scanner-appliance/daemon/internal/enroll"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/netcfg"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/support"
)

// IdleTimeout returns the console to Status.
const IdleTimeout = 5 * time.Minute

// Console drives the menu over any reader/writer (tty1 in production, a pipe in tests).
type Console struct {
	In       io.Reader
	Out      io.Writer
	Store    *state.Store
	Roots    *x509.CertPool
	Version  string
	Idle     time.Duration
	PowerOff func() error
	// ApplyNetwork is netcfg.Apply unless overridden (tests).
	ApplyNetwork func(context.Context, state.Network) error
	// Clear controls ANSI clear-screen; off for serial capture in tests.
	Clear bool

	lines chan string
	errc  chan error
}

func (c *Console) init() {
	if c.Idle == 0 {
		c.Idle = IdleTimeout
	}
	if c.PowerOff == nil {
		c.PowerOff = func() error { return exec.Command("systemctl", "poweroff").Run() }
	}
	if c.ApplyNetwork == nil {
		c.ApplyNetwork = netcfg.Apply
	}
	c.lines = make(chan string)
	c.errc = make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(c.In)
		sc.Buffer(make([]byte, 4096), 4096)
		for sc.Scan() {
			c.lines <- strings.TrimSpace(sc.Text())
		}
		if err := sc.Err(); err != nil {
			c.errc <- err
		} else {
			c.errc <- io.EOF
		}
	}()
}

// Run loops until input ends or ctx is done.
func (c *Console) Run(ctx context.Context) error {
	c.init()
	for {
		c.status()
		choice, err := c.prompt(ctx, "Select [1-6]: ")
		if err != nil {
			return err
		}
		switch choice {
		case "", "1":
			continue
		case "2":
			err = c.network(ctx)
		case "3":
			err = c.proxy(ctx)
		case "4":
			err = c.enroll(ctx)
		case "5":
			err = c.supportBundle(ctx)
		case "6":
			err = c.wipe(ctx)
		default:
			c.printf("Unknown option %q.\n", choice)
			err = c.pause(ctx)
		}
		if err == errIdle {
			continue
		}
		if err != nil {
			return err
		}
	}
}

var errIdle = fmt.Errorf("idle timeout")

// prompt reads one line with the idle timeout. errIdle sends the caller back to Status.
func (c *Console) prompt(ctx context.Context, label string) (string, error) {
	c.printf("%s", label)
	t := time.NewTimer(c.Idle)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-c.errc:
		return "", err
	case l := <-c.lines:
		return l, nil
	case <-t.C:
		c.printf("\n(idle)\n")
		return "", errIdle
	}
}

func (c *Console) pause(ctx context.Context) error {
	_, err := c.prompt(ctx, "Press Enter to continue.")
	return err
}

func (c *Console) printf(f string, a ...any) { fmt.Fprintf(c.Out, f, a...) }

func (c *Console) header(title string) {
	if c.Clear {
		c.printf("\033[H\033[2J")
	}
	c.printf("\n=== Scanner Appliance %s — %s ===\n\n", c.Version, title)
}

// ---- screens ----

func (c *Console) status() {
	c.header("Status")
	st, _ := c.Store.Load()
	if st == nil {
		st = &state.State{}
	}
	live, lerr := c.Store.ReadStatus()
	enrolled := st.ApplianceID != ""
	c.printf("  Enrolled:        %s\n", yesno(enrolled, st.ApplianceID))
	if lerr != nil {
		c.printf("  Daemon:          not running (%v)\n", lerr)
	} else {
		age := time.Since(live.UpdatedAt).Round(time.Second)
		c.printf("  Daemon state:    %s (updated %s ago)\n", live.State, age)
		c.printf("  Control plane:   %s\n", live.CPURL)
		c.printf("  Reachable:       %s\n", yesno(live.Reachable, ""))
		if live.LastHeartbeat != nil {
			c.printf("  Last heartbeat:  %s ago (skew %ds, interval %ds)\n", time.Since(*live.LastHeartbeat).Round(time.Second), live.SkewS, live.IntervalS)
		} else {
			c.printf("  Last heartbeat:  never\n")
		}
		if live.LastError != "" {
			c.printf("  Last error:      %s\n", live.LastError)
		}
		if live.StopAll {
			c.printf("  STOP_ALL:        active — no scans will run\n")
		}
		if live.CurrentJobID != "" {
			c.printf("  Current job:     %s\n", live.CurrentJobID)
		}
		if live.CertNotAfter != nil {
			c.printf("  Cert expires:    %s\n", live.CertNotAfter.Format("2006-01-02"))
		}
		c.printf("  Bundle version:  %s\n", orDash(live.BundleVersion))
	}
	c.printf("  Proxy:           %s\n", orDash(redact(st.Proxy)))
	c.printf("  Split network:   %s\n", yesno(st.Split, ""))
	c.printf("  Interfaces:\n")
	for _, i := range netcfg.Interfaces() {
		c.printf("    %-8s %-7s %-16s %s\n", i.Name, i.Role, orDash(i.IPv4), i.MAC)
	}
	c.printf("\n  1) Status   2) Network   3) Proxy   4) Enroll   5) Support bundle   6) Wipe\n\n")
}

func (c *Console) network(ctx context.Context) error {
	for {
		c.header("Network")
		st, _ := c.Store.Load()
		c.printf("  wan0: %s\n  lan0: %s\n\n", describeNIC(st.Network.WAN0), describeNIC(st.Network.LAN0))
		c.printf("  1) Configure wan0   2) Configure lan0   0) Back\n")
		ch, err := c.prompt(ctx, "Select: ")
		if err != nil {
			return err
		}
		var name string
		switch ch {
		case "0", "":
			return nil
		case "1":
			name = "wan0"
		case "2":
			name = "lan0"
		default:
			continue
		}
		nic, err := c.askNIC(ctx, name)
		if err != nil {
			return err
		}
		if nic == nil {
			continue
		}
		if name == "wan0" {
			st.Network.WAN0 = nic
		} else {
			st.Network.LAN0 = nic
		}
		if err := c.ApplyNetwork(ctx, st.Network); err != nil {
			c.printf("\n  Rejected: %v\n", err)
			if err := c.pause(ctx); err != nil {
				return err
			}
			continue
		}
		if err := c.Store.Save(st); err != nil {
			c.printf("\n  Save failed: %v\n", err)
		} else {
			_ = c.Store.Touch("reload")
			c.printf("\n  Applied to %s.\n", name)
		}
		if err := c.pause(ctx); err != nil {
			return err
		}
	}
}

func (c *Console) askNIC(ctx context.Context, name string) (*state.NIC, error) {
	c.printf("\n  %s mode — 1) DHCP  2) Static  0) Cancel\n", name)
	ch, err := c.prompt(ctx, "Select: ")
	if err != nil {
		return nil, err
	}
	switch ch {
	case "1":
		return &state.NIC{Mode: "dhcp"}, nil
	case "2":
	default:
		return nil, nil
	}
	nic := &state.NIC{Mode: "static"}
	nic.CIDR, err = c.askValid(ctx, "  Address (CIDR, e.g. 10.20.0.50/24): ", func(s string) error {
		ip, _, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("enter an IPv4 address with prefix length")
		}
		return nil
	})
	if err != nil || nic.CIDR == "" {
		return nil, err
	}
	if name == "wan0" {
		nic.GW, err = c.askValid(ctx, "  Gateway: ", ipv4Check)
		if err != nil || nic.GW == "" {
			return nil, err
		}
		dns, err := c.askValid(ctx, "  DNS servers (space separated, optional): ", func(s string) error {
			for _, d := range strings.Fields(s) {
				if err := ipv4Check(d); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		nic.DNS = strings.Fields(dns)
	} else {
		c.printf("  (lan0 never gets a gateway or DNS; it only reaches its own subnet)\n")
	}
	return nic, nil
}

// askValid re-prompts until the validator passes; empty input cancels.
func (c *Console) askValid(ctx context.Context, label string, check func(string) error) (string, error) {
	for {
		s, err := c.prompt(ctx, label)
		if err != nil {
			return "", err
		}
		if s == "" {
			return "", nil
		}
		if err := check(s); err != nil {
			c.printf("  %v\n", err)
			continue
		}
		return s, nil
	}
}

func (c *Console) proxy(ctx context.Context) error {
	c.header("Proxy")
	st, _ := c.Store.Load()
	c.printf("  Current: %s\n\n  Enter host:port or user:pass@host:port; '-' to clear; empty to go back.\n", orDash(redact(st.Proxy)))
	in, err := c.prompt(ctx, "Proxy: ")
	if err != nil {
		return err
	}
	if in == "" {
		return nil
	}
	if in == "-" {
		in = ""
	} else if _, err := cpclient.ProxyURL(in); err != nil {
		c.printf("  %v\n", err)
		return c.pause(ctx)
	}
	st.Proxy = in
	url := st.CPURL
	if url == "" {
		url = st.EnrollURL
	}
	c.printf("  Testing connection to %s ... ", url)
	cl, err := cpclient.New(cpclient.Options{Roots: c.Roots, Proxy: in, Timeout: 20 * time.Second})
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = cl.Ping(cctx, url)
		cancel()
	}
	if err != nil {
		c.printf("FAILED (%v)\n", err)
		ans, perr := c.prompt(ctx, "  Save anyway? [y/N]: ")
		if perr != nil {
			return perr
		}
		if !strings.EqualFold(ans, "y") {
			return nil
		}
	} else {
		c.printf("ok\n")
	}
	if err := c.Store.Save(st); err != nil {
		c.printf("  Save failed: %v\n", err)
	} else {
		_ = c.Store.Touch("reload")
		c.printf("  Saved.\n")
	}
	return c.pause(ctx)
}

func (c *Console) enroll(ctx context.Context) error {
	c.header("Enroll")
	st, _ := c.Store.Load()
	if st.ApplianceID != "" {
		c.printf("  Already enrolled as %s. Wipe first to re-enroll.\n", st.ApplianceID)
		return c.pause(ctx)
	}
	c.printf("  Control plane: %s\n  Enter the enrollment code from the portal (empty to go back).\n", st.EnrollURL)
	code, err := c.prompt(ctx, "Code: ")
	if err != nil {
		return err
	}
	if code == "" {
		return nil
	}
	if err := enroll.ValidateCode(code); err != nil {
		c.printf("  %v\n", err)
		return c.pause(ctx)
	}
	c.printf("  Enrolling ... ")
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	resp, err := enroll.Enroll(cctx, c.Store, enroll.Options{EnrollURL: st.EnrollURL, Code: code, Proxy: st.Proxy, Version: c.Version, Roots: c.Roots})
	cancel()
	if err != nil {
		c.printf("FAILED\n  %v\n", err)
		return c.pause(ctx)
	}
	_ = c.Store.Touch("reload")
	c.printf("ok\n  Appliance ID: %s\n  Allowed CIDRs: %s\n  The daemon will send its first heartbeat within a minute.\n", resp.ApplianceID, strings.Join(resp.Site.AllowedCIDRs, ", "))
	return c.pause(ctx)
}

func (c *Console) supportBundle(ctx context.Context) error {
	c.header("Support bundle")
	c.printf("  Collects logs, network and daemon state (never the private key) and uploads it\n  to the control plane over mTLS. Nothing is written to removable media.\n\n")
	ans, err := c.prompt(ctx, "Upload now? [y/N]: ")
	if err != nil {
		return err
	}
	if !strings.EqualFold(ans, "y") {
		return nil
	}
	c.printf("  Uploading ... ")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	ack, err := support.Upload(cctx, c.Store, c.Roots, c.Version)
	cancel()
	if err != nil {
		c.printf("FAILED\n  %v\n", err)
	} else {
		c.printf("ok\n  Reference: %s (%d bytes)\n  Quote this reference when contacting support.\n", ack.ObjectKey, ack.Bytes)
	}
	return c.pause(ctx)
}

func (c *Console) wipe(ctx context.Context) error {
	c.header("Wipe")
	st, _ := c.Store.Load()
	if st.ApplianceID == "" {
		c.printf("  Not enrolled; nothing to wipe beyond local settings.\n")
		ans, err := c.prompt(ctx, "Reset local settings and power off? type YES: ")
		if err != nil {
			return err
		}
		if ans != "YES" {
			return nil
		}
	} else {
		c.printf("  This destroys the key, certificate, and all state, marks the appliance wiped\n  on the control plane, and powers off. It cannot be undone.\n\n")
		ans, err := c.prompt(ctx, "Type the appliance ID to confirm: ")
		if err != nil {
			return err
		}
		if ans != st.ApplianceID {
			c.printf("  Did not match; aborted.\n")
			return c.pause(ctx)
		}
	}
	c.printf("  Wiping ...\n")
	heartbeat.Wipe(ctx, c.Store, c.Roots, c.Version, "console", c.PowerOff)
	c.printf("  Done. Powering off.\n")
	return nil
}

// ---- helpers ----

func ipv4Check(s string) error {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("enter an IPv4 address")
	}
	return nil
}

func describeNIC(n *state.NIC) string {
	if n == nil || n.Mode == "" || n.Mode == "dhcp" {
		return "dhcp"
	}
	s := "static " + n.CIDR
	if n.GW != "" {
		s += " gw " + n.GW
	}
	if len(n.DNS) > 0 {
		s += " dns " + strings.Join(n.DNS, ",")
	}
	return s
}

func yesno(b bool, extra string) string {
	if b {
		if extra != "" {
			return "yes (" + extra + ")"
		}
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func redact(p string) string {
	if i := strings.LastIndex(p, "@"); i >= 0 {
		return "***@" + p[i+1:]
	}
	return p
}
