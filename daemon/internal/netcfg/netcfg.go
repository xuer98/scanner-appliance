// Package netcfg detects NIC roles and writes systemd-networkd units (PLAN §9, §15).
//
// Roles: on the image the .link files name NICs wan0/lan0 by PCI path. On a
// generic host (container, dev box) the interface carrying the default
// route is "wan" and everything else is "lan". If wan0 and lan0 sit on the
// same subnet the deployment is single-network and both are "single".
package netcfg

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// NetworkdDir is where units are written.
var NetworkdDir = "/etc/systemd/network"

// Interfaces lists non-loopback interfaces with their roles.
func Interfaces() []v1.Iface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	defIface := defaultRouteIface()
	var out []v1.Iface
	var wan, lan *v1.Iface
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 || isVirtual(i.Name) {
			continue
		}
		e := v1.Iface{Name: i.Name, MAC: i.HardwareAddr.String(), IPv4: firstIPv4(i)}
		switch {
		case i.Name == "wan0" || (defIface != "" && i.Name == defIface):
			e.Role = "wan"
		case i.Name == "lan0":
			e.Role = "lan"
		default:
			e.Role = "lan"
		}
		out = append(out, e)
		if e.Role == "wan" && wan == nil {
			wan = &out[len(out)-1]
		} else if e.Role == "lan" && lan == nil {
			lan = &out[len(out)-1]
		}
	}
	if len(out) == 1 {
		out[0].Role = "single"
	} else if wan != nil && lan != nil && sameSubnet(wan.Name, lan.Name) {
		wan.Role, lan.Role = "single", "single"
	}
	return out
}

func firstIPv4(i net.Interface) string {
	addrs, err := i.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	return ""
}

func sameSubnet(a, b string) bool {
	ia, err1 := net.InterfaceByName(a)
	ib, err2 := net.InterfaceByName(b)
	if err1 != nil || err2 != nil {
		return false
	}
	aa, _ := ia.Addrs()
	ba, _ := ib.Addrs()
	for _, x := range aa {
		xn, ok := x.(*net.IPNet)
		if !ok || xn.IP.To4() == nil {
			continue
		}
		for _, y := range ba {
			yn, ok := y.(*net.IPNet)
			if ok && yn.IP.To4() != nil && xn.Contains(yn.IP) {
				return true
			}
		}
	}
	return false
}

// defaultRouteIface parses /proc/net/route (Linux). Empty elsewhere.
func defaultRouteIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func isVirtual(n string) bool {
	for _, p := range []string{"docker", "veth", "br-", "virbr", "vmnet", "utun", "awdl", "llw", "bridge", "tap", "tun", "gif", "stf", "anpi", "ap"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Render produces a systemd .network unit for one NIC.
// lan0 never gets a default route or DNS from DHCP (PLAN §4.3).
func Render(name string, nic *state.NIC, isLAN bool) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# managed by applianced — edit via the console, not by hand\n[Match]\nName=%s\n\n[Network]\n", name)
	if nic == nil || nic.Mode == "" || nic.Mode == "dhcp" {
		sb.WriteString("DHCP=ipv4\n")
		if isLAN {
			sb.WriteString("\n[DHCPv4]\nUseRoutes=no\nUseGateway=no\nUseDNS=no\nUseNTP=no\n")
		} else {
			sb.WriteString("\n[DHCPv4]\nUseNTP=no\n")
		}
		return sb.String(), nil
	}
	if nic.Mode != "static" {
		return "", fmt.Errorf("%s: unknown mode %q", name, nic.Mode)
	}
	ip, ipn, err := net.ParseCIDR(nic.CIDR)
	if err != nil || ip.To4() == nil {
		return "", fmt.Errorf("%s: bad cidr %q", name, nic.CIDR)
	}
	ones, _ := ipn.Mask.Size()
	fmt.Fprintf(&sb, "Address=%s/%d\n", ip, ones)
	if nic.GW != "" {
		gw := net.ParseIP(nic.GW)
		if gw == nil || gw.To4() == nil {
			return "", fmt.Errorf("%s: bad gateway %q", name, nic.GW)
		}
		if !ipn.Contains(gw) {
			return "", fmt.Errorf("%s: gateway %s is outside %s", name, nic.GW, nic.CIDR)
		}
		if isLAN {
			return "", fmt.Errorf("%s: lan0 must not have a gateway", name)
		}
		fmt.Fprintf(&sb, "Gateway=%s\n", gw)
	} else if !isLAN {
		return "", fmt.Errorf("%s: static wan0 needs a gateway", name)
	}
	for _, d := range nic.DNS {
		if net.ParseIP(d) == nil {
			return "", fmt.Errorf("%s: bad dns %q", name, d)
		}
		if isLAN {
			return "", fmt.Errorf("%s: lan0 must not set DNS", name)
		}
		fmt.Fprintf(&sb, "DNS=%s\n", d)
	}
	return sb.String(), nil
}

// Apply writes units for both NICs and reloads networkd.
func Apply(ctx context.Context, n state.Network) error {
	wan, err := Render("wan0", n.WAN0, false)
	if err != nil {
		return err
	}
	lan, err := Render("lan0", n.LAN0, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(NetworkdDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(NetworkdDir, "10-wan0.network"), []byte(wan), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(NetworkdDir, "20-lan0.network"), []byte(lan), 0o644); err != nil {
		return err
	}
	if _, err := exec.LookPath("networkctl"); err != nil {
		return nil // not a systemd host (container/dev); units written for inspection
	}
	if out, err := exec.CommandContext(ctx, "networkctl", "reload").CombinedOutput(); err != nil {
		return fmt.Errorf("networkctl reload: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
