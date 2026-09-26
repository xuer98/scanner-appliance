// Package seed resolves first-boot personalization (PLAN §5).
//
// Order, first hit wins:
//  1. OVF environment via vmtoolsd (VMware)
//  2. A filesystem labeled APPLIANCE holding seed.yaml (KVM, Hyper-V)
//  3. APPLIANCE_* environment variables (container)
//  4. nothing → the TTY console waits for a human
package seed

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// Seed is the resolved personalization.
type Seed struct {
	Code    string        `yaml:"code"`
	Proxy   string        `yaml:"proxy"`
	CPURL   string        `yaml:"cp_url"`
	Network state.Network `yaml:"network"`
	Split   bool          `yaml:"split"`
	Source  string        `yaml:"-"`
}

// Empty reports whether nothing usable was found.
func (s *Seed) Empty() bool {
	return s == nil || (s.Code == "" && s.Proxy == "" && s.CPURL == "" && s.Network.WAN0 == nil && s.Network.LAN0 == nil)
}

// Resolver lets the sources be swapped in tests.
type Resolver struct {
	VMToolsd  func(ctx context.Context) ([]byte, error)
	VolumeDir string // where the APPLIANCE volume gets mounted
	MountFn   func(ctx context.Context, dir string) (cleanup func(), err error)
	Getenv    func(string) string
	SeedFile  string // explicit override, mainly for tests / --seed-file
}

func Default() *Resolver {
	return &Resolver{
		VMToolsd: func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "vmtoolsd", "--cmd", "info-get guestinfo.ovfEnv").Output()
		},
		VolumeDir: filepath.Join(state.DefaultRunDir, "seed"),
		MountFn:   mountLabel,
		Getenv:    os.Getenv,
	}
}

// Resolve walks the sources.
func (r *Resolver) Resolve(ctx context.Context) (*Seed, error) {
	if r.SeedFile != "" {
		b, err := os.ReadFile(r.SeedFile)
		if err != nil {
			return nil, err
		}
		s, err := ParseYAML(b)
		if err != nil {
			return nil, err
		}
		s.Source = "file:" + r.SeedFile
		return s, nil
	}
	if r.VMToolsd != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		out, err := r.VMToolsd(cctx)
		cancel()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			if s, err := ParseOVFEnv(out); err == nil && !s.Empty() {
				s.Source = "ovf"
				return s, nil
			}
		}
	}
	if r.MountFn != nil {
		cleanup, err := r.MountFn(ctx, r.VolumeDir)
		if err == nil {
			b, rerr := os.ReadFile(filepath.Join(r.VolumeDir, "seed.yaml"))
			cleanup()
			if rerr == nil {
				s, perr := ParseYAML(b)
				if perr != nil {
					return nil, fmt.Errorf("seed.yaml on APPLIANCE volume: %w", perr)
				}
				s.Source = "volume"
				return s, nil
			}
		}
	}
	if r.Getenv != nil {
		if s := FromEnv(r.Getenv); !s.Empty() {
			s.Source = "env"
			return s, nil
		}
	}
	return &Seed{Source: "none"}, nil
}

// ParseYAML decodes seed.yaml.
func ParseYAML(b []byte) (*Seed, error) {
	var s Seed
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &s, validate(&s)
}

// FromEnv reads APPLIANCE_* variables.
func FromEnv(getenv func(string) string) *Seed {
	s := &Seed{Code: getenv("APPLIANCE_CODE"), Proxy: getenv("APPLIANCE_PROXY"), CPURL: getenv("APPLIANCE_CP_URL")}
	s.Split, _ = strconv.ParseBool(getenv("APPLIANCE_SPLIT"))
	if mode := getenv("APPLIANCE_IP_MODE"); mode != "" {
		s.Network.WAN0 = &state.NIC{Mode: mode, CIDR: getenv("APPLIANCE_IP_CIDR"), GW: getenv("APPLIANCE_GW"), DNS: splitList(getenv("APPLIANCE_DNS"))}
	}
	return s
}

// ovfEnv is the subset of the OVF environment document we read.
type ovfEnv struct {
	XMLName    xml.Name `xml:"Environment"`
	Properties []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:"value,attr"`
	} `xml:"PropertySection>Property"`
}

// ParseOVFEnv maps the guestinfo.ovfEnv document to a Seed.
func ParseOVFEnv(doc []byte) (*Seed, error) {
	var env ovfEnv
	if err := xml.Unmarshal(doc, &env); err != nil {
		return nil, err
	}
	props := map[string]string{}
	for _, p := range env.Properties {
		props[p.Key] = strings.TrimSpace(p.Value)
	}
	s := &Seed{Code: props["appliance.code"], Proxy: props["appliance.proxy"], CPURL: props["appliance.cp_url"]}
	s.Split, _ = strconv.ParseBool(props["appliance.split"])
	if mode := props["appliance.ip.mode"]; mode != "" && mode != "dhcp" || props["appliance.ip.cidr"] != "" {
		if mode == "" {
			mode = "static"
		}
		s.Network.WAN0 = &state.NIC{Mode: mode, CIDR: props["appliance.ip.cidr"], GW: props["appliance.gw"], DNS: splitList(props["appliance.dns"])}
	}
	return s, validate(s)
}

func validate(s *Seed) error {
	for name, nic := range map[string]*state.NIC{"wan0": s.Network.WAN0, "lan0": s.Network.LAN0} {
		if nic == nil {
			continue
		}
		switch nic.Mode {
		case "dhcp":
		case "static":
			if nic.CIDR == "" {
				return fmt.Errorf("%s: static mode needs cidr", name)
			}
		default:
			return fmt.Errorf("%s: mode must be dhcp or static", name)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mountLabel mounts the APPLIANCE volume read-only. Requires CAP_SYS_ADMIN.
func mountLabel(ctx context.Context, dir string) (func(), error) {
	dev, err := exec.CommandContext(ctx, "blkid", "-L", "APPLIANCE").Output()
	if err != nil || len(strings.TrimSpace(string(dev))) == 0 {
		return nil, errors.New("no APPLIANCE volume")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if out, err := exec.CommandContext(ctx, "mount", "-o", "ro", strings.TrimSpace(string(dev)), dir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mount: %s", strings.TrimSpace(string(out)))
	}
	return func() { _ = exec.Command("umount", dir).Run() }, nil
}
