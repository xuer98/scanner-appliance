package seed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const ovfDoc = `<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" oe:id="">
  <PlatformSection><Kind>VMware ESXi</Kind></PlatformSection>
  <PropertySection>
    <Property oe:key="appliance.code" oe:value="ABCD-EFGH-JKMN-PQRS-TVWX"/>
    <Property oe:key="appliance.proxy" oe:value="user:pw@proxy:3128"/>
    <Property oe:key="appliance.ip.mode" oe:value="static"/>
    <Property oe:key="appliance.ip.cidr" oe:value="10.20.0.50/24"/>
    <Property oe:key="appliance.gw" oe:value="10.20.0.1"/>
    <Property oe:key="appliance.dns" oe:value="10.20.0.10,10.20.0.11"/>
    <Property oe:key="appliance.split" oe:value="True"/>
  </PropertySection>
</Environment>`

func TestOVF(t *testing.T) {
	s, err := ParseOVFEnv([]byte(ovfDoc))
	if err != nil {
		t.Fatal(err)
	}
	if s.Code != "ABCD-EFGH-JKMN-PQRS-TVWX" || s.Proxy != "user:pw@proxy:3128" || !s.Split {
		t.Fatalf("%+v", s)
	}
	if s.Network.WAN0 == nil || s.Network.WAN0.CIDR != "10.20.0.50/24" || len(s.Network.WAN0.DNS) != 2 {
		t.Fatalf("%+v", s.Network.WAN0)
	}
}

func TestYAMLAndOrder(t *testing.T) {
	dir := t.TempDir()
	y := []byte("code: \"AAAA-BBBB-CCCC-DDDD-EEEE\"\nproxy: proxy.vendor.local:3128\nnetwork:\n  wan0: { mode: static, cidr: 10.20.0.50/24, gw: 10.20.0.1, dns: [10.20.0.10] }\n  lan0: { mode: dhcp }\nsplit: true\n")
	if err := os.WriteFile(filepath.Join(dir, "seed.yaml"), y, 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{
		VMToolsd:  func(context.Context) ([]byte, error) { return nil, os.ErrNotExist },
		VolumeDir: dir,
		MountFn:   func(context.Context, string) (func(), error) { return func() {}, nil },
		Getenv:    func(k string) string { return map[string]string{"APPLIANCE_CODE": "ENV"}[k] },
	}
	s, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != "volume" || s.Code != "AAAA-BBBB-CCCC-DDDD-EEEE" || s.Network.LAN0.Mode != "dhcp" || !s.Split {
		t.Fatalf("%+v", s)
	}
	// OVF wins over volume.
	r.VMToolsd = func(context.Context) ([]byte, error) { return []byte(ovfDoc), nil }
	s, _ = r.Resolve(context.Background())
	if s.Source != "ovf" {
		t.Fatalf("source %s", s.Source)
	}
	// Env when nothing else.
	r.VMToolsd = nil
	r.MountFn = func(context.Context, string) (func(), error) { return nil, os.ErrNotExist }
	s, _ = r.Resolve(context.Background())
	if s.Source != "env" || s.Code != "ENV" {
		t.Fatalf("%+v", s)
	}
	r.Getenv = func(string) string { return "" }
	s, _ = r.Resolve(context.Background())
	if s.Source != "none" || !s.Empty() {
		t.Fatalf("%+v", s)
	}
	if _, err := ParseYAML([]byte("network:\n  wan0: { mode: static }\n")); err == nil {
		t.Fatal("static without cidr accepted")
	}
	if _, err := ParseYAML([]byte("bogus: 1\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}
