package scanconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAndLookup(t *testing.T) {
	for _, n := range []string{"inventory", "full"} {
		c, err := Lookup(n, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, f := range c.Families {
			if ExcludedFamilies[f] || strings.HasSuffix(f, forbiddenSuffix) {
				t.Fatalf("%s selects %q", n, f)
			}
		}
		if c.Families[0] != "Service detection" {
			t.Fatalf("%s: detection families not first: %v", n, c.Families[:3])
		}
	}
	if _, err := Lookup("nope", nil); err == nil {
		t.Fatal("unknown config accepted")
	}
}

func TestResolvedStripsPolicyViolations(t *testing.T) {
	c := Config{Name: "x", Families: []string{"Denial of Service", "Web Servers", "Web Servers", "Windows : Local Security Checks"}}
	r := c.Resolved()
	if strings.Join(r.Families, ",") != "Service detection,Product detection,General,Web Servers" {
		t.Fatal(r.Families)
	}
}

func TestLoadAndWriteDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDefaults(dir); err != nil {
		t.Fatal(err)
	}
	m, err := Load(dir)
	if err != nil || len(m) != 2 {
		t.Fatalf("load: %v %d", err, len(m))
	}
	// Override wins over the default and is policy-checked.
	if err := os.WriteFile(filepath.Join(dir, "inventory.json"), []byte(`{"families":["Web Servers"],"udp_ports":[161],"params":{"optimize_test":"1"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Lookup("inventory", m)
	if len(c.UDPPorts) != 1 || len(c.Families) != 4 {
		t.Fatalf("override not applied: %+v", c)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.json"), []byte(`{"families":["Brute force attacks"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("excluded family accepted")
	}
	_ = os.Remove(filepath.Join(dir, "evil.json"))
	if err := os.WriteFile(filepath.Join(dir, "unsafe.json"), []byte(`{"families":["Web Servers"],"params":{"safe_checks":"0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("safe_checks=0 accepted")
	}
	if m, err := Load(filepath.Join(dir, "missing")); err != nil || len(m) != 0 {
		t.Fatalf("missing dir: %v", err)
	}
}
