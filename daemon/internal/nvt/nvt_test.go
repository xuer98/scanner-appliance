package nvt

import (
	"context"
	"errors"
	"testing"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

func TestCVSS(t *testing.T) {
	cases := map[string]float64{
		"AV:N/AC:L/Au:N/C:C/I:C/A:C": 10.0, // CVE-2019-0708 v2
		"AV:N/AC:L/Au:N/C:P/I:P/A:P": 7.5,
		"AV:N/AC:M/Au:N/C:N/I:P/A:N": 4.3,
		"AV:L/AC:H/Au:M/C:N/I:N/A:N": 0,
		"garbage":                    0,
	}
	for v, want := range cases {
		if got := ScoreV2(v); got != want {
			t.Fatalf("v2 %s: got %v want %v", v, got, want)
		}
	}
	cases3 := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases3 {
		if got := ScoreV3(v); got != want {
			t.Fatalf("v3 %s: got %v want %v", v, got, want)
		}
	}
	if Score("", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 2) != 7.5 || Score("", "", 2.5) != 2.5 {
		t.Fatal("Score preference")
	}
}

type fakeSrc struct {
	vts   map[string]*osp.VT
	calls int
	fail  bool
}

func (f *fakeSrc) GetVT(_ context.Context, oid string) (*osp.VT, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("ospd down")
	}
	return f.vts[oid], nil
}

func TestCacheLookup(t *testing.T) {
	src := &fakeSrc{vts: map[string]*osp.VT{
		"1.1": {OID: "1.1", Name: "A", Family: "Windows", CVEs: []string{"CVE-2019-0708"}, QoD: 97, CVSSv2Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
	}}
	dir := t.TempDir()
	c := New(dir, src, nil)
	m, err := c.Lookup(context.Background(), "202609260530", []string{"1.1", "9.9", "1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if m["1.1"].CVSS != 10 || m["1.1"].Family != "Windows" || !m["9.9"].Missing || src.calls != 2 {
		t.Fatalf("%+v calls=%d", m["1.1"], src.calls)
	}
	// Second cache instance reads from disk; no source calls.
	c2 := New(dir, src, nil)
	m2, _ := c2.Lookup(context.Background(), "202609260530", []string{"1.1", "9.9"})
	if src.calls != 2 || m2["1.1"].Name != "A" {
		t.Fatalf("not cached: calls=%d", src.calls)
	}
	// New feed version → refetch; source failure surfaces but keeps going.
	src.fail = true
	if _, err := c2.Lookup(context.Background(), "202610010000", []string{"1.1"}); err == nil {
		t.Fatal("expected error")
	}
	if got := UniqueOIDs([]string{"b", "a", "", "b"}); len(got) != 2 || got[0] != "a" {
		t.Fatal(got)
	}
}
