package netcfg

import (
	v1 "github.com/tprm/scanner-appliance/api/v1"
	"strings"
	"testing"

	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

func TestRender(t *testing.T) {
	u, err := Render("wan0", &state.NIC{Mode: "static", CIDR: "10.20.0.50/24", GW: "10.20.0.1", DNS: []string{"10.20.0.10"}}, false)
	if err != nil || !strings.Contains(u, "Address=10.20.0.50/24") || !strings.Contains(u, "Gateway=10.20.0.1") || !strings.Contains(u, "DNS=10.20.0.10") {
		t.Fatalf("%v\n%s", err, u)
	}
	u, err = Render("lan0", nil, true)
	if err != nil || !strings.Contains(u, "UseGateway=no") || !strings.Contains(u, "UseRoutes=no") {
		t.Fatalf("%v\n%s", err, u)
	}
	for _, bad := range []*state.NIC{
		{Mode: "static", CIDR: "10.20.0.50/24"},                  // wan needs gw
		{Mode: "static", CIDR: "10.20.0.50/24", GW: "10.99.0.1"}, // gw outside
		{Mode: "static", CIDR: "nope", GW: "10.20.0.1"},          // bad cidr
		{Mode: "static", CIDR: "10.20.0.50/24", GW: "10.20.0.1", DNS: []string{"x"}},
		{Mode: "bogus"},
	} {
		if _, err := Render("wan0", bad, false); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := Render("lan0", &state.NIC{Mode: "static", CIDR: "10.30.0.5/24", GW: "10.30.0.1"}, true); err == nil {
		t.Fatal("lan0 gateway accepted")
	}
	if _, err := Render("lan0", &state.NIC{Mode: "static", CIDR: "10.30.0.5/24"}, true); err != nil {
		t.Fatal(err)
	}
}

func TestRenderRoutes(t *testing.T) {
	u, err := RenderRoutes("lan0", nil, true, []v1.LANRoute{{CIDR: "10.31.0.0/16", Via: "10.30.5.1"}, {CIDR: "10.32.8.0/24", Via: "10.30.5.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "[Route]\nDestination=10.31.0.0/16\nGateway=10.30.5.1\n") || strings.Count(u, "[Route]") != 2 || !strings.Contains(u, "UseGateway=no") {
		t.Fatalf("unit:\n%s", u)
	}
	for _, bad := range [][]v1.LANRoute{
		{{CIDR: "0.0.0.0/0", Via: "10.30.5.1"}},
		{{CIDR: "10.31.0.0/16", Via: "not-an-ip"}},
		{{CIDR: "nope", Via: "10.30.5.1"}},
	} {
		if _, err := RenderRoutes("lan0", nil, true, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := RenderRoutes("wan0", nil, false, []v1.LANRoute{{CIDR: "10.31.0.0/16", Via: "10.20.0.1"}}); err == nil {
		t.Fatal("routes accepted on wan0")
	}
}
