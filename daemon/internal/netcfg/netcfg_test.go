package netcfg

import (
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
