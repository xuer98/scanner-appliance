package engine

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// neighMsg builds one RTM_NEWNEIGH message the way the kernel sends it.
func neighMsg(ip string, mac string, state uint16, confirmed time.Duration) []byte {
	le := binary.LittleEndian
	attr := func(typ uint16, val []byte) []byte {
		b := make([]byte, 4, align4(4+len(val)))
		le.PutUint16(b[0:], uint16(4+len(val)))
		le.PutUint16(b[2:], typ)
		b = append(b, val...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	a := netip.MustParseAddr(ip)
	body := make([]byte, ndmsgLen)
	body[0] = 2 // AF_INET
	if a.Is6() {
		body[0] = 10
	}
	le.PutUint32(body[4:], 7) // ifindex
	le.PutUint16(body[8:], state)
	body = append(body, attr(ndaDst, a.AsSlice())...)
	if mac != "" {
		hw, _ := net.ParseMAC(mac)
		body = append(body, attr(ndaLLAddr, hw)...)
	}
	cache := make([]byte, 16)
	le.PutUint32(cache[0:], uint32(confirmed*userHZ/time.Second))
	body = append(body, attr(ndaCacheInfo, cache)...)
	msg := make([]byte, nlmsgHdrLen)
	le.PutUint32(msg[0:], uint32(nlmsgHdrLen+len(body)))
	le.PutUint16(msg[4:], rtmNewNeigh)
	return append(msg, body...)
}

func neighDone() []byte {
	msg := make([]byte, nlmsgHdrLen+4)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], nlmsgDone)
	return msg
}

const (
	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudFailed     = 0x20
)

func TestParseNeighbors(t *testing.T) {
	var dump []byte
	dump = append(dump, neighMsg("172.18.0.4", "ee:43:b4:5a:f9:ad", nudReachable, 3*time.Second)...)
	dump = append(dump, neighMsg("172.18.0.6", "42:b7:bc:5f:ec:5c", nudStale, 26*time.Hour)...)
	dump = append(dump, neighMsg("172.18.0.99", "", nudFailed, 0)...)
	dump = append(dump, neighMsg("fd00::5", "e6:4b:5f:f4:6b:05", nudReachable, 0)...)
	dump = append(dump, neighDone()...)
	dump = append(dump, neighMsg("10.0.0.1", "02:00:00:00:00:01", nudReachable, 0)...) // after the end marker
	got, err := parseNeighbors(dump, binary.LittleEndian)
	if err != nil || len(got) != 4 {
		t.Fatalf("parsed %d entries, %v: %+v", len(got), err, got)
	}
	if n := got[0]; n.IP.String() != "172.18.0.4" || n.MAC.String() != "ee:43:b4:5a:f9:ad" || n.State != nudReachable || n.Confirmed != 3*time.Second {
		t.Fatalf("first entry: %+v", n)
	}
	if n := got[1]; n.Confirmed != 26*time.Hour || n.State != nudStale {
		t.Fatalf("second entry: %+v", n)
	}
	if n := got[2]; n.MAC != nil || n.State != nudFailed {
		t.Fatalf("entry without an address: %+v", n)
	}
	if n := got[3]; n.IP.String() != "fd00::5" {
		t.Fatalf("ipv6 entry: %+v", n)
	}
	// A dump cut short is reported, with what was read before the cut.
	if got, err := parseNeighbors(dump[:len(dump)-70], binary.LittleEndian); err == nil || len(got) != 4 {
		t.Fatalf("truncated dump: %d entries, %v", len(got), err)
	}
	if got, err := parseNeighbors(nil, binary.LittleEndian); err != nil || got != nil {
		t.Fatalf("empty dump: %v %v", got, err)
	}
}

func TestLinkMACs(t *testing.T) {
	mac := func(s string) net.HardwareAddr { hw, _ := net.ParseMAC(s); return hw }
	n := func(ip, hw string, state uint16, confirmed time.Duration) neighbor {
		return neighbor{IP: netip.MustParseAddr(ip), MAC: mac(hw), State: state, Confirmed: confirmed}
	}
	router := "9a:54:86:0b:84:b4"
	table := []neighbor{
		n("172.18.0.4", "ee:43:b4:5a:f9:ad", nudReachable, 2*time.Second),
		n("172.18.0.5", "e6:4b:5f:f4:6b:05", nudStale, 40*time.Second),
		// Resolved yesterday and not confirmed since: the address may have moved.
		n("172.18.0.6", "42:b7:bc:5f:ec:5c", nudStale, 26*time.Hour),
		// A router answering for two addresses (proxy ARP). The second
		// entry is old, and still shows the address is not one host's own.
		n("172.18.1.1", router, nudReachable, time.Second),
		n("172.18.9.9", router, nudStale, 30*time.Hour),
		// Not resolved, a group address, an empty address.
		n("172.18.0.20", "02:00:00:00:00:20", nudIncomplete, 0),
		n("172.18.0.21", "02:00:00:00:00:21", nudFailed, 0),
		n("172.18.0.22", "01:00:5e:00:00:16", nudReachable, 0),
		n("172.18.0.23", "00:00:00:00:00:00", nudReachable, 0),
		// IPv6: the link-local address of a host shares its MAC with the
		// global one and must not look like a second owner.
		n("fd00::7", "16:25:3b:f5:dc:e9", nudReachable, time.Second),
		n("fe80::1425:3bff:fef5:dce9", "16:25:3b:f5:dc:e9", nudReachable, time.Second),
		// One MAC on an IPv4 and an IPv6 address is one dual-stack host.
		n("172.18.0.7", "16:25:3b:f5:dc:e9", nudReachable, time.Second),
	}
	got := linkMACs(table, time.Minute)
	want := map[string]string{"172.18.0.4": "ee:43:b4:5a:f9:ad", "172.18.0.5": "e6:4b:5f:f4:6b:05", "fd00::7": "16:25:3b:f5:dc:e9", "172.18.0.7": "16:25:3b:f5:dc:e9"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for ip, m := range want {
		if got[ip] != m {
			t.Fatalf("%s: got %q, want %q (all: %v)", ip, got[ip], m, got)
		}
	}
	// A job that has only just started trusts only what was confirmed since.
	if got := linkMACs(table, 5*time.Second); len(got) != 3 || got["172.18.0.5"] != "" {
		t.Fatalf("young job: %v", got)
	}
	// Two interfaces that disagree about one address: neither is used.
	clash := []neighbor{n("10.0.0.5", "02:00:00:00:00:05", nudReachable, 0), n("10.0.0.5", "02:00:00:00:00:06", nudReachable, 0)}
	if got := linkMACs(clash, time.Minute); len(got) != 0 {
		t.Fatalf("clash: %v", got)
	}
}

// A host with nothing but TCP services gets its MAC from the neighbor
// table, in the first chunk already, so the control plane can match it by
// MAC before the engine has said anything. A MAC the engine reports is
// only used where the table has none.
func TestHostsGetTheirLinkMAC(t *testing.T) {
	f := fakeOSPD(t, false)
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "naabu.log")))
	calls := 0
	e.Neighbors = func() ([]neighbor, error) {
		calls++
		hw := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
		return []neighbor{
			{IP: netip.MustParseAddr("10.30.5.20"), MAC: hw("02:42:0a:1e:05:14"), State: nudReachable},
			{IP: netip.MustParseAddr("10.30.5.99"), MAC: hw("02:42:0a:1e:05:63"), State: nudReachable},
			{IP: netip.MustParseAddr("10.30.5.77"), MAC: hw("02:42:0a:1e:05:4d"), State: nudReachable}, // not a scanned host
		}, nil
	}
	spec, site := inventorySpec()
	sink := &memSink{}
	if _, err := e.Run(context.Background(), spec, site, sink); err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("the table was read %d times, want once per emit", calls)
	}
	macs := func(b v1.ResultBatch) map[string]string {
		out := map[string]string{}
		for _, h := range b.Hosts {
			out[h.IP] = h.MAC
		}
		return out
	}
	first := map[string]string{}
	all := map[string]string{}
	for _, b := range sink.batches {
		for ip, m := range macs(b) {
			if _, seen := first[ip]; !seen {
				first[ip] = m
			}
			all[ip] = m
		}
	}
	if first["10.30.5.20"] != "02:42:0a:1e:05:14" || first["10.30.5.99"] != "02:42:0a:1e:05:63" {
		t.Fatalf("interim chunk lacks the MACs: %v", first)
	}
	// The engine reported 00:50:56:ab:cd:ef for .20; the table wins.
	if all["10.30.5.20"] != "02:42:0a:1e:05:14" || all["10.30.5.21"] != "" {
		t.Fatalf("final MACs: %v", all)
	}
	if _, leaked := all["10.30.5.77"]; leaked {
		t.Fatalf("a neighbor that was not scanned became a host: %v", all)
	}

	// Without an entry the engine's own report is still used.
	e = newEngine(t, fakeOSPD(t, false), fakeNaabu(t, filepath.Join(t.TempDir(), "naabu.log")))
	e.Neighbors = func() ([]neighbor, error) { return nil, nil }
	sink = &memSink{}
	if _, err := e.Run(context.Background(), spec, site, sink); err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, b := range sink.batches {
		if m := macs(b)["10.30.5.20"]; m != "" {
			got = m
		}
	}
	if got != "00:50:56:ab:cd:ef" {
		t.Fatalf("engine MAC not used as the fallback: %q", got)
	}
}
