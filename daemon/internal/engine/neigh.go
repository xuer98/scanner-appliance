package engine

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Link-layer addresses. The control plane matches a host by MAC before
// anything else (PLAN §12.3), yet naabu prints bare IP addresses and the
// engine reports a MAC only where one of its tests reads one (SNMP,
// NetBIOS), so a host with nothing but TCP services reached the control
// plane without one.
//
// The kernel knows it all the same: to send a probe to a host on its own
// segment it resolves the host's link-layer address and keeps the answer in
// its neighbor table. The table is read over rtnetlink before results are
// emitted. A host behind a router has no entry and gets no MAC here.
//
// Two rules keep a wrong address out, because host records are merged on
// it. An entry counts only when the kernel confirmed it after the job
// started: an older one may describe a device that has since left the
// address. And an address that answers for more than one IP is not a host's
// own (a router doing proxy ARP, a load balancer), so it is used for none.

// neighbor is one entry of the kernel's neighbor table.
type neighbor struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	State     uint16
	Confirmed time.Duration // since the kernel last confirmed the address
}

// Neighbor states (linux/neighbour.h) in which the entry holds an address
// the kernel resolved itself: reachable, stale, delay, probe.
const nudResolved = 0x02 | 0x04 | 0x08 | 0x10

// rtnetlink constants (linux/rtnetlink.h, linux/neighbour.h).
const (
	nlmsgError   = 2
	nlmsgDone    = 3
	rtmNewNeigh  = 28
	ndaDst       = 1
	ndaLLAddr    = 2
	ndaCacheInfo = 3
	nlmsgHdrLen  = 16
	ndmsgLen     = 12
	// userHZ is the unit of the cache ages: clock ticks, 100 a second on
	// every architecture the appliance is built for.
	userHZ = 100
)

// parseNeighbors decodes an RTM_GETNEIGH dump.
func parseNeighbors(b []byte, order binary.ByteOrder) ([]neighbor, error) {
	var out []neighbor
	for len(b) >= nlmsgHdrLen {
		l := int(order.Uint32(b[0:4]))
		typ := order.Uint16(b[4:6])
		if l < nlmsgHdrLen || l > len(b) {
			return out, errors.New("neighbor table: truncated netlink message")
		}
		body := b[nlmsgHdrLen:l]
		b = b[min(align4(l), len(b)):]
		switch typ {
		case nlmsgDone:
			return out, nil
		case nlmsgError:
			return out, errors.New("neighbor table: netlink error")
		case rtmNewNeigh:
		default:
			continue
		}
		if len(body) < ndmsgLen {
			continue
		}
		n := neighbor{State: order.Uint16(body[8:10]), Confirmed: -1}
		for attrs := body[ndmsgLen:]; len(attrs) >= 4; {
			al := int(order.Uint16(attrs[0:2]))
			at := order.Uint16(attrs[2:4])
			if al < 4 || al > len(attrs) {
				break
			}
			val := attrs[4:al]
			switch at {
			case ndaDst:
				if a, ok := netip.AddrFromSlice(val); ok {
					n.IP = a.Unmap()
				}
			case ndaLLAddr:
				n.MAC = append(net.HardwareAddr{}, val...)
			case ndaCacheInfo:
				if len(val) >= 4 {
					n.Confirmed = time.Duration(order.Uint32(val[0:4])) * time.Second / userHZ
				}
			}
			attrs = attrs[min(align4(al), len(attrs)):]
		}
		if n.IP.IsValid() {
			out = append(out, n)
		}
	}
	return out, nil
}

func align4(n int) int { return (n + 3) &^ 3 }

// linkMACs picks the hosts' own link-layer addresses out of the table:
// IP → MAC for every entry the kernel confirmed within maxAge, less the
// addresses that answer for several IPs of one family.
func linkMACs(table []neighbor, maxAge time.Duration) map[string]string {
	type key struct {
		mac string
		v4  bool
	}
	owners := map[key]map[netip.Addr]bool{}
	usable := func(n neighbor) bool {
		if n.State&nudResolved == 0 || len(n.MAC) != 6 || n.MAC[0]&1 != 0 || n.IP.IsLinkLocalUnicast() {
			return false
		}
		for _, x := range n.MAC {
			if x != 0 {
				return true
			}
		}
		return false
	}
	for _, n := range table {
		if !usable(n) {
			continue
		}
		k := key{n.MAC.String(), n.IP.Is4()}
		if owners[k] == nil {
			owners[k] = map[netip.Addr]bool{}
		}
		owners[k][n.IP] = true
	}
	out := map[string]string{}
	seen := map[string]string{}
	for _, n := range table {
		if !usable(n) || n.Confirmed < 0 || n.Confirmed > maxAge {
			continue
		}
		mac := n.MAC.String()
		if len(owners[key{mac, n.IP.Is4()}]) != 1 {
			continue
		}
		ip := n.IP.String()
		if prev, dup := seen[ip]; dup && prev != mac {
			delete(out, ip) // two interfaces disagree about the address
			continue
		}
		seen[ip] = mac
		out[ip] = mac
	}
	return out
}

// learnMACs gives every host the kernel resolved during this job its
// link-layer address.
func (r *run) learnMACs() {
	read := r.e.Neighbors
	if read == nil {
		read = readNeighbors
	}
	table, err := read()
	if err != nil {
		r.log.Debug("neighbor table not read", "err", err)
		return
	}
	macs := linkMACs(table, r.e.Now().Sub(r.start))
	n := 0
	for ip, h := range r.hosts {
		if h.linkMAC != "" {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if mac := macs[a.Unmap().String()]; mac != "" {
			h.linkMAC = mac
			n++
		}
	}
	if n > 0 {
		r.log.Info("link-layer addresses read from the neighbor table", "hosts", n)
	}
}
