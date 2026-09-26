// Package osp is a minimal Open Scanner Protocol client (XML over a Unix
// socket) for ospd-openvas: the health probe that feeds the heartbeat
// (osp.go), the scan lifecycle and VT metadata calls (scan.go), and the
// redis + ospd supervisor used where there is no systemd (supervise.go).
package osp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// DefaultSocket is where install-openvas.sh puts the ospd listener.
const DefaultSocket = "/run/ospd/ospd.sock"

// Client talks to one ospd socket.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// New returns a client for the socket (DefaultSocket when empty).
func New(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	return &Client{Socket: socket, Timeout: 15 * time.Second}
}

// VersionResponse is <get_version_response>.
type VersionResponse struct {
	XMLName  xml.Name `xml:"get_version_response"`
	Status   string   `xml:"status,attr"`
	Text     string   `xml:"status_text,attr"`
	Protocol struct {
		Name    string `xml:"name"`
		Version string `xml:"version"`
	} `xml:"protocol"`
	Daemon struct {
		Name    string `xml:"name"`
		Version string `xml:"version"`
	} `xml:"daemon"`
	Scanner struct {
		Name    string `xml:"name"`
		Version string `xml:"version"`
	} `xml:"scanner"`
	VTs struct {
		Version string `xml:"version"`
	} `xml:"vts"`
}

// vtsCount is the subset of <get_vts_response> we read when asking for details="0".
type vtsResponse struct {
	XMLName xml.Name `xml:"get_vts_response"`
	Status  string   `xml:"status,attr"`
	VTs     struct {
		Total string `xml:"total,attr"`
	} `xml:"vts"`
}

// Command sends one OSP command and returns the raw response.
func (c *Client) Command(ctx context.Context, cmd string) ([]byte, error) {
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(c.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, cmd); err != nil {
		return nil, err
	}
	// ospd closes the connection after one response.
	b, err := io.ReadAll(io.LimitReader(conn, 64<<20))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	return b, nil
}

// Version runs <get_version/>.
func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	b, err := c.Command(ctx, "<get_version/>")
	if err != nil {
		return nil, err
	}
	var vr VersionResponse
	if err := xml.Unmarshal(b, &vr); err != nil {
		return nil, fmt.Errorf("parse get_version_response: %w", err)
	}
	if vr.Status != "" && vr.Status != "200" {
		return &vr, fmt.Errorf("ospd: %s %s", vr.Status, vr.Text)
	}
	return &vr, nil
}

// VTCount runs <get_vts details="0"/> and reads the total attribute
// (ospd-openvas ≥ 21 reports it; older builds return 0 here).
func (c *Client) VTCount(ctx context.Context) (int, error) {
	b, err := c.Command(ctx, `<get_vts details="0" filter="id=none"/>`)
	if err != nil {
		return 0, err
	}
	var r vtsResponse
	if err := xml.Unmarshal(b, &r); err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(r.VTs.Total))
	return n, nil
}

// Health is the heartbeat probe. It never returns an error: problems land in
// EngineHealth.Error so the control plane can see them.
func (c *Client) Health(ctx context.Context) v1.EngineHealth {
	h := v1.EngineHealth{}
	if _, err := os.Stat(c.Socket); err != nil {
		h.Error = "ospd socket absent"
		return h
	}
	vr, err := c.Version(ctx)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, os.ErrNotExist) {
			h.Error = "ospd not answering: " + err.Error()
		} else {
			h.Error = err.Error()
		}
		return h
	}
	h.OSPDUp = true
	h.OSPDVersion = vr.Daemon.Version
	h.OpenVASVersion = vr.Scanner.Version
	// ospd-openvas leaves <vts><version/></vts> empty until the redis VT cache is loaded.
	h.VTCacheLoaded = strings.TrimSpace(vr.VTs.Version) != ""
	h.FeedVersion = strings.TrimSpace(vr.VTs.Version)
	if h.VTCacheLoaded {
		if n, err := c.VTCount(ctx); err == nil {
			h.VTCount = n
		}
	}
	return h
}
