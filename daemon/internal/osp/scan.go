package osp

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Scan-related OSP commands (PLAN §10.3): start_scan, get_scans (with
// pop_results), stop_scan, delete_scan and get_vts for one VT's metadata.

// AliveTestConsiderAlive tells openvas to skip its own alive detection;
// the host list comes from naabu, which just saw the hosts answer.
const AliveTestConsiderAlive = 16

// ScanStatus values reported by ospd.
const (
	ScanQueued      = "queued"
	ScanInit        = "init"
	ScanRunning     = "running"
	ScanStopped     = "stopped"
	ScanFinished    = "finished"
	ScanInterrupted = "interrupted"
)

// Target is the <target> element of start_scan.
type Target struct {
	Hosts        []string
	Ports        string // openvas port list syntax, e.g. "T:22,80,443,U:53,161"
	ExcludeHosts []string
	AliveTest    int
}

// VTSelection picks VTs by family and/or by OID.
type VTSelection struct {
	Families []string
	OIDs     []string
}

// StartScan issues <start_scan> and returns ospd's scan id.
func (c *Client) StartScan(ctx context.Context, t Target, params map[string]string, sel VTSelection) (string, error) {
	var sb strings.Builder
	sb.WriteString("<start_scan><targets><target>")
	fmt.Fprintf(&sb, "<hosts>%s</hosts>", esc(strings.Join(t.Hosts, ",")))
	fmt.Fprintf(&sb, "<ports>%s</ports>", esc(t.Ports))
	if len(t.ExcludeHosts) > 0 {
		fmt.Fprintf(&sb, "<exclude_hosts>%s</exclude_hosts>", esc(strings.Join(t.ExcludeHosts, ",")))
	}
	if t.AliveTest > 0 {
		fmt.Fprintf(&sb, "<alive_test>%d</alive_test>", t.AliveTest)
	}
	sb.WriteString("</target></targets>")
	if len(params) > 0 {
		sb.WriteString("<scanner_params>")
		for _, k := range sortedKeys(params) {
			fmt.Fprintf(&sb, "<%s>%s</%s>", k, esc(params[k]), k)
		}
		sb.WriteString("</scanner_params>")
	}
	sb.WriteString("<vt_selection>")
	for _, f := range sel.Families {
		fmt.Fprintf(&sb, `<vt_group filter="family=%s"/>`, esc(f))
	}
	for _, o := range sel.OIDs {
		fmt.Fprintf(&sb, `<vt_single id="%s"/>`, esc(o))
	}
	sb.WriteString("</vt_selection></start_scan>")

	b, err := c.Command(ctx, sb.String())
	if err != nil {
		return "", err
	}
	var r struct {
		XMLName xml.Name `xml:"start_scan_response"`
		Status  string   `xml:"status,attr"`
		Text    string   `xml:"status_text,attr"`
		ID      string   `xml:"id"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("parse start_scan_response: %w", err)
	}
	if r.Status != "200" || strings.TrimSpace(r.ID) == "" {
		return "", fmt.Errorf("ospd start_scan: %s %s", r.Status, r.Text)
	}
	return strings.TrimSpace(r.ID), nil
}

// Result is one <result> of a scan.
type Result struct {
	Host     string `xml:"host,attr"`
	Hostname string `xml:"hostname,attr"`
	Name     string `xml:"name,attr"`
	Type     string `xml:"type,attr"` // Alarm | Log Message | Error Message | Host Detail | Host Start | Host End
	Severity string `xml:"severity,attr"`
	Port     string `xml:"port,attr"` // "80/tcp", "general/tcp"
	TestID   string `xml:"test_id,attr"`
	QoD      string `xml:"qod,attr"`
	URI      string `xml:"uri,attr"`
	Text     string `xml:",chardata"`
}

// SeverityScore parses the severity attribute (a CVSS base score).
func (r Result) SeverityScore() float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
	return f
}

// QoDValue parses qod (0-100).
func (r Result) QoDValue() int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.QoD))
	return n
}

// PortNumber splits "80/tcp" into (80, "tcp"); "general/tcp" gives (0, "tcp").
func (r Result) PortNumber() (int, string) {
	p := strings.TrimSpace(r.Port)
	proto := ""
	if i := strings.Index(p, "/"); i >= 0 {
		proto = p[i+1:]
		p = p[:i]
	}
	n, _ := strconv.Atoi(p)
	return n, proto
}

// Scan is the state of one scan as returned by get_scans.
type Scan struct {
	ID        string   `xml:"id,attr"`
	Target    string   `xml:"target,attr"`
	StartTime string   `xml:"start_time,attr"`
	EndTime   string   `xml:"end_time,attr"`
	Progress  int      `xml:"progress,attr"`
	Status    string   `xml:"status,attr"`
	Results   []Result `xml:"results>result"`
	HostCount struct {
		Alive    int `xml:"count_alive"`
		Dead     int `xml:"count_dead"`
		Excluded int `xml:"count_excluded"`
		Total    int `xml:"count_total"`
	} `xml:"progress"`
}

// Done reports a terminal status.
func (s *Scan) Done() bool {
	switch s.Status {
	case ScanFinished, ScanStopped, ScanInterrupted:
		return true
	}
	return false
}

// GetScan polls one scan. With pop, results already returned are dropped
// by ospd so each call yields only new ones.
func (c *Client) GetScan(ctx context.Context, id string, pop bool, maxResults int) (*Scan, error) {
	popAttr := "0"
	if pop {
		popAttr = "1"
	}
	cmd := fmt.Sprintf(`<get_scans scan_id="%s" details="1" pop_results="%s" progress="1"`, esc(id), popAttr)
	if maxResults > 0 {
		cmd += fmt.Sprintf(` max_results="%d"`, maxResults)
	}
	cmd += "/>"
	b, err := c.Command(ctx, cmd)
	if err != nil {
		return nil, err
	}
	var r struct {
		XMLName xml.Name `xml:"get_scans_response"`
		Status  string   `xml:"status,attr"`
		Text    string   `xml:"status_text,attr"`
		Scans   []Scan   `xml:"scan"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse get_scans_response: %w", err)
	}
	if r.Status != "200" {
		return nil, fmt.Errorf("ospd get_scans: %s %s", r.Status, r.Text)
	}
	if len(r.Scans) == 0 {
		return nil, fmt.Errorf("ospd get_scans: scan %s not found", id)
	}
	return &r.Scans[0], nil
}

// StopScan issues <stop_scan>.
func (c *Client) StopScan(ctx context.Context, id string) error {
	return c.simple(ctx, fmt.Sprintf(`<stop_scan scan_id="%s"/>`, esc(id)), "stop_scan_response")
}

// DeleteScan issues <delete_scan> (only valid once the scan is finished or stopped).
func (c *Client) DeleteScan(ctx context.Context, id string) error {
	return c.simple(ctx, fmt.Sprintf(`<delete_scan scan_id="%s"/>`, esc(id)), "delete_scan_response")
}

func (c *Client) simple(ctx context.Context, cmd, want string) error {
	b, err := c.Command(ctx, cmd)
	if err != nil {
		return err
	}
	var r struct {
		XMLName xml.Name
		Status  string `xml:"status,attr"`
		Text    string `xml:"status_text,attr"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("parse %s: %w", want, err)
	}
	if r.XMLName.Local != want && r.XMLName.Local != "osp_response" {
		return fmt.Errorf("unexpected %s", r.XMLName.Local)
	}
	if r.Status != "200" {
		return fmt.Errorf("ospd %s: %s %s", want, r.Status, r.Text)
	}
	return nil
}

// VT is the metadata of one VT from <get_vts details="1">.
type VT struct {
	OID          string
	Name         string
	Family       string
	Summary      string
	Solution     string
	SolutionType string
	CVEs         []string
	QoD          int
	QoDType      string
	// CVSS vectors as shipped by the feed (either may be empty).
	CVSSv2Vector string
	CVSSv3Vector string
	// CVSSBase is the feed's own cvss_base when present.
	CVSSBase float64
}

type vtXML struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
	Refs []struct {
		Type string `xml:"type,attr"`
		ID   string `xml:"id,attr"`
	} `xml:"refs>ref"`
	Summary  string `xml:"summary"`
	Solution struct {
		Type string `xml:"type,attr"`
		Text string `xml:",chardata"`
	} `xml:"solution"`
	Detection struct {
		QoDType string `xml:"qod_type,attr"`
		QoD     string `xml:"qod,attr"`
	} `xml:"detection"`
	Severities []struct {
		Type  string `xml:"type,attr"`
		Value string `xml:"value"`
	} `xml:"severities>severity"`
	Custom struct {
		Family   string `xml:"family"`
		CVSSBase string `xml:"cvss_base"`
	} `xml:"custom"`
}

func (v vtXML) toVT() *VT {
	out := &VT{OID: v.ID, Name: strings.TrimSpace(v.Name), Family: strings.TrimSpace(v.Custom.Family),
		Summary: strings.TrimSpace(v.Summary), Solution: strings.TrimSpace(v.Solution.Text), SolutionType: v.Solution.Type,
		QoDType: v.Detection.QoDType}
	out.QoD, _ = strconv.Atoi(strings.TrimSpace(v.Detection.QoD))
	out.CVSSBase, _ = strconv.ParseFloat(strings.TrimSpace(v.Custom.CVSSBase), 64)
	for _, r := range v.Refs {
		if strings.EqualFold(r.Type, "cve") {
			out.CVEs = append(out.CVEs, strings.ToUpper(strings.TrimSpace(r.ID)))
		}
	}
	for _, s := range v.Severities {
		switch s.Type {
		case "cvss_base_v2":
			out.CVSSv2Vector = strings.TrimSpace(s.Value)
		case "cvss_base_v3":
			out.CVSSv3Vector = strings.TrimSpace(s.Value)
		}
	}
	return out
}

// GetVT fetches one VT's metadata (nil, nil when the feed has no such OID).
func (c *Client) GetVT(ctx context.Context, oid string) (*VT, error) {
	b, err := c.Command(ctx, fmt.Sprintf(`<get_vts vt_id="%s" details="1"/>`, esc(oid)))
	if err != nil {
		return nil, err
	}
	var r struct {
		XMLName xml.Name `xml:"get_vts_response"`
		Status  string   `xml:"status,attr"`
		Text    string   `xml:"status_text,attr"`
		VTs     []vtXML  `xml:"vts>vt"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse get_vts_response: %w", err)
	}
	if r.Status == "404" {
		return nil, nil
	}
	if r.Status != "200" {
		return nil, fmt.Errorf("ospd get_vts: %s %s", r.Status, r.Text)
	}
	if len(r.VTs) == 0 {
		return nil, nil
	}
	return r.VTs[0].toVT(), nil
}

// bulkTimeout bounds one full-feed get_vts when the caller's context has
// no earlier deadline.
const bulkTimeout = 10 * time.Minute

// GetVTs fetches the metadata of many VTs with one full-feed <get_vts/>,
// streaming the response and keeping only the wanted OIDs. ospd-openvas
// cannot select several VTs at once (its filter only takes modification
// times) and answers each single-VT query by first walking the whole feed
// in redis, which costs seconds per call; the full list costs about as
// much as seven of those. OIDs the feed does not carry are absent from the
// result. On error the VTs decoded so far are still returned.
func (c *Client) GetVTs(ctx context.Context, oids []string) (map[string]*VT, error) {
	want := make(map[string]bool, len(oids))
	for _, o := range oids {
		want[o] = true
	}
	out := make(map[string]*VT, len(want))
	if len(want) == 0 {
		return out, nil
	}
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	deadline := time.Now().Add(bulkTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, `<get_vts details="1"/>`); err != nil {
		return out, err
	}
	fail := func(err error) (map[string]*VT, error) {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, fmt.Errorf("parse get_vts_response: %w", err)
	}
	dec := xml.NewDecoder(bufio.NewReaderSize(conn, 1<<16))
	answered := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !answered {
				return fail(errors.New("empty response"))
			}
			return out, nil
		}
		if err != nil {
			return fail(err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "get_vts_response":
			if st := startAttr(se, "status"); st != "200" {
				return out, fmt.Errorf("ospd get_vts: %s %s", st, startAttr(se, "status_text"))
			}
			answered = true
		case "vt":
			if !want[startAttr(se, "id")] {
				if err := dec.Skip(); err != nil {
					return fail(err)
				}
				continue
			}
			var v vtXML
			if err := dec.DecodeElement(&v, &se); err != nil {
				return fail(err)
			}
			out[v.ID] = v.toVT()
		}
	}
}

func startAttr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// FeedVersion returns the loaded VT feed version from get_version.
func (c *Client) FeedVersion(ctx context.Context) (string, error) {
	vr, err := c.Version(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(vr.VTs.Version), nil
}

func esc(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
