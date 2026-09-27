// Package qualys parses Qualys VM exports (scan results / vulnerability
// details CSV, host list detection XML, KnowledgeBase XML) into the
// control plane's external-scan form, for the migration period during
// which a site runs both the Qualys scanner and the appliance and the
// parity report compares them (docs/MIGRATION.md).
//
// Only the columns and elements the comparison needs are read; unknown
// ones are ignored so a differently configured export still loads.
package qualys

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Scanner is the source name recorded on imported findings.
const Scanner = "qualys"

// KB maps QIDs to the KnowledgeBase metadata the detection export lacks.
type KB map[string]KBEntry

// KBEntry is one KnowledgeBase vulnerability.
type KBEntry struct {
	QID      string
	Title    string
	Severity int
	CVEs     []string
	CVSS     float64
	CVSSv3   float64
	Solution string
	Type     string // Vulnerability | Potential Vulnerability | Information Gathered
}

// Severity maps Qualys 1..5 to the appliance's buckets, preferring the
// CVSS base score when one is known: 5 Urgent → critical, 4 Critical →
// high, 3 Serious → medium, 2 Medium → low, 1 Minimal → info.
func Severity(level int, cvss float64) string {
	if cvss > 0 {
		return v1.SeverityFor(cvss)
	}
	switch level {
	case 5:
		return v1.SeverityCritical
	case 4:
		return v1.SeverityHigh
	case 3:
		return v1.SeverityMedium
	case 2:
		return v1.SeverityLow
	}
	return v1.SeverityInfo
}

var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// CVEs extracts CVE ids from a comma/space separated field.
func CVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveRe.FindAllString(s, -1) {
		m = strings.ToUpper(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// bom is the UTF-8 byte order mark some exports start with.
const bom = "\xef\xbb\xbf"

// Parse sniffs the format (XML documents start with '<'; anything else is
// CSV) and converts. kb may be nil.
func Parse(data []byte, kb KB) ([]v1.ExternalHost, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n"+bom)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return ParseDetectionXML(trimmed, kb)
	}
	return ParseCSV(trimmed, kb)
}

// ---- CSV ----

// csvAliases map the columns this package reads to the headers Qualys
// uses across its exports (scan results, vulnerability details, host
// detection list). Matching is case-insensitive on the trimmed header.
var csvAliases = map[string][]string{
	"ip":       {"IP", "IP Address"},
	"dns":      {"DNS", "DNS Name", "Host Name", "Hostname"},
	"netbios":  {"NetBIOS", "NetBIOS Name"},
	"os":       {"OS", "Operating System"},
	"qid":      {"QID"},
	"title":    {"Title", "Vulnerability Title"},
	"type":     {"Type", "Vuln Type", "Detection Type"},
	"severity": {"Severity", "Severity Level"},
	"port":     {"Port"},
	"protocol": {"Protocol"},
	"cve":      {"CVE ID", "CVE", "CVE IDs"},
	"cvss":     {"CVSS3 Base", "CVSS3.1 Base", "CVSS Base", "CVSS3 Score", "CVSS Score"},
	"status":   {"Status", "Vuln Status", "Detection Status"},
	"first":    {"First Detected", "First Found", "First Found Datetime", "First Detected Date"},
	"last":     {"Last Detected", "Last Found", "Last Found Datetime", "Last Detected Date"},
	"results":  {"Results", "Result"},
	"solution": {"Solution"},
}

func findHeader(rec []string) (map[string]int, bool) {
	idx := map[string]int{}
	for i, h := range rec {
		h = strings.TrimSpace(strings.Trim(h, "\""))
		for key, names := range csvAliases {
			if _, done := idx[key]; done {
				continue
			}
			for _, n := range names {
				if strings.EqualFold(h, n) {
					idx[key] = i
				}
			}
		}
	}
	_, hasIP := idx["ip"]
	_, hasQID := idx["qid"]
	return idx, hasIP && hasQID
}

// ParseCSV reads a Qualys CSV export. Qualys prefixes the table with
// report metadata lines; the header is the first row that has both IP and
// QID columns. Rows are grouped by IP.
func ParseCSV(data []byte, kb KB) ([]v1.ExternalHost, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var idx map[string]int
	var rows [][]string
	var pending []string
	for sc.Scan() {
		line := sc.Text()
		if idx == nil {
			rec, err := csv.NewReader(strings.NewReader(line)).Read()
			if err != nil {
				continue
			}
			if m, ok := findHeader(rec); ok {
				idx = m
			}
			continue
		}
		pending = append(pending, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, errors.New("qualys csv: no header row with IP and QID columns")
	}
	r := csv.NewReader(strings.NewReader(strings.Join(pending, "\n")))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("qualys csv: %w", err)
		}
		rows = append(rows, rec)
	}
	get := func(rec []string, key string) string {
		i, ok := idx[key]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	hosts := map[string]*v1.ExternalHost{}
	var order []string
	for _, rec := range rows {
		ip := get(rec, "ip")
		qid := get(rec, "qid")
		if ip == "" || qid == "" {
			continue
		}
		h := hosts[ip]
		if h == nil {
			h = &v1.ExternalHost{IP: ip, Hostname: firstNonEmpty(get(rec, "dns"), get(rec, "netbios")), OS: get(rec, "os")}
			hosts[ip] = h
			order = append(order, ip)
		}
		f := v1.ExternalFinding{ID: qid, Name: get(rec, "title"), Type: normType(get(rec, "type")), CVE: CVEs(get(rec, "cve")),
			Proto: strings.ToLower(get(rec, "protocol")), Status: normStatus(get(rec, "status")), Evidence: clip(get(rec, "results"), 4096), Solution: clip(get(rec, "solution"), 4096)}
		f.Port, _ = strconv.Atoi(get(rec, "port"))
		f.CVSS = parseFloat(get(rec, "cvss"))
		level, _ := strconv.Atoi(get(rec, "severity"))
		if e, ok := kb[qid]; ok {
			if f.Name == "" {
				f.Name = e.Title
			}
			if len(f.CVE) == 0 {
				f.CVE = append([]string{}, e.CVEs...)
			}
			if f.CVSS == 0 {
				f.CVSS = firstPositive(e.CVSSv3, e.CVSS)
			}
			if level == 0 {
				level = e.Severity
			}
			if f.Solution == "" {
				f.Solution = e.Solution
			}
			if f.Type == "" {
				f.Type = normType(e.Type)
			}
		}
		f.Severity = Severity(level, f.CVSS)
		if f.Type == "" {
			f.Type = "confirmed"
		}
		f.FirstSeen = parseTime(get(rec, "first"))
		f.LastSeen = parseTime(get(rec, "last"))
		h.Findings = append(h.Findings, f)
	}
	out := make([]v1.ExternalHost, 0, len(order))
	for _, ip := range order {
		out = append(out, *hosts[ip])
	}
	return out, nil
}

// ---- Host List Detection XML ----

type detectionOutput struct {
	XMLName xml.Name `xml:"HOST_LIST_VM_DETECTION_OUTPUT"`
	Hosts   []struct {
		IP         string `xml:"IP"`
		DNS        string `xml:"DNS"`
		NetBIOS    string `xml:"NETBIOS"`
		OS         string `xml:"OS"`
		Detections []struct {
			QID       string `xml:"QID"`
			Type      string `xml:"TYPE"`
			Severity  int    `xml:"SEVERITY"`
			Port      int    `xml:"PORT"`
			Protocol  string `xml:"PROTOCOL"`
			Results   string `xml:"RESULTS"`
			Status    string `xml:"STATUS"`
			FirstSeen string `xml:"FIRST_FOUND_DATETIME"`
			LastSeen  string `xml:"LAST_FOUND_DATETIME"`
		} `xml:"DETECTION_LIST>DETECTION"`
	} `xml:"RESPONSE>HOST_LIST>HOST"`
}

// ParseDetectionXML reads the host list detection API output. Detections
// carry no CVE or title; a KnowledgeBase export (ParseKB) fills them in.
func ParseDetectionXML(data []byte, kb KB) ([]v1.ExternalHost, error) {
	var doc detectionOutput
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("qualys xml: %w", err)
	}
	var out []v1.ExternalHost
	for _, h := range doc.Hosts {
		ip := strings.TrimSpace(h.IP)
		if ip == "" {
			continue
		}
		eh := v1.ExternalHost{IP: ip, Hostname: firstNonEmpty(strings.TrimSpace(h.DNS), strings.TrimSpace(h.NetBIOS)), OS: strings.TrimSpace(h.OS)}
		for _, d := range h.Detections {
			qid := strings.TrimSpace(d.QID)
			if qid == "" {
				continue
			}
			f := v1.ExternalFinding{ID: qid, Type: normType(d.Type), Port: d.Port, Proto: strings.ToLower(strings.TrimSpace(d.Protocol)),
				Status: normStatus(d.Status), Evidence: clip(strings.TrimSpace(d.Results), 4096), CVE: []string{}}
			level := d.Severity
			if e, ok := kb[qid]; ok {
				f.Name, f.Solution = e.Title, e.Solution
				f.CVE = append([]string{}, e.CVEs...)
				f.CVSS = firstPositive(e.CVSSv3, e.CVSS)
				if level == 0 {
					level = e.Severity
				}
				if f.Type == "" {
					f.Type = normType(e.Type)
				}
			}
			if f.Name == "" {
				f.Name = "QID " + qid
			}
			f.Severity = Severity(level, f.CVSS)
			if f.Type == "" {
				f.Type = "confirmed"
			}
			f.FirstSeen = parseTime(d.FirstSeen)
			f.LastSeen = parseTime(d.LastSeen)
			eh.Findings = append(eh.Findings, f)
		}
		out = append(out, eh)
	}
	return out, nil
}

// ---- KnowledgeBase XML ----

type kbOutput struct {
	XMLName xml.Name `xml:"KNOWLEDGE_BASE_VULN_LIST_OUTPUT"`
	Vulns   []struct {
		QID      string `xml:"QID"`
		Type     string `xml:"VULN_TYPE"`
		Severity int    `xml:"SEVERITY_LEVEL"`
		Title    string `xml:"TITLE"`
		CVEs     []struct {
			ID string `xml:"ID"`
		} `xml:"CVE_LIST>CVE"`
		CVSS     string `xml:"CVSS>BASE"`
		CVSSv3   string `xml:"CVSS_V3>BASE"`
		Solution string `xml:"SOLUTION"`
	} `xml:"RESPONSE>VULN_LIST>VULN"`
}

// ParseKB reads a KnowledgeBase export (knowledge_base/vuln API output).
func ParseKB(data []byte) (KB, error) {
	var doc kbOutput
	if err := xml.Unmarshal(bytes.TrimLeft(data, " \t\r\n"+bom), &doc); err != nil {
		return nil, fmt.Errorf("qualys knowledgebase: %w", err)
	}
	kb := KB{}
	for _, v := range doc.Vulns {
		qid := strings.TrimSpace(v.QID)
		if qid == "" {
			continue
		}
		e := KBEntry{QID: qid, Title: strings.TrimSpace(v.Title), Severity: v.Severity, Type: strings.TrimSpace(v.Type), Solution: clip(strings.TrimSpace(v.Solution), 4096),
			CVSS: parseFloat(v.CVSS), CVSSv3: parseFloat(v.CVSSv3)}
		for _, c := range v.CVEs {
			e.CVEs = append(e.CVEs, CVEs(c.ID)...)
		}
		kb[qid] = e
	}
	return kb, nil
}

// ---- helpers ----

func normType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "confirmed", "vuln", "vulnerability":
		return "confirmed"
	case "potential", "practice", "potential vulnerability":
		return "potential"
	case "info", "ig", "information gathered", "information":
		return "info"
	}
	return ""
}

func normStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "new":
		return "new"
	case "active":
		return "active"
	case "fixed":
		return "fixed"
	case "re-opened", "reopened":
		return "reopened"
	}
	return ""
}

var timeLayouts = []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "01/02/2006 15:04:05", "2006-01-02"}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	// "7.5 (AV:N/AC:L/...)" appears in some exports.
	if i := strings.IndexAny(s, " ("); i > 0 {
		s = s[:i]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 10 {
		return 0
	}
	return f
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstPositive(a, b float64) float64 {
	if a > 0 {
		return a
	}
	return b
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Summary counts a parsed export for the CLI.
func Summary(hosts []v1.ExternalHost) string {
	n, cve := 0, 0
	sev := map[string]int{}
	for _, h := range hosts {
		for _, f := range h.Findings {
			n++
			sev[f.Severity]++
			if len(f.CVE) > 0 {
				cve++
			}
		}
	}
	keys := make([]string, 0, len(sev))
	for k := range sev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, sev[k]))
	}
	return fmt.Sprintf("%d hosts, %d detections (%d with CVEs): %s", len(hosts), n, cve, strings.Join(parts, " "))
}
