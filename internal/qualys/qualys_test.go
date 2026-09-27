package qualys

import (
	"os"
	"strings"
	"testing"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func TestParseCSV(t *testing.T) {
	data, err := os.ReadFile("testdata/scan-results.csv")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := Parse(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 || hosts[0].IP != "10.30.9.20" || hosts[0].Hostname != "wms-app-01.acme.local" || hosts[0].OS != "Windows Server 2008 R2" {
		t.Fatalf("hosts: %+v", hosts)
	}
	byQID := map[string]v1.ExternalFinding{}
	for _, f := range hosts[0].Findings {
		byQID[f.ID] = f
	}
	bk := byQID["91534"]
	if bk.Name == "" || bk.Type != "confirmed" || bk.Severity != v1.SeverityCritical || bk.CVSS != 9.8 || bk.Port != 3389 || bk.Proto != "tcp" || len(bk.CVE) != 1 || bk.CVE[0] != "CVE-2019-0708" || bk.Solution != "Apply KB4499175" {
		t.Fatalf("bluekeep: %+v", bk)
	}
	smb := byQID["90007"]
	if smb.Type != "potential" || smb.Severity != v1.SeverityMedium || len(smb.CVE) != 2 || smb.CVSS != 5.0 {
		t.Fatalf("smb: %+v", smb)
	}
	if ig := byQID["45038"]; ig.Type != "info" || ig.Severity != v1.SeverityInfo {
		t.Fatalf("info row: %+v", ig)
	}
	if hosts[2].Hostname != "PRINTER-01" || hosts[2].Findings[0].Severity != v1.SeverityLow {
		t.Fatalf("printer: %+v", hosts[2])
	}
	if s := Summary(hosts); !strings.Contains(s, "3 hosts, 5 detections (3 with CVEs)") {
		t.Fatalf("summary: %s", s)
	}
	if _, err := Parse([]byte("a,b\n1,2\n"), nil); err == nil {
		t.Fatal("csv without IP/QID accepted")
	}
}

func TestParseXMLWithKB(t *testing.T) {
	kbData, _ := os.ReadFile("testdata/kb.xml")
	kb, err := ParseKB(kbData)
	if err != nil || len(kb) != 2 || kb["91534"].CVSSv3 != 9.8 || len(kb["90007"].CVEs) != 2 {
		t.Fatalf("kb: %v %+v", err, kb)
	}
	data, _ := os.ReadFile("testdata/detections.xml")
	hosts, err := Parse(data, kb)
	if err != nil || len(hosts) != 1 || len(hosts[0].Findings) != 2 {
		t.Fatalf("xml: %v %+v", err, hosts)
	}
	bk, smb := hosts[0].Findings[0], hosts[0].Findings[1]
	if bk.Name != kb["91534"].Title || bk.CVE[0] != "CVE-2019-0708" || bk.CVSS != 9.8 || bk.Severity != v1.SeverityCritical || bk.Status != "active" || bk.FirstSeen == nil || bk.LastSeen == nil {
		t.Fatalf("bluekeep from xml: %+v", bk)
	}
	if smb.Type != "potential" || smb.Status != "fixed" || len(smb.CVE) != 2 || smb.Severity != v1.SeverityMedium {
		t.Fatalf("smb from xml: %+v", smb)
	}
	// Without the KB the detection keeps its QID as the name and no CVE.
	hosts, _ = Parse(data, nil)
	if hosts[0].Findings[0].Name != "QID 91534" || len(hosts[0].Findings[0].CVE) != 0 || hosts[0].Findings[0].Severity != v1.SeverityCritical {
		t.Fatalf("xml without kb: %+v", hosts[0].Findings[0])
	}
	if _, err := Parse([]byte("<nope/>"), nil); err == nil {
		t.Fatal("wrong xml accepted")
	}
}

func TestSeverityAndCVEs(t *testing.T) {
	if Severity(5, 0) != v1.SeverityCritical || Severity(4, 0) != v1.SeverityHigh || Severity(3, 0) != v1.SeverityMedium || Severity(2, 0) != v1.SeverityLow || Severity(1, 0) != v1.SeverityInfo || Severity(3, 9.1) != v1.SeverityCritical {
		t.Fatal("severity map")
	}
	if c := CVEs("CVE-2020-1234, cve-2020-1234 CVE-2021-99999"); len(c) != 2 || c[1] != "CVE-2021-99999" {
		t.Fatalf("cves: %v", c)
	}
	if parseFloat("7.5 (AV:N/AC:L)") != 7.5 || parseFloat("-") != 0 || parseFloat("11") != 0 {
		t.Fatal("parseFloat")
	}
}
