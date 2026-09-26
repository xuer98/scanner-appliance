package osp_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
)

func TestScanLifecycle(t *testing.T) {
	f := osptest.Start(t, &osptest.Fake{
		VTs: map[string]osptest.VT{"1.3.6.1.4.1.25623.1.0.108587": {Name: "BlueKeep", Family: "Windows", QoD: 97, QoDType: "remote_active", CVEs: []string{"CVE-2019-0708"}, CVSSv2: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Solution: "Patch"}},
		Script: []osptest.Step{
			{Progress: 10},
			{Progress: 60, Results: []osp.Result{{Host: "10.30.5.20", Type: "Alarm", Severity: "9.8", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.108587", Name: "BlueKeep", QoD: "97", Text: "vulnerable"}}},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := osp.New(f.Socket)
	id, err := c.StartScan(ctx, osp.Target{Hosts: []string{"10.30.5.20", "10.30.5.21"}, Ports: "T:22,3389", ExcludeHosts: []string{"10.30.5.1"}, AliveTest: osp.AliveTestConsiderAlive},
		map[string]string{"safe_checks": "1", "max_hosts": "4"}, osp.VTSelection{Families: []string{"Windows", "Service detection"}})
	if err != nil {
		t.Fatal(err)
	}
	start := f.Starts()[0]
	for _, want := range []string{"<hosts>10.30.5.20,10.30.5.21</hosts>", "<ports>T:22,3389</ports>", "<exclude_hosts>10.30.5.1</exclude_hosts>", "<alive_test>16</alive_test>", "<max_hosts>4</max_hosts><safe_checks>1</safe_checks>", `<vt_group filter="family=Windows"/>`} {
		if !strings.Contains(start, want) {
			t.Fatalf("start_scan missing %q:\n%s", want, start)
		}
	}
	s1, err := c.GetScan(ctx, id, true, 0)
	if err != nil || s1.Progress != 10 || s1.Status != osp.ScanRunning || len(s1.Results) != 0 {
		t.Fatalf("step1: %+v %v", s1, err)
	}
	s2, _ := c.GetScan(ctx, id, true, 0)
	if len(s2.Results) != 1 || s2.Results[0].SeverityScore() != 9.8 || s2.Results[0].QoDValue() != 97 {
		t.Fatalf("step2: %+v", s2)
	}
	if p, proto := s2.Results[0].PortNumber(); p != 3389 || proto != "tcp" {
		t.Fatal("port parse")
	}
	s3, _ := c.GetScan(ctx, id, true, 0)
	if !s3.Done() || s3.Status != osp.ScanFinished || s3.Progress != 100 {
		t.Fatalf("finished: %+v", s3)
	}
	vt, err := c.GetVT(ctx, "1.3.6.1.4.1.25623.1.0.108587")
	if err != nil || vt == nil || vt.Family != "Windows" || len(vt.CVEs) != 1 || vt.QoD != 97 || vt.CVSSv2Vector == "" || vt.Solution != "Patch" {
		t.Fatalf("vt: %+v %v", vt, err)
	}
	if vt, err := c.GetVT(ctx, "1.2.3"); err != nil || vt != nil {
		t.Fatalf("missing vt: %+v %v", vt, err)
	}
	if err := c.DeleteScan(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetScan(ctx, id, true, 0); err == nil {
		t.Fatal("deleted scan still found")
	}
	if fv, _ := c.FeedVersion(ctx); fv != "202609260530" {
		t.Fatal(fv)
	}
}

func TestStopScan(t *testing.T) {
	f := osptest.Start(t, &osptest.Fake{Script: []osptest.Step{{Progress: 5}}, Hang: true})
	ctx := context.Background()
	c := osp.New(f.Socket)
	id, _ := c.StartScan(ctx, osp.Target{Hosts: []string{"10.0.0.1"}, Ports: "T:80"}, nil, osp.VTSelection{Families: []string{"General"}})
	for i := 0; i < 3; i++ {
		s, _ := c.GetScan(ctx, id, true, 0)
		if s.Done() {
			t.Fatal("hung scan finished")
		}
	}
	if err := c.StopScan(ctx, id); err != nil {
		t.Fatal(err)
	}
	s, _ := c.GetScan(ctx, id, true, 0)
	if s.Status != osp.ScanStopped || len(f.Stops()) != 1 {
		t.Fatalf("after stop: %+v", s)
	}
}
