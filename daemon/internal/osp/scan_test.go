package osp_test

import (
	"context"
	"io"
	"net"
	"os"
	"reflect"
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

func TestGetVTsStreamsTheFullList(t *testing.T) {
	f := osptest.Start(t, &osptest.Fake{VTs: map[string]osptest.VT{
		"1.1": {Name: "BlueKeep", Family: "Windows", QoD: 97, QoDType: "remote_active", CVEs: []string{"CVE-2019-0708"}, CVSSv2: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Solution: "Patch"},
		"1.2": {Name: "Services", Family: "Service detection", QoD: 80},
		"1.3": {Name: "nginx < 1.21 & friends", Family: "Web Servers", QoD: 30, CVSSv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSSBase: "9.8"},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := osp.New(f.Socket)
	got, err := c.GetVTs(ctx, []string{"1.3", "9.9", "1.1", "1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["9.9"] != nil || got["1.2"] != nil {
		t.Fatalf("want exactly the two known OIDs asked for, got %v", got)
	}
	// One stream, and each VT reads the same as a single-VT query.
	if single, bulk := f.VTCalls(); single != 0 || bulk != 1 {
		t.Fatalf("calls: single=%d bulk=%d", single, bulk)
	}
	for _, oid := range []string{"1.1", "1.3"} {
		one, err := c.GetVT(ctx, oid)
		if err != nil || !reflect.DeepEqual(one, got[oid]) {
			t.Fatalf("%s: bulk %+v != single %+v (%v)", oid, got[oid], one, err)
		}
	}
	if got["1.3"].Name != "nginx < 1.21 & friends" || got["1.3"].CVSSBase != 9.8 {
		t.Fatalf("escaping or fields: %+v", got["1.3"])
	}
	if none, err := c.GetVTs(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("no OIDs: %v %v", none, err)
	}
	if _, bulk := f.VTCalls(); bulk != 1 {
		t.Fatal("an empty request must not open a stream")
	}
}

// replyOnce serves one canned response per connection on a fresh socket.
func replyOnce(t *testing.T, resp string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "osp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := dir + "/ospd.sock"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = io.WriteString(c, resp)
			c.Close()
		}
	}()
	return sock
}

func TestGetVTsFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const head = `<get_vts_response status="200" status_text="OK"><vts vts_version="1" total="">`
	const vt1 = `<vt id="1.1"><name>A</name><custom><family>Windows</family></custom></vt>`
	// A stream cut inside the list is an error, and keeps what was complete.
	got, err := osp.New(replyOnce(t, head+vt1+`<vt id="1.2"><name>B`)).GetVTs(ctx, []string{"1.1", "1.2", "1.3"})
	if err == nil || len(got) != 1 || got["1.1"] == nil || got["1.1"].Family != "Windows" {
		t.Fatalf("truncated inside a wanted VT: %v %v", got, err)
	}
	// Also when the cut falls between VTs: absence then proves nothing.
	if got, err := osp.New(replyOnce(t, head+vt1)).GetVTs(ctx, []string{"1.1", "1.3"}); err == nil || len(got) != 1 {
		t.Fatalf("truncated between VTs: %v %v", got, err)
	}
	if _, err := osp.New(replyOnce(t, "")).GetVTs(ctx, []string{"1.1"}); err == nil {
		t.Fatal("empty response accepted")
	}
	_, err = osp.New(replyOnce(t, `<get_vts_response status="400" status_text="Invalid filter element"/>`)).GetVTs(ctx, []string{"1.1"})
	if err == nil || !strings.Contains(err.Error(), "400 Invalid filter element") {
		t.Fatalf("status: %v", err)
	}
	// The complete stream is not an error even when nothing matched.
	if got, err := osp.New(replyOnce(t, head+vt1+`</vts></get_vts_response>`)).GetVTs(ctx, []string{"7.7"}); err != nil || len(got) != 0 {
		t.Fatalf("complete stream: %v %v", got, err)
	}
}
