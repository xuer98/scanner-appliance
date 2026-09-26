package spool

import (
	"os"
	"testing"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/seal"
)

func TestSpool(t *testing.T) {
	key, _ := seal.GenerateKey()
	s := &Spool{Dir: t.TempDir() + "/spool"}
	if _, err := s.Put(v1.ResultBatch{JobID: "job_a", Seq: 1}); err != ErrNoKey {
		t.Fatalf("no key: %v", err)
	}
	s.Pub = key.PublicKey()
	c1, err := s.Put(v1.ResultBatch{JobID: "job_a", Seq: 1, Hosts: []v1.Host{{IP: "10.0.0.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := s.Put(v1.ResultBatch{JobID: "job_a", Seq: 2, Final: true})
	c0, _ := s.Put(v1.ResultBatch{JobID: "job_0", Seq: 1, Final: true})
	if err := s.SetTerminal("job_a", v1.JobStatusRequest{Status: v1.JobDone}); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Pending()
	if len(p) != 3 || p[0].JobID != "job_0" || p[1].Seq != 1 || !p[2].Final || p[1].SHA256 != c1.SHA256 || p[2].Size != c2.Size {
		t.Fatalf("pending: %+v", p)
	}
	// Appliance cannot read its own spool; the control plane can.
	body, _ := s.Read(c1)
	var got v1.ResultBatch
	if err := seal.OpenJSON(key, body, seal.AAD("job_a", 1), &got); err != nil || got.Hosts[0].IP != "10.0.0.1" {
		t.Fatalf("open: %v", err)
	}
	if err := seal.OpenJSON(key, body, seal.AAD("job_a", 2), &got); err == nil {
		t.Fatal("chunk replayable under another seq")
	}
	_ = s.Remove(c0)
	if _, err := os.Stat(s.Dir + "/job_0"); !os.IsNotExist(err) {
		t.Fatal("empty job dir not pruned")
	}
	_ = s.Remove(c1)
	_ = s.Remove(c2)
	if s.HasChunks("job_a") {
		t.Fatal("chunks remain")
	}
	if st, ok := s.Terminal("job_a"); !ok || st.Status != v1.JobDone {
		t.Fatal("terminal lost")
	}
	if s.Count() != 0 || len(s.Jobs()) != 1 {
		t.Fatalf("count=%d jobs=%v", s.Count(), s.Jobs())
	}
	_ = s.ClearTerminal("job_a")
	if len(s.Jobs()) != 0 {
		t.Fatal("job dir not pruned after terminal cleared")
	}
}
