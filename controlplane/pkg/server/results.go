package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/seal"
)

const (
	maxResultBody    = 16 << 20
	maxHostsPerChunk = 4096
	maxFindingsHost  = 5000
	maxPortsHost     = 65536
	maxEvidenceLen   = 8192
	maxStringLen     = 512
)

// ---- POST /v1/jobs/{job}/results ----
//
// Chunked, resumable upload (PLAN §17.2): each chunk is a sealed envelope
// whose plaintext is a ResultBatch; (job, seq) is idempotent. Results are
// data: the plaintext is parsed with a strict schema and size limits and
// nothing is executed (PLAN §16).
func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	apl := applianceFrom(r)
	job, err := s.cfg.Store.GetJob(r.Context(), r.PathValue("job"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such job", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	if job.ApplianceID != apl.ID {
		writeErr(w, http.StatusForbidden, "job belongs to another appliance", "job_owner")
		return
	}
	switch job.Status {
	case v1.JobRejected, v1.JobCancelled:
		writeErr(w, http.StatusConflict, "job is "+job.Status, "terminal")
		return
	}
	seq, err := strconv.Atoi(r.Header.Get(v1.HeaderResultSeq))
	if err != nil || seq <= 0 || seq > 1_000_000 {
		writeErr(w, http.StatusBadRequest, "bad "+v1.HeaderResultSeq, "bad_seq")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxResultBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "chunk too large or unreadable", "too_large")
		return
	}
	sum := sha256.Sum256(body)
	shaHex := hex.EncodeToString(sum[:])
	if want := strings.ToLower(r.Header.Get(v1.HeaderResultSHA256)); want != "" && want != shaHex {
		writeErr(w, http.StatusBadRequest, "sha256 mismatch", "bad_sha256")
		return
	}
	var batch v1.ResultBatch
	if err := openBatch(s.cfg.SpoolKey, body, job.ID, seq, &batch); err != nil {
		writeErr(w, http.StatusBadRequest, "cannot open chunk: "+err.Error(), "bad_chunk")
		return
	}
	if batch.JobID != job.ID || batch.Seq != seq {
		writeErr(w, http.StatusBadRequest, "chunk job/seq do not match the request", "bad_chunk")
		return
	}
	if err := validateBatch(&batch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_chunk")
		return
	}
	now := s.cfg.Now()
	key := fmt.Sprintf("results/%s/%06d.json", job.ID, seq)
	plain, _ := json.Marshal(batch)
	// Idempotency is keyed on the decrypted content: every seal of the same
	// chunk differs on the wire (fresh ephemeral key and nonce).
	plainSum := sha256.Sum256(plain)
	if _, err := s.cfg.Objects.Put(r.Context(), key, bytes.NewReader(plain)); err != nil {
		writeErr(w, http.StatusInternalServerError, "object store error", "objects")
		return
	}
	dup, err := s.cfg.Store.RecordResultBatch(r.Context(), store.ResultBatchRec{JobID: job.ID, Seq: seq, ReceivedAt: now, ObjectKey: key, SHA256: hex.EncodeToString(plainSum[:]), Final: batch.Final, Hosts: len(batch.Hosts)})
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "seq already received with different content", "seq_conflict")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	if dup {
		writeJSON(w, http.StatusOK, v1.ResultAck{Seq: seq, Duplicate: true, Hosts: len(batch.Hosts), Complete: job.Status == v1.JobDone})
		return
	}
	sum2, err := s.cfg.Store.IngestHosts(r.Context(), job.SiteID, job.ID, batch.Hosts, batch.FeedVersion, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ingest error", "store")
		return
	}
	if nvts := nvtsFrom(batch); len(nvts) > 0 {
		if err := s.cfg.Store.UpsertNVTs(r.Context(), nvts); err != nil {
			s.log.Warn("nvt mirror update failed", "err", err)
		}
	}
	complete := false
	if batch.Final {
		job.Stats = batch.Stats
		if !job.Terminal() {
			job.Status = v1.JobDone
			job.ProgressPct = 100
			job.FinishedAt = &now
		}
		if err := s.cfg.Store.UpdateJob(r.Context(), job); err != nil {
			writeErr(w, http.StatusInternalServerError, "store error", "store")
			return
		}
		complete = true
	} else if job.Status == v1.JobDispatched {
		job.Status = v1.JobRunning
		job.StartedAt = &now
		_ = s.cfg.Store.UpdateJob(r.Context(), job)
	}
	s.log.Info("result chunk ingested", "job", job.ID, "seq", seq, "hosts", sum2.Hosts, "created", sum2.Created, "merged", sum2.Merged, "findings", sum2.Findings, "final", batch.Final)
	writeJSON(w, http.StatusOK, v1.ResultAck{Seq: seq, Hosts: sum2.Hosts, Complete: complete})
}

func openBatch(key interface{ Public() interface{} }, body []byte, jobID string, seq int, out *v1.ResultBatch) error {
	k, ok := key.(sealKey)
	if !ok || k == nil {
		return errors.New("no spool key configured")
	}
	var env seal.Envelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return fmt.Errorf("bad envelope: %w", err)
	}
	pt, err := seal.Open(k.priv(), &env, seal.AAD(jobID, seq))
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(pt))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("bad result batch: %w", err)
	}
	return nil
}

func validateBatch(b *v1.ResultBatch) error {
	if len(b.Hosts) > maxHostsPerChunk {
		return fmt.Errorf("too many hosts in chunk (%d)", len(b.Hosts))
	}
	for i := range b.Hosts {
		h := &b.Hosts[i]
		if len(h.IP) > 64 || len(h.MAC) > 32 {
			return errors.New("bad host identity")
		}
		h.Hostname = clip(h.Hostname, maxStringLen)
		if len(h.Ports) > maxPortsHost {
			return errors.New("too many ports")
		}
		if len(h.Findings) > maxFindingsHost {
			return errors.New("too many findings")
		}
		if len(h.Notes) > 64 {
			h.Notes = h.Notes[:64]
		}
		for j := range h.Ports {
			p := &h.Ports[j]
			if p.Port < 0 || p.Port > 65535 {
				return errors.New("bad port")
			}
			p.Service, p.Product, p.Version, p.CPE, p.Source = clip(p.Service, 64), clip(p.Product, maxStringLen), clip(p.Version, 128), clip(p.CPE, maxStringLen), clip(p.Source, 64)
		}
		for j := range h.Findings {
			f := &h.Findings[j]
			f.Name, f.Family, f.Solution = clip(f.Name, maxStringLen), clip(f.Family, 128), clip(f.Solution, maxEvidenceLen)
			f.Evidence = clip(f.Evidence, maxEvidenceLen)
			if len(f.CVE) > 256 {
				f.CVE = f.CVE[:256]
			}
			if f.QoD < 0 || f.QoD > 100 || f.CVSS < 0 || f.CVSS > 10 {
				return errors.New("bad finding score")
			}
			if f.Severity == "" {
				f.Severity = v1.SeverityFor(f.CVSS)
			}
			if f.CVE == nil {
				f.CVE = []string{}
			}
		}
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// nvtsFrom mirrors VT metadata carried in findings (PLAN §17.1 nvt table).
func nvtsFrom(b v1.ResultBatch) []store.NVT {
	seen := map[string]bool{}
	var out []store.NVT
	for _, h := range b.Hosts {
		for _, f := range h.Findings {
			if f.NVTOID == "" || seen[f.NVTOID] {
				continue
			}
			seen[f.NVTOID] = true
			out = append(out, store.NVT{OID: f.NVTOID, Name: f.Name, Family: f.Family, CVSS: f.CVSS, CVEs: f.CVE, QoD: f.QoD, Solution: f.Solution, FeedVersion: b.FeedVersion})
		}
	}
	return out
}
