// Package spool is the on-disk queue of result chunks awaiting upload
// (PLAN §9). Every chunk is sealed to the control plane's spool key before
// it is written, so the appliance can never read its own spool; the file
// is uploaded as-is and deleted on acknowledgement. A terminal job status
// is kept beside the chunks and reported once they are all flushed.
package spool

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/seal"
)

// ErrNoKey means the appliance has no spool public key yet (enroll or
// renew against a control plane that hands one out).
var ErrNoKey = errors.New("spool: no control-plane spool key; results cannot be stored")

// Spool is rooted at Dir (typically /var/lib/appliance/spool).
type Spool struct {
	Dir string
	Pub *ecdh.PublicKey
}

// Chunk is one pending sealed file.
type Chunk struct {
	JobID  string
	Seq    int
	Final  bool
	Path   string
	Size   int64
	SHA256 string
}

func jobDir(dir, jobID string) string { return filepath.Join(dir, safe(jobID)) }

func safe(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	if sb.Len() == 0 {
		return "unknown"
	}
	return sb.String()
}

// Put seals and stores one batch.
func (s *Spool) Put(b v1.ResultBatch) (Chunk, error) {
	if s.Pub == nil {
		return Chunk{}, ErrNoKey
	}
	if b.JobID == "" || b.Seq <= 0 {
		return Chunk{}, errors.New("spool: batch needs job_id and seq")
	}
	body, err := seal.SealJSON(s.Pub, b, seal.AAD(b.JobID, b.Seq))
	if err != nil {
		return Chunk{}, err
	}
	dir := jobDir(s.Dir, b.JobID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Chunk{}, err
	}
	name := fmt.Sprintf("%06d.sealed", b.Seq)
	if b.Final {
		name = fmt.Sprintf("%06d.final.sealed", b.Seq)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path+".tmp", body, 0o600); err != nil {
		return Chunk{}, err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return Chunk{}, err
	}
	sum := sha256.Sum256(body)
	return Chunk{JobID: b.JobID, Seq: b.Seq, Final: b.Final, Path: path, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}, nil
}

// Pending lists chunks ordered by job id then sequence.
func (s *Spool) Pending() ([]Chunk, error) {
	jobs, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for _, j := range jobs {
		if !j.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.Dir, j.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			name := f.Name()
			if !strings.HasSuffix(name, ".sealed") {
				continue
			}
			seqStr := strings.SplitN(name, ".", 2)[0]
			seq, err := strconv.Atoi(seqStr)
			if err != nil {
				continue
			}
			path := filepath.Join(s.Dir, j.Name(), name)
			body, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(body)
			out = append(out, Chunk{JobID: j.Name(), Seq: seq, Final: strings.Contains(name, ".final."), Path: path, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
		}
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].JobID != out[k].JobID {
			return out[i].JobID < out[k].JobID
		}
		return out[i].Seq < out[k].Seq
	})
	return out, nil
}

// Read returns the sealed bytes of a chunk.
func (s *Spool) Read(c Chunk) ([]byte, error) { return os.ReadFile(c.Path) }

// Remove deletes an uploaded chunk.
func (s *Spool) Remove(c Chunk) error {
	if err := os.Remove(c.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.prune(c.JobID)
	return nil
}

// Count is the number of pending chunks (heartbeat pending_results).
func (s *Spool) Count() int {
	p, _ := s.Pending()
	return len(p)
}

// SetTerminal records the status to report once the job's chunks are flushed.
func (s *Spool) SetTerminal(jobID string, st v1.JobStatusRequest) error {
	dir := jobDir(s.Dir, jobID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	return os.WriteFile(filepath.Join(dir, "terminal.json"), b, 0o600)
}

// Terminal returns the recorded terminal status, if any.
func (s *Spool) Terminal(jobID string) (*v1.JobStatusRequest, bool) {
	b, err := os.ReadFile(filepath.Join(jobDir(s.Dir, jobID), "terminal.json"))
	if err != nil {
		return nil, false
	}
	var st v1.JobStatusRequest
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	return &st, true
}

// ClearTerminal removes the terminal marker after it was reported.
func (s *Spool) ClearTerminal(jobID string) error {
	err := os.Remove(filepath.Join(jobDir(s.Dir, jobID), "terminal.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.prune(jobID)
	return nil
}

// Jobs lists job ids with anything pending (chunks or a terminal marker).
func (s *Spool) Jobs() []string {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// HasChunks reports whether a job still has unsent chunks.
func (s *Spool) HasChunks(jobID string) bool {
	files, err := os.ReadDir(jobDir(s.Dir, jobID))
	if err != nil {
		return false
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sealed") {
			return true
		}
	}
	return false
}

func (s *Spool) prune(jobID string) {
	dir := jobDir(s.Dir, jobID)
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".tmp") {
			return
		}
	}
	_ = os.RemoveAll(dir)
}

// Wipe removes the whole spool (part of the appliance wipe).
func (s *Spool) Wipe() error { return os.RemoveAll(s.Dir) }
