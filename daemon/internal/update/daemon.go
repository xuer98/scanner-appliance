package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tprm/scanner-appliance/internal/bundle"
)

// Daemon self-update (PLAN §14): download → verify sha256 + signature →
// sanity-run `<new> version` → atomic swap next to the running binary →
// exit so the supervisor (systemd Restart=always) starts the new one. The
// previous binary is kept as <exe>.prev and a pending record is written;
// the new daemon must confirm itself with a heartbeat within
// ConfirmWindow or it puts the previous binary back. The image's
// ExecStartPre guard (packer/scripts/harden.sh) does the same when the new
// binary cannot even start.

// ConfirmWindow is how long a new binary has to heartbeat successfully.
const ConfirmWindow = 10 * time.Minute

// Pending describes a staged self-update; it is stored as KEY='value'
// lines so the shell guard can source it.
type Pending struct {
	Version     string
	PrevVersion string
	Prev        string
	Exe         string
	StartedAt   int64
	Starts      int
	RolledBack  bool
	Reason      string
}

func (m *Manager) pendingPath() string { return filepath.Join(m.StateDir, "update", "pending.env") }

// LoadPending returns nil when no update is staged.
func (m *Manager) LoadPending() (*Pending, error) {
	f, err := os.Open(m.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p := &Pending{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
		v = strings.ReplaceAll(v, `'\''`, "'")
		switch k {
		case "VERSION":
			p.Version = v
		case "PREV_VERSION":
			p.PrevVersion = v
		case "PREV":
			p.Prev = v
		case "EXE":
			p.Exe = v
		case "STARTED":
			p.StartedAt, _ = strconv.ParseInt(v, 10, 64)
		case "STARTS":
			p.Starts, _ = strconv.Atoi(v)
		case "ROLLED_BACK":
			p.RolledBack = v == "1"
		case "REASON":
			p.Reason = v
		}
	}
	return p, sc.Err()
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (m *Manager) savePending(p *Pending) error {
	if err := os.MkdirAll(filepath.Dir(m.pendingPath()), 0o700); err != nil {
		return err
	}
	rb := "0"
	if p.RolledBack {
		rb = "1"
	}
	body := fmt.Sprintf("VERSION=%s\nPREV_VERSION=%s\nPREV=%s\nEXE=%s\nSTARTED=%d\nSTARTS=%d\nROLLED_BACK=%s\nREASON=%s\n",
		shellQuote(p.Version), shellQuote(p.PrevVersion), shellQuote(p.Prev), shellQuote(p.Exe), p.StartedAt, p.Starts, rb, shellQuote(p.Reason))
	tmp := m.pendingPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.pendingPath())
}

// ClearPending forgets a staged update (after confirmation or a report).
func (m *Manager) ClearPending() error {
	err := os.Remove(m.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) exePath() (string, error) {
	if m.ExePath != "" {
		return m.ExePath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

func daemonErr(version string, err error) error { return fmt.Errorf("daemon %s: %w", version, err) }

// ApplyDaemon stages a new binary and returns ErrRestartRequired.
func (m *Manager) ApplyDaemon(ctx context.Context, p Payload) error {
	m.init()
	if m.Container {
		return ErrNotApplicable
	}
	if p.Version == m.Version {
		m.Log.Info("daemon already at requested version", "version", p.Version)
		return nil
	}
	if m.Fetch == nil {
		return daemonErr(p.Version, errors.New("no fetcher (not enrolled?)"))
	}
	exe, err := m.exePath()
	if err != nil {
		return daemonErr(p.Version, err)
	}
	dir := filepath.Join(m.StateDir, "update")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return daemonErr(p.Version, err)
	}
	tmp := filepath.Join(dir, "applianced-"+p.Version+".part")
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return daemonErr(p.Version, err)
	}
	h := sha256.New()
	_, _, err = m.Fetch.Download(ctx, p.URL, io.MultiWriter(fh, h), maxArtifact)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return daemonErr(p.Version, fmt.Errorf("fetch: %w", err))
	}
	defer os.Remove(tmp)
	digest := h.Sum(nil)
	if got := hex.EncodeToString(digest); got != p.SHA256 {
		return daemonErr(p.Version, fmt.Errorf("artifact digest %s does not match the directive", got[:12]))
	}
	if err := bundle.VerifyDigest(digest, p.Sig, m.Keys); err != nil {
		return daemonErr(p.Version, err)
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	got, err := m.VersionOf(vctx, tmp)
	cancel()
	if err != nil {
		return daemonErr(p.Version, fmt.Errorf("new binary does not run: %w", err))
	}
	if got != p.Version {
		return daemonErr(p.Version, fmt.Errorf("new binary reports version %q", got))
	}
	newPath := exe + ".new"
	if err := copyFile(tmp, newPath, 0o755); err != nil {
		return daemonErr(p.Version, err)
	}
	_ = os.Chmod(newPath, 0o755)
	prev := exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Rename(exe, prev); err != nil {
		_ = os.Remove(newPath)
		return daemonErr(p.Version, fmt.Errorf("stash current binary: %w", err))
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(prev, exe)
		return daemonErr(p.Version, fmt.Errorf("install new binary: %w", err))
	}
	pend := &Pending{Version: p.Version, PrevVersion: m.Version, Prev: prev, Exe: exe, StartedAt: m.Now().Unix()}
	if err := m.savePending(pend); err != nil {
		// Without the record nothing would ever roll back: undo.
		_ = os.Rename(exe, newPath)
		_ = os.Rename(prev, exe)
		_ = os.Remove(newPath)
		return daemonErr(p.Version, fmt.Errorf("record pending update: %w", err))
	}
	m.Log.Warn("daemon binary replaced; restarting to run the new version", "from", m.Version, "to", p.Version, "exe", exe)
	return ErrRestartRequired
}

func versionOf(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Startup inspects a staged update when the daemon starts. It reports
// whether this process is the new binary awaiting confirmation, and a
// message to surface as update_error when a rollback happened.
func (m *Manager) Startup() (awaitConfirm bool, report string) {
	m.init()
	pend, err := m.LoadPending()
	if err != nil {
		m.Log.Warn("pending update record unreadable", "err", err)
		return false, ""
	}
	if pend == nil {
		return false, ""
	}
	switch {
	case pend.RolledBack:
		_ = m.ClearPending()
		why := pend.Reason
		if why == "" {
			why = fmt.Sprintf("rolled back after %d failed starts", pend.Starts)
		}
		return false, fmt.Sprintf("daemon %s: %s (running %s)", pend.Version, why, m.Version)
	case pend.Version != m.Version:
		_ = m.ClearPending()
		return false, fmt.Sprintf("daemon %s: not running after update (running %s)", pend.Version, m.Version)
	}
	m.Log.Info("running a freshly updated daemon; awaiting confirmation", "version", m.Version, "previous", pend.PrevVersion)
	return true, ""
}

// Confirm marks the running version as good (first successful heartbeat).
func (m *Manager) Confirm() error {
	pend, err := m.LoadPending()
	if err != nil || pend == nil {
		return err
	}
	if pend.Version != m.Version {
		return nil
	}
	m.Log.Info("daemon update confirmed", "version", m.Version)
	return m.ClearPending()
}

// Rollback puts the previous binary back (no heartbeat within
// ConfirmWindow) and returns ErrRestartRequired.
func (m *Manager) Rollback(reason string) error {
	pend, err := m.LoadPending()
	if err != nil {
		return err
	}
	if pend == nil {
		return errors.New("no pending update to roll back")
	}
	if _, err := os.Stat(pend.Prev); err != nil {
		return fmt.Errorf("previous binary missing: %w", err)
	}
	if err := os.Rename(pend.Prev, pend.Exe); err != nil {
		return err
	}
	pend.RolledBack = true
	pend.Reason = reason
	if err := m.savePending(pend); err != nil {
		return err
	}
	m.Log.Error("daemon update rolled back", "version", pend.Version, "reason", reason)
	return ErrRestartRequired
}
