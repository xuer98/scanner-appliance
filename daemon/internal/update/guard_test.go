package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tprm/scanner-appliance/internal/bundle"
)

// imageGuard returns the start guard the VM image installs
// (appliance-update-guard in packer/scripts/harden.sh), pointed at the
// pending record of state directory dir.
func imageGuard(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the guard is a POSIX shell script of the Linux image")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "packer", "scripts", "harden.sh"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(src), "cat >/usr/local/sbin/appliance-update-guard <<'EOF'\n")
	script, _, closed := strings.Cut(rest, "\nEOF\n")
	if !found || !closed {
		t.Fatal("appliance-update-guard not found in packer/scripts/harden.sh")
	}
	// The script and the daemon have to agree on where the record is.
	inImage := (&Manager{StateDir: "/var/lib/appliance"}).pendingPath()
	if strings.Count(script, "P="+inImage+"\n") != 1 {
		t.Fatalf("the guard does not read %s, where the daemon writes its pending record", inImage)
	}
	script = strings.Replace(script, "P="+inImage+"\n", "P='"+strings.ReplaceAll((&Manager{StateDir: dir}).pendingPath(), "'", `'\''`)+"'\n", 1)
	p := filepath.Join(t.TempDir(), "appliance-update-guard")
	if err := os.WriteFile(p, []byte(script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The image's start guard and the daemon share the pending record: the
// daemon writes it when it swaps its binary, systemd runs the guard before
// every start, and the guard puts the previous binary back when the new one
// has been started three times without confirming itself. Neither side had
// ever read what the other wrote.
func TestStartGuardRollsBackACrashLoop(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	m := newManager(t, cp, key, "", nil)
	// A quote in the path: the record is sourced by a shell.
	bin := filepath.Join(t.TempDir(), "it's bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "applianced")
	const oldBin, newBin = "#!/bin/sh\necho 1.2.0\n", "#!/bin/sh\necho 1.3.0\n"
	m.ExePath = exe
	sig, _ := bundle.Sign([]byte(newBin), key.key)
	cp.mu.Lock()
	cp.releases["applianced-linux-amd64/1.3.0"] = []byte(newBin)
	cp.mu.Unlock()
	p := Payload{URL: "/v1/releases/applianced-linux-amd64/1.3.0", SHA256: bundle.SHA256Hex([]byte(newBin)), Sig: sig, Version: "1.3.0"}
	guard := imageGuard(t, m.StateDir)
	start := func() {
		t.Helper()
		if out, err := exec.Command("/bin/sh", guard).CombinedOutput(); err != nil {
			t.Fatalf("guard: %v: %s", err, out)
		}
	}
	stage := func() {
		t.Helper()
		if err := os.WriteFile(exe, []byte(oldBin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplyDaemon(t.Context(), p); err != ErrRestartRequired {
			t.Fatalf("apply: %v", err)
		}
	}
	nu, old := *m, *m
	nu.Version, old.Version = "1.3.0", "1.2.0"

	// Nothing staged: the guard has nothing to do on an ordinary start.
	start()
	if _, err := os.Stat(m.pendingPath()); !os.IsNotExist(err) {
		t.Fatalf("the guard made a pending record out of nothing: %v", err)
	}

	// The new binary starts and confirms itself with a heartbeat. Later
	// starts are ordinary ones again.
	stage()
	start()
	pend, err := m.LoadPending()
	if err != nil || pend == nil || pend.Starts != 1 || pend.RolledBack || pend.Version != "1.3.0" || pend.PrevVersion != "1.2.0" || pend.Exe != exe || pend.Prev != exe+".prev" {
		t.Fatalf("record after the first start: %v %+v", err, pend)
	}
	if await, report := nu.Startup(); !await || report != "" {
		t.Fatalf("new binary startup: %v %q", await, report)
	}
	if err := nu.Confirm(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		start()
	}
	if read(t, exe) != newBin {
		t.Fatal("a confirmed update was rolled back by later restarts")
	}

	// The new binary crashes on every start: the third start gets the
	// previous binary back.
	stage()
	start()
	start()
	if pend, _ = m.LoadPending(); pend == nil || pend.Starts != 2 || pend.RolledBack || read(t, exe) != newBin {
		t.Fatalf("after two starts: %+v, binary %q", pend, read(t, exe))
	}
	start()
	pend, err = m.LoadPending()
	if err != nil || pend == nil || !pend.RolledBack || pend.Starts != 3 || pend.Reason != "rolled back after 3 failed starts" || pend.Version != "1.3.0" || pend.Exe != exe {
		t.Fatalf("record after the third start: %v %+v", err, pend)
	}
	if read(t, exe) != oldBin || read(t, exe+".prev") != "<missing>" {
		t.Fatalf("the previous binary is not back in place: %q", read(t, exe))
	}
	if fi, err := os.Stat(exe); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the restored binary is not executable: %v", err)
	}
	// The previous binary, running again, reports what happened and the
	// record is gone, so the next start is an ordinary one.
	if await, report := old.Startup(); await || report != "daemon 1.3.0: rolled back after 3 failed starts (running 1.2.0)" {
		t.Fatalf("startup after the rollback: %v %q", await, report)
	}
	start()
	if _, err := os.Stat(m.pendingPath()); !os.IsNotExist(err) || read(t, exe) != oldBin {
		t.Fatalf("after the report: record %v, binary %q", err, read(t, exe))
	}
}
