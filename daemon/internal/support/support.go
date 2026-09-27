// Package support builds and uploads a support bundle (PLAN §6).
// The bundle never contains key.pem or the pending enrollment code, and it
// only ever goes to the control plane over mTLS — never to removable media.
package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/cpclient"
	"github.com/tprm/scanner-appliance/daemon/internal/netcfg"
	"github.com/tprm/scanner-appliance/daemon/internal/platform"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

const maxCmdOutput = 4 << 20

// Build writes a tar.gz to w.
func Build(ctx context.Context, w io.Writer, st *state.Store, version string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, b []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: "support/" + name, Mode: 0o600, Size: int64(len(b)), ModTime: now, Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	addCmd := func(name string, args ...string) {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, args[0], args[1:]...).CombinedOutput()
		if len(out) > maxCmdOutput {
			out = out[len(out)-maxCmdOutput:]
		}
		if err != nil {
			out = append(out, []byte("\n# error: "+err.Error()+"\n")...)
		}
		add(name, out)
	}
	addFile := func(name, path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			b = []byte("# " + err.Error() + "\n")
		}
		add(name, b)
	}

	meta := map[string]any{"version": version, "generated_at": now.UTC(), "hostname": hostname(), "ifaces": netcfg.Interfaces()}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	add("meta.json", mb)

	// state.json with secrets redacted
	if s, err := st.Load(); err == nil {
		s.PendingCode = ""
		if s.Proxy != "" {
			s.Proxy = redactProxy(s.Proxy)
		}
		b, _ := json.MarshalIndent(s, "", "  ")
		add("state.json", b)
	}
	addFile("cert.pem", filepath.Join(st.Dir, "cert.pem"))
	addFile("status.json", filepath.Join(st.RunDir, "status.json"))
	if runtime.GOOS == "windows" {
		// A Windows host runs the daemon only (no engine, no systemd).
		addCmd("systeminfo.txt", "systeminfo")
		addCmd("ipconfig.txt", "ipconfig", "/all")
		addCmd("route.txt", "route", "print")
		addCmd("tasklist.txt", "tasklist")
		addCmd("eventlog-application.txt", "wevtutil", "qe", "Application", "/c:500", "/rd:true", "/f:text")
	} else {
		addFile("os-release", "/etc/os-release")
		addFile("machine-id", "/etc/machine-id")
		addCmd("journal-applianced.txt", "journalctl", "-u", "applianced", "--no-pager", "-n", "5000")
		addCmd("journal-networkd.txt", "journalctl", "-u", "systemd-networkd", "--no-pager", "-n", "500")
		addCmd("dmesg.txt", "dmesg", "--ctime")
		addCmd("ip-addr.txt", "ip", "addr")
		addCmd("ip-route.txt", "ip", "route", "show", "table", "all")
		addCmd("resolvectl.txt", "resolvectl", "status")
		addCmd("nft-ruleset.txt", "nft", "list", "ruleset")
		addCmd("df.txt", "df", "-h")
		addCmd("uptime.txt", "uptime")
		addCmd("systemctl-failed.txt", "systemctl", "--failed", "--no-pager")
		if entries, err := os.ReadDir(netcfg.NetworkdDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					addFile("network/"+e.Name(), filepath.Join(netcfg.NetworkdDir, e.Name()))
				}
			}
		}
	}
	if entries, err := os.ReadDir(platform.ConfDir()); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				addFile("etc-appliance/"+e.Name(), filepath.Join(platform.ConfDir(), e.Name()))
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Upload builds and sends the bundle over mTLS.
func Upload(ctx context.Context, st *state.Store, roots *x509.CertPool, version string) (*v1.SupportBundleAck, error) {
	s, err := st.Load()
	if err != nil {
		return nil, err
	}
	if s.ApplianceID == "" {
		return nil, fmt.Errorf("not enrolled; support bundles upload over mTLS only")
	}
	cert, err := st.Certificate()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := Build(ctx, &buf, st, version); err != nil {
		return nil, err
	}
	cl, err := cpclient.New(cpclient.Options{Roots: roots, ClientCert: cert, Proxy: s.Proxy, Timeout: 5 * time.Minute})
	if err != nil {
		return nil, err
	}
	return cl.Support(ctx, s.CPURL, s.ApplianceID, &buf)
}

func redactProxy(p string) string {
	if i := strings.LastIndex(p, "@"); i >= 0 {
		return "***@" + p[i+1:]
	}
	return p
}

func hostname() string { h, _ := os.Hostname(); return h }
