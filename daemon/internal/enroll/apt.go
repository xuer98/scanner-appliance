package enroll

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/tprm/scanner-appliance/daemon/internal/pki"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// apt security mirror behind the control-plane FQDN (PLAN §14, §17.2).
//
// apt's https method runs as the _apt user and authenticates with a client
// certificate given as files, so a copy of the appliance certificate and key
// is kept readable by that user under /etc/appliance/apt/. The sources
// entry and the per-host TLS/proxy settings are rewritten at every
// enrollment and renewal. Best effort and Linux-image only: nothing happens
// on a host without /etc/apt/apt.conf.d or /etc/appliance.
var (
	AptConfDir    = "/etc/apt/apt.conf.d"
	AptSourcesDir = "/etc/apt/sources.list.d"
	AptCredDir    = "/etc/appliance/apt"
)

func writeAptConfig(st *state.Store, cpURL, proxy string) {
	if runtime.GOOS != "linux" || cpURL == "" {
		return
	}
	for _, d := range []string{AptConfDir, AptSourcesDir, filepath.Dir(AptCredDir)} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			return
		}
	}
	u, err := url.Parse(cpURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := u.Host
	gid := -1
	if g, err := user.Lookup("_apt"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if err := os.MkdirAll(AptCredDir, 0o750); err != nil {
		return
	}
	_ = os.Chown(AptCredDir, 0, gid)
	copyFor := func(name, src string, mode os.FileMode) bool {
		b, err := os.ReadFile(src)
		if err != nil {
			return false
		}
		dst := filepath.Join(AptCredDir, name)
		if err := os.WriteFile(dst+".tmp", b, mode); err != nil {
			return false
		}
		_ = os.Chown(dst+".tmp", 0, gid)
		return os.Rename(dst+".tmp", dst) == nil
	}
	if !copyFor("cert.pem", filepath.Join(st.Dir, "cert.pem"), 0o640) || !copyFor("key.pem", filepath.Join(st.Dir, "key.pem"), 0o640) {
		return
	}
	if roots := pki.RootsPEM(); len(roots) > 0 {
		_ = os.WriteFile(filepath.Join(AptCredDir, "ca.pem"), roots, 0o644)
	}
	var conf strings.Builder
	fmt.Fprintf(&conf, "// managed by applianced: mTLS to the control-plane apt mirror\n")
	fmt.Fprintf(&conf, "Acquire::https::%s::SslCert \"%s/cert.pem\";\n", host, AptCredDir)
	fmt.Fprintf(&conf, "Acquire::https::%s::SslKey \"%s/key.pem\";\n", host, AptCredDir)
	if _, err := os.Stat(filepath.Join(AptCredDir, "ca.pem")); err == nil {
		fmt.Fprintf(&conf, "Acquire::https::%s::CaInfo \"%s/ca.pem\";\n", host, AptCredDir)
	}
	if proxy != "" {
		p := proxy
		if !strings.Contains(p, "://") {
			p = "http://" + p
		}
		fmt.Fprintf(&conf, "Acquire::http::Proxy \"%s\";\nAcquire::https::Proxy \"%s\";\n", p, p)
	}
	_ = os.WriteFile(filepath.Join(AptConfDir, "50appliance"), []byte(conf.String()), 0o640)
	_ = os.Chown(filepath.Join(AptConfDir, "50appliance"), 0, gid)
	src := fmt.Sprintf("# managed by applianced: security pocket mirrored behind the control plane\nTypes: deb\nURIs: https://%s/apt/debian-security\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n", host)
	_ = os.WriteFile(filepath.Join(AptSourcesDir, "appliance-security.sources"), []byte(src), 0o644)
}
