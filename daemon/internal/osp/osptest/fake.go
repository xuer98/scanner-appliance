// Package osptest is a scripted fake ospd-openvas speaking enough OSP for
// the daemon tests: get_version, get_vts (single-VT metadata and the full
// list), start_scan, get_scans with pop_results, stop_scan and delete_scan.
// Next to it listens a fake of the engine's redis (redis.go), which is
// where the number of loaded tests is read.
package osptest

import (
	"encoding/xml"
	"fmt"
	"github.com/tprm/scanner-appliance/internal/bundle"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

// Step is what one get_scans call returns for a running scan.
type Step struct {
	Progress int
	Results  []osp.Result
}

// VT is the metadata returned for one OID.
type VT struct {
	Name, Family, Solution, QoDType string
	QoD                             int
	CVEs                            []string
	CVSSv2, CVSSv3                  string
	CVSSBase                        string
}

// Fake is one listener.
type Fake struct {
	Socket string
	// RedisSocket is the fake of the engine's redis; it reports VTCount
	// tests while a feed is loaded.
	RedisSocket string
	VTsVersion  string
	VTCount     int
	VTs         map[string]VT
	// PluginsDir makes the fake behave like ospd-openvas after a feed
	// update: the reported VT version is PLUGIN_SET from
	// <PluginsDir>/plugin_feed_info.inc (empty = cache not loaded) and the
	// VT count is the number of .nasl files below it. Like the real daemon
	// it only loads a feed that is newer than the one it has.
	PluginsDir string
	// Script drives every scan started against this fake. After the last
	// step the scan reports finished (or keeps running when Hang is set,
	// until stop_scan).
	Script []Step
	Hang   bool

	verMu  sync.Mutex
	loaded string // feed version "in the cache" (PluginsDir mode)

	mu        sync.Mutex
	scans     map[string]*scanState
	StartXML  []string
	StopIDs   []string
	DeleteIDs []string
	nextID    int
	vtSingle  int
	vtBulk    int
}

type scanState struct {
	step    int
	stopped bool
}

// Start listens on a fresh socket under t.TempDir().
func Start(t *testing.T, f *Fake) *Fake {
	t.Helper()
	if f == nil {
		f = &Fake{}
	}
	if f.VTsVersion == "" {
		f.VTsVersion = "202609260530"
	}
	if f.VTCount == 0 {
		f.VTCount = 98765
	}
	f.scans = map[string]*scanState{}
	// A short path: Unix socket names are capped at ~104 bytes on macOS and
	// t.TempDir() embeds the (long) test name.
	dir, err := os.MkdirTemp("", "osp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.Socket = dir + "/ospd.sock"
	l, err := net.Listen("unix", f.Socket)
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
			go f.serve(c)
		}
	}()
	f.RedisSocket = dir + "/redis.sock"
	rl, err := net.Listen("unix", f.RedisSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })
	go func() {
		for {
			c, err := rl.Accept()
			if err != nil {
				return
			}
			go f.serveRedis(c)
		}
	}()
	return f
}

var (
	scanIDRe = regexp.MustCompile(`scan_id="([^"]+)"`)
	vtIDRe   = regexp.MustCompile(`vt_id="([^"]+)"`)
)

func (f *Fake) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 1<<20)
	n, _ := c.Read(buf)
	req := string(buf[:n])
	var resp string
	switch {
	case strings.HasPrefix(req, "<get_version"):
		resp = `<get_version_response status="200" status_text="OK"><protocol><name>OSP</name><version>22.4</version></protocol><daemon><name>OSPd OpenVAS</name><version>22.10.5</version></daemon><scanner><name>openvas</name><version>OpenVAS 23.50.24</version></scanner><vts><version>` + f.version() + `</version></vts></get_version_response>`
	case strings.HasPrefix(req, "<get_vts"):
		resp = f.getVTs(req)
	case strings.HasPrefix(req, "<start_scan"):
		resp = f.startScan(req)
	case strings.HasPrefix(req, "<get_scans"):
		resp = f.getScans(req)
	case strings.HasPrefix(req, "<stop_scan"):
		id := attr(scanIDRe, req)
		f.mu.Lock()
		f.StopIDs = append(f.StopIDs, id)
		if s, ok := f.scans[id]; ok {
			s.stopped = true
		}
		f.mu.Unlock()
		resp = `<stop_scan_response status="200" status_text="OK"/>`
	case strings.HasPrefix(req, "<delete_scan"):
		id := attr(scanIDRe, req)
		f.mu.Lock()
		f.DeleteIDs = append(f.DeleteIDs, id)
		delete(f.scans, id)
		f.mu.Unlock()
		resp = `<delete_scan_response status="200" status_text="OK"/>`
	default:
		resp = `<osp_response status="400" status_text="bad command"/>`
	}
	_, _ = io.WriteString(c, resp)
}

func attr(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func (f *Fake) getVTs(req string) string {
	if oid := attr(vtIDRe, req); oid != "" {
		f.mu.Lock()
		f.vtSingle++
		f.mu.Unlock()
		vt, ok := f.VTs[oid]
		if !ok {
			return `<get_vts_response status="404" status_text="Not found"/>`
		}
		return fmt.Sprintf(`<get_vts_response status="200" status_text="OK"><vts vts_version="%s" total="">%s</vts></get_vts_response>`, f.version(), vtXML(oid, vt))
	}
	// As measured on ospd-openvas 22.10.5: the total attribute is always
	// empty, because the tests live in redis, and the only filter it takes
	// compares modification times.
	if strings.Contains(req, `version_only="1"`) {
		return fmt.Sprintf(`<get_vts_response status="200" status_text="OK"><vts vts_version="%s" total=""></vts></get_vts_response>`, f.version())
	}
	if strings.Contains(req, "filter=") && !strings.Contains(req, "modification_time") {
		return `<get_vts_response status="400" status_text="Invalid filter element" />`
	}
	// No vt_id and no filter: the whole feed, as ospd-openvas streams it.
	f.mu.Lock()
	f.vtBulk++
	f.mu.Unlock()
	oids := make([]string, 0, len(f.VTs))
	for oid := range f.VTs {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	var sb strings.Builder
	fmt.Fprintf(&sb, `<get_vts_response status="200" status_text="OK"><vts vts_version="%s" total="">`, f.version())
	for _, oid := range oids {
		sb.WriteString(vtXML(oid, f.VTs[oid]))
	}
	sb.WriteString(`</vts></get_vts_response>`)
	return sb.String()
}

func vtXML(oid string, vt VT) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `<vt id="%s"><name>%s</name><refs>`, oid, x(vt.Name))
	for _, c := range vt.CVEs {
		fmt.Fprintf(&sb, `<ref type="cve" id="%s"/>`, c)
	}
	fmt.Fprintf(&sb, `<ref type="url" id="https://example.invalid/adv"/></refs><summary>summary</summary><solution type="VendorFix">%s</solution><detection qod_type="%s" qod="%d"/><severities>`, x(vt.Solution), vt.QoDType, vt.QoD)
	if vt.CVSSv2 != "" {
		fmt.Fprintf(&sb, `<severity type="cvss_base_v2"><origin>NVD</origin><date>2019-05-14</date><value>%s</value></severity>`, vt.CVSSv2)
	}
	if vt.CVSSv3 != "" {
		fmt.Fprintf(&sb, `<severity type="cvss_base_v3"><value>%s</value></severity>`, vt.CVSSv3)
	}
	fmt.Fprintf(&sb, `</severities><custom><category>3</category><family>%s</family><filename>x.nasl</filename><cvss_base>%s</cvss_base></custom></vt>`, x(vt.Family), vt.CVSSBase)
	return sb.String()
}

func (f *Fake) startScan(req string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("fake-scan-%d", f.nextID)
	f.scans[id] = &scanState{}
	f.StartXML = append(f.StartXML, req)
	return `<start_scan_response status="200" status_text="OK"><id>` + id + `</id></start_scan_response>`
}

func (f *Fake) getScans(req string) string {
	id := attr(scanIDRe, req)
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.scans[id]
	if !ok {
		return `<get_scans_response status="404" status_text="Failed to find scan"/>`
	}
	status := "running"
	progress := 0
	var results []osp.Result
	switch {
	case s.stopped:
		status = "stopped"
		if s.step > 0 && s.step <= len(f.Script) {
			progress = f.Script[s.step-1].Progress
		}
	case s.step < len(f.Script):
		st := f.Script[s.step]
		s.step++
		progress, results = st.Progress, st.Results
	case f.Hang:
		if len(f.Script) > 0 {
			progress = f.Script[len(f.Script)-1].Progress
		}
	default:
		status, progress = "finished", 100
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `<get_scans_response status="200" status_text="OK"><scan id="%s" target="t" start_time="1" end_time="" progress="%d" status="%s"><results>`, id, progress, status)
	for _, r := range results {
		fmt.Fprintf(&sb, `<result host="%s" hostname="%s" name="%s" type="%s" severity="%s" port="%s" test_id="%s" qod="%s" uri="%s">%s</result>`,
			x(r.Host), x(r.Hostname), x(r.Name), x(r.Type), x(r.Severity), x(r.Port), x(r.TestID), x(r.QoD), x(r.URI), x(r.Text))
	}
	fmt.Fprintf(&sb, `</results><progress><overall>%d</overall><count_alive>1</count_alive><count_dead>0</count_dead><count_excluded>0</count_excluded><count_total>1</count_total></progress></scan></get_scans_response>`, progress)
	return sb.String()
}

func x(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

// SetHang toggles Hang under the lock (safe while scans run).
func (f *Fake) SetHang(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Hang = v
}

// VTCalls returns how many single-VT and full-list get_vts commands the
// fake has answered.
func (f *Fake) VTCalls() (single, bulk int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vtSingle, f.vtBulk
}

// Stops returns the stop_scan calls seen so far.
func (f *Fake) Stops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.StopIDs...)
}

// Starts returns the raw start_scan commands seen so far.
func (f *Fake) Starts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.StartXML...)
}

// version reports the loaded feed version (see PluginsDir). ospd-openvas
// reloads when PLUGIN_SET on disk, read as a number, is greater than the
// version it has loaded (feed_is_outdated in ospd_openvas/daemon.py). An
// older feed on disk is never loaded: the daemon keeps reporting the newer
// version, which is what the lab showed when a bundle with an older feed
// was applied.
func (f *Fake) version() string {
	if f.PluginsDir == "" {
		return f.VTsVersion
	}
	disk := ""
	if fh, err := os.Open(filepath.Join(f.PluginsDir, "plugin_feed_info.inc")); err == nil {
		disk = bundle.ParseFeedVersion(fh)
		_ = fh.Close()
	}
	f.verMu.Lock()
	defer f.verMu.Unlock()
	have, errHave := strconv.ParseUint(f.loaded, 10, 64)
	next, errNext := strconv.ParseUint(disk, 10, 64)
	if f.loaded == "" || (disk != "" && (errHave != nil || errNext != nil || next > have)) {
		f.loaded = disk
	}
	return f.loaded
}

func (f *Fake) vtCount() int {
	if f.PluginsDir == "" {
		return f.VTCount
	}
	n := 0
	_ = filepath.WalkDir(f.PluginsDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".nasl") {
			n++
		}
		return nil
	})
	return n
}
