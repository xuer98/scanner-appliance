package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// naabuLine is one JSON line of naabu output. Port is tolerant to both the
// flat form ("port":80,"protocol":"tcp") and the nested struct form some
// releases emit.
type naabuLine struct {
	Host     string          `json:"host"`
	IP       string          `json:"ip"`
	Port     json.RawMessage `json:"port"`
	Protocol string          `json:"protocol"`
}

func (l naabuLine) port() (int, string) {
	if len(l.Port) == 0 || string(l.Port) == "null" {
		return 0, l.Protocol
	}
	var n int
	if err := json.Unmarshal(l.Port, &n); err == nil {
		return n, strings.ToLower(l.Protocol)
	}
	var obj struct {
		Port     int    `json:"Port"`
		Protocol string `json:"Protocol"`
		LPort    int    `json:"port"`
		LProto   string `json:"protocol"`
	}
	if err := json.Unmarshal(l.Port, &obj); err == nil {
		p, proto := obj.Port, obj.Protocol
		if p == 0 {
			p, proto = obj.LPort, obj.LProto
		}
		if proto == "" {
			proto = l.Protocol
		}
		return p, strings.ToLower(proto)
	}
	return 0, l.Protocol
}

func (l naabuLine) ip() string {
	if l.IP != "" {
		return l.IP
	}
	if net.ParseIP(l.Host) != nil {
		return l.Host
	}
	return ""
}

// naabuRun holds the parsed output of one invocation.
type naabuRun struct {
	Hosts map[string]map[int]string // ip → port → proto ("" set of ports)
	Order []string                  // ips in first-seen order
}

func newNaabuRun() *naabuRun { return &naabuRun{Hosts: map[string]map[int]string{}} }

func (r *naabuRun) add(ip string, port int, proto string) {
	if ip == "" {
		return
	}
	if _, ok := r.Hosts[ip]; !ok {
		r.Hosts[ip] = map[int]string{}
		r.Order = append(r.Order, ip)
	}
	if port > 0 {
		if proto == "" {
			proto = "tcp"
		}
		r.Hosts[ip][port] = proto
	}
}

// parseNaabu reads naabu output. Port scans are run with -json (one object
// per open port); host discovery (-sn) is run in plain mode because naabu
// 2.3 emits empty records for -json/-csv there, so a bare IP per line is
// accepted as an alive host. Anything else (banners) is ignored.
func parseNaabu(out []byte) *naabuRun {
	r := newNaabuRun()
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			if ip := net.ParseIP(string(line)); ip != nil {
				r.add(ip.String(), 0, "")
			}
			continue
		}
		var l naabuLine
		if err := json.Unmarshal(line, &l); err != nil {
			continue
		}
		p, proto := l.port()
		r.add(l.ip(), p, proto)
	}
	return r
}

// naabuArgs builds the common argument list (output mode is added per phase).
func (e *Engine) naabuArgs(spec v1.JobSpec, site v1.SiteConfig, hosts []string) []string {
	args := []string{"-host", strings.Join(hosts, ","), "-silent", "-no-color", "-disable-update-check",
		"-rate", strconv.Itoa(spec.Rate.PPS), "-c", strconv.Itoa(clamp(spec.Rate.PerHostParallel*10, 10, 80)),
		"-retries", "1", "-timeout", "1000", "-warm-up-time", "1"}
	var excl []string
	excl = append(excl, spec.Excludes...)
	excl = append(excl, site.Excludes...)
	if len(excl) > 0 {
		args = append(args, "-exclude-hosts", strings.Join(excl, ","))
	}
	if iface := e.scanIface(spec); iface != "" {
		args = append(args, "-interface", iface)
	}
	if e.ScanType != "" {
		args = append(args, "-scan-type", e.ScanType)
	}
	return args
}

func (e *Engine) ifaceExists(name string) bool {
	if e.IfaceExists != nil {
		return e.IfaceExists(name)
	}
	_, err := net.InterfaceByName(name)
	return err == nil
}

// runNaabu executes naabu and parses its output. A non-zero exit with no
// output is an error; with output it is logged and the output used.
func (e *Engine) runNaabu(ctx context.Context, phase string, args []string) (*naabuRun, error) {
	if e.NaabuPath == "" {
		return nil, errors.New("naabu binary not configured")
	}
	if _, err := os.Stat(e.NaabuPath); err != nil {
		return nil, fmt.Errorf("naabu: %w", err)
	}
	cmd := exec.CommandContext(ctx, e.NaabuPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(), "HOME=/var/lib/appliance", "NO_COLOR=1")
	e.Log.Info("naabu start", "phase", phase, "args", strings.Join(args, " "))
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.Len() > 32<<20 {
		return nil, errors.New("naabu: output too large")
	}
	run := parseNaabu(stdout.Bytes())
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if len(run.Order) == 0 {
			return nil, fmt.Errorf("naabu %s failed: %v: %s", phase, err, msg)
		}
		e.Log.Warn("naabu exited non-zero but produced output", "phase", phase, "err", err, "stderr", msg)
	}
	e.Log.Info("naabu done", "phase", phase, "hosts", len(run.Order))
	return run, nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
