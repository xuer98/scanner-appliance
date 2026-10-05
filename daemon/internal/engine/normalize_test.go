package engine

import (
	"testing"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

// The results below are what ospd-openvas 22.10.5 with openvas 23.50.24 and
// the community feed sent for four lab hosts (nginx 1.16.1, Tomcat 9.0.30,
// Redis 5.0.7, Apache 2.4.49). Two things differ from the OSP documentation
// and are easy to get wrong: host details arrive as "Log Message" results
// on the pseudo port general/Host_Details, one detail each, and a detection
// that consolidates several methods reports on general/tcp and names the
// real port in its "Location:" line.

func logMsg(host, name, port, text string) osp.Result {
	return osp.Result{Host: host, Type: "Log Message", Name: name, Port: port, QoD: "80", Text: text}
}

func detailMsg(host, name, value string) osp.Result {
	return logMsg(host, "Host Details", "general/Host_Details",
		"<host><detail><name>"+name+"</name><value>"+value+"</value><source><type>nvt</type><name>1.3.6.1.4.1.25623.1.0.103997</name><description>Host Details</description></source></detail></host>")
}

const (
	nginxReport = "Detected Nginx\n\nVersion:       1.16.1\nLocation:      80/tcp\nCPE:           cpe:/a:nginx:nginx:1.16.1\n\nConcluded from version/product identification result:\nServer: nginx/1.16.1"
	httpdReport = "Detected Apache HTTP Server\n\nVersion:       2.4.49\nLocation:      80/tcp\nCPE:           cpe:/a:apache:http_server:2.4.49\n\nConcluded from version/product identification result:\nServer: Apache/2.4.49 (Unix)"
	// The quoted evidence after the header repeats "Version" and carries a URL.
	tomcatReport = "Detected Apache Tomcat\n\nVersion:       9.0.30\nLocation:      8080/tcp\nCPE:           cpe:/a:apache:tomcat:9.0.30\n\nConcluded from version/product identification result:\nApache Tomcat Version 9.0.30\n\nConcluded from version/product identification location:\nhttp://scanner-lab-tomcat-1.scannerlab:8080/RELEASE-NOTES.txt"
	redisReport  = "Detected Redis Server\n\nVersion:       5.0.7\nLocation:      /\nCPE:           cpe:/a:redis:redis:5.0.7\n\nConcluded from version/product identification result:\nredis_version:5.0.7\n\nExtra information:\nRedis Server is not protected with a password."
	osReport     = "Best matching OS:\n\nOS:           Linux Kernel\nCPE:          cpe:/o:linux:kernel\nFound by VT:  1.3.6.1.4.1.25623.1.0.102002 (Operating System (OS) Detection (ICMP))\nConcluded from ICMP based OS fingerprint"
)

func finalized(t *testing.T, ip string, naabu []int, results ...osp.Result) v1.Host {
	t.Helper()
	h := newHostAgg(ip)
	for _, p := range naabu {
		h.addPort(p, "tcp", "naabu")
	}
	for _, r := range results {
		h.absorb(r)
	}
	return h.finalize(nil)
}

func portOf(t *testing.T, h v1.Host, n int) v1.Port {
	t.Helper()
	for _, p := range h.Ports {
		if p.Port == n {
			return p
		}
	}
	t.Fatalf("%s: port %d missing from %+v", h.IP, n, h.Ports)
	return v1.Port{}
}

func TestRealEngineInventory(t *testing.T) {
	nginx := finalized(t, "172.18.0.4", []int{80},
		logMsg("172.18.0.4", "Services", "80/tcp", "A web server is running on this port"),
		logMsg("172.18.0.4", "HTTP Server type and version", "80/tcp", "The remote HTTP Server banner is:\n\nServer: nginx/1.16.1"),
		logMsg("172.18.0.4", "nginx Detection Consolidation", "general/tcp", nginxReport),
		logMsg("172.18.0.4", "OS Detection Consolidation and Reporting", "general/tcp", osReport),
		logMsg("172.18.0.4", "CPE Inventory", "general/CPE-T", "172.18.0.4|cpe:/a:f5:nginx:1.16.1\n172.18.0.4|cpe:/a:nginx:nginx:1.16.1\n172.18.0.4|cpe:/o:linux:kernel"),
		detailMsg("172.18.0.4", "OS", "cpe:/o:linux:kernel"),
		detailMsg("172.18.0.4", "OS", "Linux Kernel"),
		detailMsg("172.18.0.4", "App", "cpe:/a:nginx:nginx:1.16.1"),
		detailMsg("172.18.0.4", "cpe:/a:nginx:nginx:1.16.1", "80/tcp"),
		detailMsg("172.18.0.4", "tcp_ports", "80"),
		detailMsg("172.18.0.4", "hostname", "scanner-lab-nginx-1.scannerlab"),
		detailMsg("172.18.0.4", "best_os_cpe", "cpe:/o:linux:kernel"),
		detailMsg("172.18.0.4", "best_os_txt", "Linux Kernel"),
	)
	if p := portOf(t, nginx, 80); p.Service != "http" || p.Product != "Nginx" || p.Version != "1.16.1" || p.CPE != "cpe:/a:nginx:nginx:1.16.1" || p.Source != "openvas:product_detection" {
		t.Fatalf("nginx port: %+v", p)
	}
	if len(nginx.Ports) != 1 {
		t.Fatalf("pseudo ports leaked into the inventory: %+v", nginx.Ports)
	}
	if g := nginx.OSGuess; g == nil || g.Family != "linux" || g.Name != "Linux Kernel" || g.CPE != "cpe:/o:linux:kernel" || g.Confidence != 0.7 || g.Source != "openvas:os_detection" {
		t.Fatalf("nginx os: %+v", g)
	}
	if nginx.Hostname != "scanner-lab-nginx-1.scannerlab" {
		t.Fatalf("hostname: %q", nginx.Hostname)
	}

	tomcat := finalized(t, "172.18.0.5", []int{8009, 8080},
		logMsg("172.18.0.5", "Services", "8080/tcp", "A web server is running on this port"),
		logMsg("172.18.0.5", "Apache JServ Protocol (AJP) v1.3 Detection (TCP)", "8009/tcp", "A service supporting the Apache JServ Protocol (AJP) v1.3 seems to be running on this port."),
		logMsg("172.18.0.5", "Apache Tomcat Detection Consolidation", "general/tcp", tomcatReport),
		detailMsg("172.18.0.5", "Services", "8009,tcp,ajp13"),
		detailMsg("172.18.0.5", "detected_at", "8009/tcp"),
	)
	if p := portOf(t, tomcat, 8080); p.Service != "http" || p.Product != "Apache Tomcat" || p.Version != "9.0.30" || p.CPE != "cpe:/a:apache:tomcat:9.0.30" {
		t.Fatalf("tomcat port: %+v", p)
	}
	if p := portOf(t, tomcat, 8009); p.Service != "ajp13" || p.Product != "" || p.CPE != "" || p.Source != "naabu" {
		t.Fatalf("ajp port: %+v", p)
	}

	// A detection that reports on the port itself gives a path as location.
	redis := finalized(t, "172.18.0.6", []int{6379},
		logMsg("172.18.0.6", "Service Detection with 'GET' Request", "6379/tcp", "A Redis server seems to be running on this port."),
		logMsg("172.18.0.6", "Redis Server Detection (TCP)", "6379/tcp", redisReport),
		detailMsg("172.18.0.6", "Services", "6379,tcp,redis,A Redis server seems to be running on this port."),
	)
	if p := portOf(t, redis, 6379); p.Service != "redis" || p.Product != "Redis Server" || p.Version != "5.0.7" || p.CPE != "cpe:/a:redis:redis:5.0.7" {
		t.Fatalf("redis port: %+v", p)
	}

	httpd := finalized(t, "172.18.0.7", []int{80},
		logMsg("172.18.0.7", "Services", "80/tcp", "A web server is running on this port"),
		logMsg("172.18.0.7", "Apache HTTP Server Detection Consolidation", "general/tcp", httpdReport),
	)
	if p := portOf(t, httpd, 80); p.Product != "Apache HTTP Server" || p.Version != "2.4.49" || p.CPE != "cpe:/a:apache:http_server:2.4.49" {
		t.Fatalf("httpd port: %+v", p)
	}
}

func TestDetectionBlocks(t *testing.T) {
	// One consolidated report covers every install of the product.
	two := "Detected Nginx\n\nVersion:       1.16.1\nLocation:      80/tcp\nCPE:           cpe:/a:nginx:nginx:1.16.1\n\nConcluded from version/product identification result:\nServer: nginx/1.16.1\n\n" +
		"Detected Nginx\n\nVersion:       unknown\nLocation:      8443/tcp\nCPEs:          cpe:/a:nginx:nginx\n               cpe:/a:f5:nginx"
	d := detections(two)
	if len(d) != 2 || d[0].port != 80 || d[0].proto != "tcp" || d[0].version != "1.16.1" || d[1].port != 8443 || d[1].version != "" || d[1].cpe != "cpe:/a:nginx:nginx" || d[1].product != "Nginx" {
		t.Fatalf("blocks: %+v", d)
	}
	h := finalized(t, "10.0.0.1", []int{80}, logMsg("10.0.0.1", "nginx Detection Consolidation", "general/tcp", two))
	if p := portOf(t, h, 8443); p.Product != "Nginx" || p.Version != "" || p.CPE != "cpe:/a:nginx:nginx" || p.Source != "openvas:product_detection" {
		t.Fatalf("install on a port naabu did not report: %+v", p)
	}
	if p := portOf(t, h, 80); p.Version != "1.16.1" {
		t.Fatalf("first install: %+v", p)
	}

	// Only the header lines of a block count; quoted banners may repeat them.
	banner := "Detected Example Server\n\nVersion:       2.0\nLocation:      8080/tcp\nCPE:           cpe:/a:example:server:2.0\n\nConcluded from version/product identification result:\nVersion: 1.1\nLocation: 9999/tcp\nCPE: cpe:/a:other:thing:9"
	if d := detections(banner); len(d) != 1 || d[0].version != "2.0" || d[0].port != 8080 || d[0].cpe != "cpe:/a:example:server:2.0" {
		t.Fatalf("banner lines moved the header fields: %+v", d)
	}

	// Carriage returns from a quoted banner do not end up in the values.
	if d := detections("Detected Example Server\r\n\r\nVersion:       2.0\r\nLocation:      8080/tcp\r\nCPE:           cpe:/a:example:server:2.0\r\n"); len(d) != 1 || d[0].product != "Example Server" || d[0].version != "2.0" || d[0].port != 8080 || d[0].cpe != "cpe:/a:example:server:2.0" {
		t.Fatalf("crlf report: %+v", d)
	}

	// Without a port in the block there is nothing to attach it to, an OS
	// CPE is not a product, and text that is no report yields no block.
	for name, text := range map[string]string{
		"path location": "Detected Example App\n\nVersion:       1.0\nLocation:      /app\nCPE:           cpe:/a:example:app:1.0",
		"bad port":      "Detected Example App\n\nVersion:       1.0\nLocation:      70000/tcp\nCPE:           cpe:/a:example:app:1.0",
		"os report":     osReport,
	} {
		h := finalized(t, "10.0.0.2", nil, logMsg("10.0.0.2", name, "general/tcp", text))
		if len(h.Ports) != 0 {
			t.Fatalf("%s: ports %+v", name, h.Ports)
		}
	}
	if d := detections("Detected Example OS\n\nVersion:       1\nLocation:      22/tcp\nCPE:           cpe:/o:example:os:1"); len(d) != 1 || d[0].cpe != "" || d[0].port != 22 {
		t.Fatalf("os cpe taken as a product cpe: %+v", d)
	}

	// The first product reported for a port keeps it, whichever way it came.
	h = finalized(t, "10.0.0.3", []int{80},
		logMsg("10.0.0.3", "Example Detection (HTTP)", "80/tcp", "Detected Example Server\n\nVersion:       2.0\nLocation:      /\nCPE:           cpe:/a:example:server:2.0"),
		logMsg("10.0.0.3", "nginx Detection Consolidation", "general/tcp", nginxReport))
	if p := portOf(t, h, 80); p.Product != "Example Server" || p.CPE != "cpe:/a:example:server:2.0" || p.Version != "2.0" {
		t.Fatalf("second detection replaced the first: %+v", p)
	}
}

func TestHostDetailForms(t *testing.T) {
	// The candidate CPE may arrive before the candidate name, and the
	// engine's pick comes last and wins.
	h := finalized(t, "10.0.0.4", nil,
		detailMsg("10.0.0.4", "OS", "cpe:/o:canonical:ubuntu_linux:22.04"),
		detailMsg("10.0.0.4", "OS", "Linux Kernel"),
		detailMsg("10.0.0.4", "best_os_cpe", "cpe:/o:canonical:ubuntu_linux:22.04"),
		detailMsg("10.0.0.4", "best_os_txt", "Ubuntu 22.04"),
		detailMsg("10.0.0.4", "MAC", "00:50:56:AB:CD:EF"),
	)
	if g := h.OSGuess; g == nil || g.Name != "Ubuntu 22.04" || g.CPE != "cpe:/o:canonical:ubuntu_linux:22.04" || g.Family != "linux" {
		t.Fatalf("os: %+v", g)
	}
	if h.MAC != "00:50:56:ab:cd:ef" {
		t.Fatalf("mac: %q", h.MAC)
	}
	// Only candidates, no pick: the name is used, never the CPE as a name.
	h = finalized(t, "10.0.0.5", nil, detailMsg("10.0.0.5", "OS", "cpe:/o:linux:kernel"), detailMsg("10.0.0.5", "OS", "Linux Kernel"))
	if g := h.OSGuess; g == nil || g.Name != "Linux Kernel" || g.CPE != "" || g.Confidence != 0.5 {
		t.Fatalf("os from candidates: %+v", g)
	}
	// The OSP "Host Detail" result type carries the same document.
	h = finalized(t, "10.0.0.6", nil, osp.Result{Host: "10.0.0.6", Type: "Host Detail", Port: "general/tcp", Name: "OS Detection",
		Text: "<host><detail><name>best_os_cpe</name><value>cpe:/o:microsoft:windows_server_2008:r2</value></detail><detail><name>best_os_txt</name><value>Microsoft Windows Server 2008 R2</value></detail></host>"})
	if g := h.OSGuess; g == nil || g.Family != "windows" || g.Confidence != 0.7 {
		t.Fatalf("typed host detail: %+v", g)
	}

	// Services details label ports the log texts left bare, and nothing else.
	h = finalized(t, "10.0.0.7", []int{80, 8009, 9000},
		logMsg("10.0.0.7", "Services", "80/tcp", "A web server is running on this port"),
		detailMsg("10.0.0.7", "Services", "80,tcp,www"),
		detailMsg("10.0.0.7", "Services", "8009,tcp,ajp13"),
		detailMsg("10.0.0.7", "Services", "8009,tcp,other"),
		detailMsg("10.0.0.7", "Services", "9000,tcp,unknown"),
		detailMsg("10.0.0.7", "Services", "5353,udp,mdns"),
		detailMsg("10.0.0.7", "Services", "garbage"),
		detailMsg("10.0.0.7", "Services", "0,tcp,zero"),
	)
	if portOf(t, h, 80).Service != "http" || portOf(t, h, 8009).Service != "ajp13" || portOf(t, h, 9000).Service != "" || len(h.Ports) != 3 {
		t.Fatalf("services: %+v", h.Ports)
	}
	h = finalized(t, "10.0.0.8", []int{8080}, detailMsg("10.0.0.8", "Services", "8080,tcp,www"))
	if portOf(t, h, 8080).Service != "http" {
		t.Fatalf("www not mapped: %+v", h.Ports)
	}
}
