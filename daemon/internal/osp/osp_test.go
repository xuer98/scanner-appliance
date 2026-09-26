package osp

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOSPD answers one command per connection like ospd does.
func fakeOSPD(t *testing.T, vtsVersion string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ospd.sock")
	l, err := net.Listen("unix", sock)
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
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				switch {
				case strings.HasPrefix(req, "<get_version"):
					io.WriteString(c, `<get_version_response status="200" status_text="OK"><protocol><name>OSP</name><version>22.4</version></protocol><daemon><name>OSPd OpenVAS</name><version>22.7.1</version></daemon><scanner><name>openvas</name><version>OpenVAS 23.0.1</version></scanner><vts><version>`+vtsVersion+`</version></vts></get_version_response>`)
				case strings.HasPrefix(req, "<get_vts"):
					io.WriteString(c, `<get_vts_response status="200" status_text="OK"><vts vts_version="`+vtsVersion+`" total="98765" sent="0"/></get_vts_response>`)
				default:
					io.WriteString(c, `<osp_response status="400" status_text="bad"/>`)
				}
			}()
		}
	}()
	return sock
}

func TestHealth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := New(fakeOSPD(t, "202609260530")).Health(ctx)
	if !h.OSPDUp || !h.VTCacheLoaded || h.VTCount != 98765 || h.OpenVASVersion != "OpenVAS 23.0.1" || h.OSPDVersion != "22.7.1" || h.Error != "" {
		t.Fatalf("%+v", h)
	}
	h = New(fakeOSPD(t, "")).Health(ctx)
	if !h.OSPDUp || h.VTCacheLoaded || h.Error != "" {
		t.Fatalf("cache not loaded case: %+v", h)
	}
	h = New(filepath.Join(t.TempDir(), "missing.sock")).Health(ctx)
	if h.OSPDUp || h.Error == "" {
		t.Fatalf("missing socket: %+v", h)
	}
}
