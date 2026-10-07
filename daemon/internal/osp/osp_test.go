package osp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

func TestHealth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := osptest.Start(t, &osptest.Fake{VTsVersion: "202609260530", VTCount: 45678})
	c := osp.New(f.Socket)
	c.RedisSocket = f.RedisSocket
	h := c.Health(ctx)
	if !h.OSPDUp || !h.VTCacheLoaded || h.VTCount != 45678 || h.OpenVASVersion != "OpenVAS 23.50.24" || h.OSPDVersion != "22.10.5" || h.Error != "" {
		t.Fatalf("%+v", h)
	}
	// Without the engine's redis the count is unknown; the rest still holds.
	c = osp.New(f.Socket)
	c.RedisSocket = filepath.Join(t.TempDir(), "missing.sock")
	if h := c.Health(ctx); !h.Ready() || h.VTCount != 0 || h.Error != "" {
		t.Fatalf("no redis: %+v", h)
	}
	h = osp.New(filepath.Join(t.TempDir(), "missing.sock")).Health(ctx)
	if h.OSPDUp || h.Error == "" {
		t.Fatalf("missing socket: %+v", h)
	}
}

// The number of tests is counted once per feed version and again when the
// feed changes, which is the only time it can.
func TestVTCountFollowsTheFeed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plugins := t.TempDir()
	write := func(version string, scripts int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(plugins, bundle.FeedInfoFile), []byte(`PLUGIN_SET = "`+version+`";`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < scripts; i++ {
			if err := os.WriteFile(filepath.Join(plugins, "t"+string(rune('a'+i))+".nasl"), []byte("#"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	f := osptest.Start(t, &osptest.Fake{PluginsDir: plugins})
	c := osp.New(f.Socket)
	c.RedisSocket = f.RedisSocket
	if h := c.Health(ctx); h.VTCacheLoaded || h.VTCount != 0 {
		t.Fatalf("no feed yet: %+v", h)
	}
	write("202610050609", 3)
	if h := c.Health(ctx); h.FeedVersion != "202610050609" || h.VTCount != 3 {
		t.Fatalf("first feed: %+v", h)
	}
	// More scripts on disk under the same version: the engine has not
	// loaded them, and the count is not taken again.
	write("202610050609", 5)
	if h := c.Health(ctx); h.VTCount != 3 {
		t.Fatalf("same version recounted: %+v", h)
	}
	write("202610060600", 5)
	if h := c.Health(ctx); h.FeedVersion != "202610060600" || h.VTCount != 5 {
		t.Fatalf("after the feed moved: %+v", h)
	}
}
