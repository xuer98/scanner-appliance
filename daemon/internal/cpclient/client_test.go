package cpclient

import "testing"

func TestProxyURL(t *testing.T) {
	for in, want := range map[string]string{
		"proxy:3128":                      "http://proxy:3128",
		"user:pw@proxy.vendor.local:3128": "http://user:pw@proxy.vendor.local:3128",
		"http://p:8080":                   "http://p:8080",
		"":                                "",
	} {
		u, err := ProxyURL(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != want {
			t.Fatalf("%q → %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"proxy", "socks5://p:1080", "::"} {
		if _, err := ProxyURL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
