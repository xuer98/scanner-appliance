// Package cpclient is the HTTPS client applianced uses to talk to cp-api.
//
// Roots are pinned (daemon/internal/pki); the vendor proxy is honored via
// CONNECT; mTLS is end-to-end through the tunnel (PLAN §7.4).
package cpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Error is a non-2xx response.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("http %d (%s): %s", e.Status, e.Code, e.Msg)
	}
	return fmt.Sprintf("http %d: %s", e.Status, e.Msg)
}

// IsAuthError reports a definitive rejection (revoked, unknown cert, bad code) as opposed to a transport problem.
func IsAuthError(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == 401 || e.Status == 403)
}

// Client wraps an http.Client with the appliance's TLS identity.
type Client struct {
	http      *http.Client
	UserAgent string
}

// Options for New.
type Options struct {
	Roots      *x509.CertPool
	ClientCert *tls.Certificate // nil for the enroll call
	Proxy      string           // "" | host:port | user:pass@host:port | http://...
	Timeout    time.Duration
}

// ProxyURL normalizes the console/seed proxy syntax into a URL.
func ProxyURL(p string) (*url.URL, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, nil
	}
	if !strings.Contains(p, "://") {
		p = "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("proxy must be host:port or user:pass@host:port")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy scheme must be http or https")
	}
	if u.Port() == "" {
		return nil, fmt.Errorf("proxy needs a port")
	}
	return u, nil
}

func New(o Options) (*Client, error) {
	tcfg := &tls.Config{RootCAs: o.Roots, MinVersion: tls.VersionTLS12}
	if o.ClientCert != nil {
		tcfg.Certificates = []tls.Certificate{*o.ClientCert}
	}
	tr := &http.Transport{
		TLSClientConfig:       tcfg,
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	if o.Proxy != "" {
		pu, err := ProxyURL(o.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: o.Timeout}, UserAgent: "applianced"}, nil
}

func (c *Client) do(ctx context.Context, method, rawURL string, body io.Reader, contentType string, out any) error {
	_, err := c.doHeaders(ctx, method, rawURL, body, contentType, nil, out)
	return err
}

// doHeaders is do with extra request headers; it returns the status code
// so callers can tell 204 from 200.
func (c *Client) doHeaders(ctx context.Context, method, rawURL string, body io.Reader, contentType string, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var er v1.ErrorResponse
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(b, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(b))
		}
		return resp.StatusCode, &Error{Status: resp.StatusCode, Code: er.Code, Msg: er.Error}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return resp.StatusCode, nil
}

func (c *Client) postJSON(ctx context.Context, rawURL string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, rawURL, bytes.NewReader(b), "application/json", out)
}

// Enroll calls POST {enrollURL}/v1/enroll (no client cert).
func (c *Client) Enroll(ctx context.Context, enrollURL string, req v1.EnrollRequest) (*v1.EnrollResponse, error) {
	var out v1.EnrollResponse
	if err := c.postJSON(ctx, join(enrollURL, "/v1/enroll"), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat posts the heartbeat and returns directives.
func (c *Client) Heartbeat(ctx context.Context, cpURL, id string, hb v1.Heartbeat) (*v1.HeartbeatResponse, error) {
	var out v1.HeartbeatResponse
	if err := c.postJSON(ctx, join(cpURL, "/v1/appliances/"+id+"/heartbeat"), hb, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Renew requests a fresh certificate over mTLS.
func (c *Client) Renew(ctx context.Context, cpURL string, req v1.RenewRequest) (*v1.EnrollResponse, error) {
	var out v1.EnrollResponse
	if err := c.postJSON(ctx, join(cpURL, "/v1/renew"), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Support uploads a support bundle.
func (c *Client) Support(ctx context.Context, cpURL, id string, r io.Reader) (*v1.SupportBundleAck, error) {
	var out v1.SupportBundleAck
	if err := c.do(ctx, http.MethodPost, join(cpURL, "/v1/appliances/"+id+"/support"), r, "application/gzip", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Wipe tells the control plane the appliance is destroying itself.
func (c *Client) Wipe(ctx context.Context, cpURL, id, reason string) error {
	return c.postJSON(ctx, join(cpURL, "/v1/appliances/"+id+"/wipe"), v1.WipeRequest{Reason: reason}, nil)
}

// Jobs polls for the next dispatched job; (nil, nil) when there is none.
func (c *Client) Jobs(ctx context.Context, cpURL, id string) (*v1.JobsResponse, error) {
	var out v1.JobsResponse
	status, err := c.doHeaders(ctx, http.MethodGet, join(cpURL, "/v1/appliances/"+id+"/jobs"), nil, "", nil, &out)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &out, nil
}

// JobStatus reports running/rejected/failed/done for a job.
func (c *Client) JobStatus(ctx context.Context, cpURL, jobID string, st v1.JobStatusRequest) error {
	return c.postJSON(ctx, join(cpURL, "/v1/jobs/"+jobID+"/status"), st, nil)
}

// UploadResults sends one sealed result chunk.
func (c *Client) UploadResults(ctx context.Context, cpURL, jobID string, seq int, final bool, sha256Hex string, body []byte) (*v1.ResultAck, error) {
	var out v1.ResultAck
	h := map[string]string{v1.HeaderResultSeq: strconv.Itoa(seq), v1.HeaderResultSHA256: sha256Hex, v1.HeaderResultFinal: strconv.FormatBool(final)}
	if _, err := c.doHeaders(ctx, http.MethodPost, join(cpURL, "/v1/jobs/"+jobID+"/results"), bytes.NewReader(body), v1.ContentTypeSealed, h, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IsPermanent reports a 4xx other than 429: retrying the same request
// cannot succeed.
func IsPermanent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests
}

// Ping checks reachability of a base URL (used by the console's "test connection").
func (c *Client) Ping(ctx context.Context, baseURL string) error {
	return c.do(ctx, http.MethodGet, join(baseURL, "/healthz"), nil, "", nil)
}

func join(base, path string) string { return strings.TrimRight(base, "/") + path }
