package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// S3Objects is an ObjectStore on any S3-compatible service (AWS S3,
// MinIO, Ceph RGW), signed with Signature Version 4 in the standard
// library so the control plane keeps its two dependencies (Phase 6).
// Objects are bounded (a result chunk is at most 16 MiB, a support bundle
// 64 MiB), so Put buffers the body to sign its hash.
type S3Objects struct {
	Endpoint  string // https://s3.eu-central-1.amazonaws.com or http://minio:9000
	Region    string
	Bucket    string
	Prefix    string // optional key prefix
	AccessKey string
	SecretKey string
	PathStyle bool // http://endpoint/bucket/key (MinIO) instead of bucket.endpoint
	Client    *http.Client
	Now       func() time.Time
}

const s3MaxObject = 256 << 20

var errS3Config = errors.New("s3: endpoint, region, bucket, access key and secret key are required")

func (s S3Objects) check() error {
	if s.Endpoint == "" || s.Region == "" || s.Bucket == "" || s.AccessKey == "" || s.SecretKey == "" {
		return errS3Config
	}
	return nil
}

func (s S3Objects) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (s S3Objects) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// uriEncode is the AWS canonical encoding: unreserved characters stay,
// everything else is percent-encoded, '/' kept when it separates segments.
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// target returns the request URL and the canonical URI for a key.
func (s S3Objects) target(key string) (*url.URL, string, error) {
	base, err := url.Parse(strings.TrimRight(s.Endpoint, "/"))
	if err != nil || base.Host == "" {
		return nil, "", fmt.Errorf("s3: bad endpoint %q", s.Endpoint)
	}
	full := key
	if s.Prefix != "" {
		full = strings.Trim(s.Prefix, "/") + "/" + key
	}
	var path string
	u := *base
	if s.PathStyle {
		path = "/" + s.Bucket + "/" + uriEncode(full, true)
	} else {
		u.Host = s.Bucket + "." + base.Host
		path = "/" + uriEncode(full, true)
	}
	u.Path, u.RawPath = "", ""
	u.Opaque = ""
	// Build the final URL by string so the encoded path survives untouched.
	out, err := url.Parse(u.Scheme + "://" + u.Host + path)
	if err != nil {
		return nil, "", err
	}
	return out, path, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sign adds the SigV4 headers to req for the given payload hash.
func (s S3Objects) sign(req *http.Request, canonicalURI, payloadHash string) {
	t := s.now()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	host := req.URL.Host
	req.Host = host
	canonicalHeaders := "host:" + host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalQuery := req.URL.RawQuery
	canonicalRequest := strings.Join([]string{req.Method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := dateStamp + "/" + s.Region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	kDate := hmacSHA256([]byte("AWS4"+s.SecretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.Region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.AccessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func (s S3Objects) do(ctx context.Context, method, key string, body []byte) (*http.Response, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if badKey(key) {
		return nil, fmt.Errorf("bad key")
	}
	u, canonicalURI, err := s.target(key)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	s.sign(req, canonicalURI, sha256Hex(body))
	return s.client().Do(req)
}

func (s S3Objects) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	body, err := io.ReadAll(io.LimitReader(r, s3MaxObject+1))
	if err != nil {
		return 0, err
	}
	if len(body) > s3MaxObject {
		return 0, fmt.Errorf("s3: object larger than %d bytes", s3MaxObject)
	}
	resp, err := s.do(ctx, http.MethodPut, key, body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, s3Error(resp)
	}
	return int64(len(body)), nil
}

func (s S3Objects) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	resp, err := s.do(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, 0, ErrObjectNotFound
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, 0, s3Error(resp)
	}
	size := resp.ContentLength
	if size < 0 {
		if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
			size = n
		}
	}
	return resp.Body, size, nil
}

func (s S3Objects) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode/100 == 2 {
		return nil
	}
	return s3Error(resp)
}

// EnsureBucket creates the bucket when it does not exist (dev stacks and
// tests; production buckets are provisioned with their policies).
func (s S3Objects) EnsureBucket(ctx context.Context) error {
	if err := s.check(); err != nil {
		return err
	}
	base, err := url.Parse(strings.TrimRight(s.Endpoint, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("s3: bad endpoint %q", s.Endpoint)
	}
	host, path := base.Host, "/"
	if s.PathStyle {
		path = "/" + s.Bucket
	} else {
		host = s.Bucket + "." + base.Host
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base.Scheme+"://"+host+path, nil)
	if err != nil {
		return err
	}
	s.sign(req, path, sha256Hex(nil))
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusConflict {
		return nil // created, or already ours
	}
	return s3Error(resp)
}

func s3Error(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := strings.TrimSpace(string(b))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return fmt.Errorf("s3: http %d: %s", resp.StatusCode, msg)
}
