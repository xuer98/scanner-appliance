package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ObjectStore holds support bundles, releases and signature bundles.
// DirObjects (a directory, typically on shared storage) is the shipped
// implementation; an S3 backend can implement the same two methods.
type ObjectStore interface {
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
	// Get streams an object; ErrObjectNotFound when absent.
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// ErrObjectNotFound is returned by Get for a missing key.
var ErrObjectNotFound = errors.New("object not found")

func badKey(key string) bool {
	return key == "" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") || strings.Contains(key, "\\")
}

// DirObjects stores objects under a directory.
type DirObjects struct{ Root string }

func (d DirObjects) Put(_ context.Context, key string, r io.Reader) (int64, error) {
	if badKey(key) {
		return 0, fmt.Errorf("bad key")
	}
	path := filepath.Join(d.Root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(path+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path + ".part")
		return 0, err
	}
	return n, os.Rename(path+".part", path)
}

func (d DirObjects) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	if badKey(key) {
		return nil, 0, fmt.Errorf("bad key")
	}
	f, err := os.Open(filepath.Join(d.Root, filepath.FromSlash(key)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrObjectNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		_ = f.Close()
		return nil, 0, ErrObjectNotFound
	}
	return f, fi.Size(), nil
}

// DiscardObjects counts bytes and drops them (tests without downloads).
type DiscardObjects struct{}

func (DiscardObjects) Put(_ context.Context, _ string, r io.Reader) (int64, error) {
	return io.Copy(io.Discard, r)
}

func (DiscardObjects) Get(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, ErrObjectNotFound
}
