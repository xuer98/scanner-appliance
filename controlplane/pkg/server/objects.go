package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ObjectStore holds support bundles, releases, and signature bundles.
// Phase 1 ships a local-directory implementation; S3 comes with Phase 3.
type ObjectStore interface {
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
}

// DirObjects stores objects under a directory.
type DirObjects struct{ Root string }

func (d DirObjects) Put(_ context.Context, key string, r io.Reader) (int64, error) {
	if strings.Contains(key, "..") {
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

// DiscardObjects counts bytes and drops them (tests).
type DiscardObjects struct{}

func (DiscardObjects) Put(_ context.Context, _ string, r io.Reader) (int64, error) {
	return io.Copy(io.Discard, r)
}
