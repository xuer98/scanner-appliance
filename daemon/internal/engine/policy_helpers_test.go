package engine

import (
	"os"
	"path/filepath"
)

func mkdirAll(path string) error          { return os.MkdirAll(filepath.Dir(path), 0o755) }
func osWriteFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o644) }
