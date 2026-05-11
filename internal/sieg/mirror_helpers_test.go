package sieg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeJSONLAt(t *testing.T, base, sub string, when time.Time) error {
	t.Helper()
	dir := filepath.Join(base, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
		return err
	}
	return os.Chtimes(path, when, when)
}
