package appscanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNoHardCodedDebugPathsInSource(t *testing.T) {
	// Walk key source trees and assert developer-local debug paths are gone.
	roots := []string{
		mustRepoRoot(t) + "/pkg",
		mustRepoRoot(t) + "/integration",
		mustRepoRoot(t) + "/fingerprint",
	}
	// Build markers without embedding the full forbidden literals as contiguous
	// source that would fail this scan on the test file itself.
	forbidden := []string{
		string([]byte{'/', 'U', 's', 'e', 'r', 's', '/', 'o', 'z', '/'}),
		string([]byte{'.', 'c', 'u', 'r', 's', 'o', 'r', '/', 'd', 'e', 'b', 'u', 'g', '.', 'l', 'o', 'g'}),
		"#region" + " agent log",
	}
	thisFile := ""
	_, thisFile, _, _ = runtime.Caller(0)

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if filepath.Clean(path) == filepath.Clean(thisFile) {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(data)
			for _, f := range forbidden {
				if strings.Contains(content, f) {
					t.Errorf("%s contains forbidden marker %q", path, f)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// integration/appscanner/strategy_test.go → repo root is ../..
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
