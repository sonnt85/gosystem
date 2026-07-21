// Package pid provides structure and helper functions to create and remove
// PID file.
package pidfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewAndRemove(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "test-pidfile")
	if err != nil {
		t.Fatal("Could not create test directory")
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "testfile.pid")
	file, err := NewPidfile(path, nil, "", false)
	if err != nil {
		t.Fatal("Could not create test file", err)
	}

	if pid := file.Get("pid").Int(); pid == 0 {
		t.Fatal("PID should not be zero")
	}

	if err := file.Remove(); err != nil {
		t.Fatal("Could not delete created test file")
	}
}

func TestNewPidfileWithProgname(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "test-pidfile")
	if err != nil {
		t.Fatal("Could not create test directory")
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "testfile.pid")
	f, err := NewPidfile(path, nil, "testprog", false)
	if err != nil {
		t.Fatal("Could not create pid file", err)
	}
	defer f.Remove()

	if name := f.Get("name").String(); name == "" {
		t.Fatal("Process name should not be empty")
	}
	if pid := f.Get("pid").Int(); pid != int64(os.Getpid()) {
		t.Fatalf("PID mismatch: got %d, want %d", pid, os.Getpid())
	}
}
