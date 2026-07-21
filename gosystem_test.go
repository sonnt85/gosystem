package gosystem

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestKillProcess(t *testing.T) {
	// Start a long-running subprocess
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "100", "127.0.0.1")
	} else {
		cmd = exec.Command("sleep", "100")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start subprocess: %v", err)
	}
	pid := cmd.Process.Pid

	// Give the process time to start
	time.Sleep(100 * time.Millisecond)

	// Verify process exists
	p := GetProcessFromPid(pid)
	if p == nil {
		t.Fatalf("Process %d should exist", pid)
	}

	// Kill the process
	if err := KillPid(int64(pid)); err != nil {
		t.Fatalf("Failed to kill process %d: %v", pid, err)
	}

	// Wait for process to finish
	_ = cmd.Wait()

	// Verify process is gone
	time.Sleep(100 * time.Millisecond)
	proc, err := os.FindProcess(pid)
	if err == nil && proc != nil && runtime.GOOS != "windows" {
		// On Unix, FindProcess always succeeds; check with Signal(0)
		if err := proc.Signal(os.Signal(nil)); err == nil {
			t.Fatalf("Process %d should be dead", pid)
		}
	}
}

func TestGetProcessFromPid(t *testing.T) {
	// Current process should exist
	p := GetProcessFromPid(os.Getpid())
	if p == nil {
		t.Fatal("Current process should exist")
	}

	name, err := p.Name()
	if err != nil {
		t.Fatalf("Failed to get process name: %v", err)
	}
	if name == "" {
		t.Fatal("Process name should not be empty")
	}
}
