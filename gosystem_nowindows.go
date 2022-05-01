//go:build !windows
// +build !windows

package gosystem

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func fileIWriteable(path string) (isWritable bool) {
	isWritable = false
	if file, err := os.OpenFile(path, os.O_WRONLY, 0666); err == nil {
		defer file.Close()
		isWritable = true
	} else {
		if os.IsPermission(err) {
			return false
		}
	}

	return
}

func dirIsWritable(path string) (isWritable bool, err error) {
	isWritable = false
	var info fs.FileInfo
	info, err = os.Stat(path)
	if err != nil {
		return
	}

	if !info.IsDir() {
		err = errors.New("path isn't a directory")
		return
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		err = errors.New("write permission bit is not set on this file for user")
		return
	}

	var stat syscall.Stat_t
	if err = syscall.Stat(path, &stat); err != nil {
		return
	}

	err = nil
	if uint32(os.Geteuid()) != stat.Uid {
		isWritable = false
		// fmt.Println("User doesn't have permission to write to this directory")
		return
	}

	isWritable = true
	return
}